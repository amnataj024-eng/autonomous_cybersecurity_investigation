"""Agent 1 - Alert Triage Agent.

Validates incoming alerts, categorises them, detects duplicates, assigns an initial
severity, filters obvious false positives and finds alerts that belong to the same
incident. Fully rule-based, so it is deterministic and needs no API key.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional

import pandas as pd
from pydantic import ValidationError

from graph.state import InvestigationState
from utils.netutils import is_internal_ip
from models.schemas import (
    SEVERITY_ORDER,
    IncidentCategory,
    SecurityAlert,
    Severity,
    TriageResult,
)

# --- Configuration (kept as constants so the rules are easy to read and change) ---
DUPLICATE_WINDOW = timedelta(minutes=15)
CORRELATION_WINDOW = timedelta(hours=24)

#: Internal hosts known to generate benign "noisy" alerts (synthetic demo allowlist).
AUTHORIZED_INTERNAL_HOSTS = {
    "10.0.5.20": "authorized vulnerability scanner",
    "10.0.5.30": "scheduled backup server",
    "10.0.1.5": "SIEM rule-testing source",
}
BENIGN_KEYWORDS = (
    "scheduled", "authorized", "authorised", "test event", "rule validation",
    "maintenance window",
)
BENIGN_ALERT_TYPES = {"vulnerability_scan", "test_alert", "large_data_transfer"}

ALERT_TYPE_CATEGORY: dict[str, IncidentCategory] = {
    "failed_login_burst": IncidentCategory.BRUTE_FORCE,
    "login_after_failures": IncidentCategory.BRUTE_FORCE,
    "brute_force": IncidentCategory.BRUTE_FORCE,
    "unusual_login_location": IncidentCategory.SUSPICIOUS_LOGIN,
    "impossible_travel": IncidentCategory.SUSPICIOUS_LOGIN,
    "after_hours_login": IncidentCategory.SUSPICIOUS_LOGIN,
    "unauthorized_access": IncidentCategory.UNAUTHORIZED_ACCESS,
    "malware_detected": IncidentCategory.MALWARE,
    "port_scan": IncidentCategory.NETWORK_ANOMALY,
    "malicious_ip_connection": IncidentCategory.NETWORK_ANOMALY,
    "data_exfiltration": IncidentCategory.NETWORK_ANOMALY,
    "large_data_transfer": IncidentCategory.NETWORK_ANOMALY,
    "dns_anomaly": IncidentCategory.NETWORK_ANOMALY,
    "vulnerability_scan": IncidentCategory.NETWORK_ANOMALY,
    "suspicious_account_activity": IncidentCategory.SUSPICIOUS_ACCOUNT,
    "privilege_escalation": IncidentCategory.SUSPICIOUS_ACCOUNT,
    "test_alert": IncidentCategory.FALSE_POSITIVE,
}

# Fallback keyword rules for alert types that are not in the table above.
KEYWORD_CATEGORY: list[tuple[tuple[str, ...], IncidentCategory]] = [
    (("brute", "failed login", "password spray"), IncidentCategory.BRUTE_FORCE),
    (("malware", "trojan", "ransom", "virus"), IncidentCategory.MALWARE),
    (("unauthorized", "unauthorised", "access denied"), IncidentCategory.UNAUTHORIZED_ACCESS),
    (("privilege", "account"), IncidentCategory.SUSPICIOUS_ACCOUNT),
    (("dns", "traffic", "port", "scan", "transfer", "connection", "exfil"),
     IncidentCategory.NETWORK_ANOMALY),
    (("login", "geo", "location", "travel"), IncidentCategory.SUSPICIOUS_LOGIN),
]


def validate_alert(raw_alert: Optional[dict[str, Any]]) -> tuple[Optional[SecurityAlert], list[str]]:
    """Validate a raw alert dictionary. Returns ``(alert, errors)``."""
    if not raw_alert:
        return None, ["No alert was provided."]
    try:
        return SecurityAlert.model_validate(raw_alert), []
    except ValidationError as exc:
        errors = []
        for err in exc.errors():
            field = ".".join(str(p) for p in err["loc"]) or "alert"
            message = err["msg"].removeprefix("Value error, ")
            errors.append(f"{field}: {message}")
        return None, errors


def categorize_alert(alert_type: str, description: str = "") -> IncidentCategory:
    """Map an alert type (and, if unknown, its text) to an incident category."""
    key = alert_type.strip().lower().replace(" ", "_").replace("-", "_")
    if key in ALERT_TYPE_CATEGORY:
        return ALERT_TYPE_CATEGORY[key]
    text = f"{alert_type} {description}".lower().replace("_", " ")
    for keywords, category in KEYWORD_CATEGORY:
        if any(word in text for word in keywords):
            return category
    return IncidentCategory.INSUFFICIENT


def detect_false_positive(alert: SecurityAlert) -> tuple[bool, str]:
    """Apply conservative rules that only filter *obvious* false positives."""
    text = f"{alert.alert_type} {alert.description}".lower()
    alert_type = alert.alert_type.lower()

    if alert_type == "test_alert" or "test event" in text or "rule validation" in text:
        return True, "Alert is a SIEM test / rule-validation event, not real activity."

    allow_reason = AUTHORIZED_INTERNAL_HOSTS.get(alert.source_ip)
    if (
        allow_reason
        and alert.severity in (Severity.LOW, Severity.MEDIUM)
        and (alert_type in BENIGN_ALERT_TYPES or any(k in text for k in BENIGN_KEYWORDS))
    ):
        return True, (
            f"Source {alert.source_ip} is an allow-listed internal host ({allow_reason}) "
            "and the alert describes scheduled/authorized activity."
        )

    if (
        alert_type == "failed_login_burst"
        and alert.event_count <= 3
        and alert.severity == Severity.LOW
        and alert.source_ip
        and is_internal_ip(alert.source_ip)
    ):
        return True, (
            f"Only {alert.event_count} failed login(s) from an internal address at Low severity: "
            "consistent with a mistyped password."
        )
    return False, ""


def assign_initial_severity(alert: SecurityAlert, category: IncidentCategory) -> Severity:
    """Start from the alert severity and raise it one level for high-volume or malware alerts."""
    severity = alert.severity
    index = SEVERITY_ORDER.index(severity)
    bump = (alert.event_count >= 20 and severity in (Severity.LOW, Severity.MEDIUM)) or (
        category == IncidentCategory.MALWARE and severity != Severity.CRITICAL
    )
    if bump:
        index = min(index + 1, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[index]


def _norm(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "" if text in {"nan", "none"} else text


def find_duplicate(alert: SecurityAlert, alerts_df: Optional[pd.DataFrame]) -> Optional[str]:
    """Return the id of an earlier alert with the same type/IP/user within 15 minutes."""
    if alerts_df is None or alerts_df.empty:
        return None
    best: Optional[tuple[pd.Timestamp, str]] = None
    for _, row in alerts_df.iterrows():
        other_id = _norm(row.get("alert_id"))
        if other_id == alert.alert_id.lower():
            continue
        other_ts = pd.to_datetime(row.get("timestamp"), utc=True, errors="coerce")
        if pd.isna(other_ts):
            continue
        same = (
            _norm(row.get("alert_type")) == alert.alert_type.lower()
            and _norm(row.get("source_ip")) == alert.source_ip.lower()
            and _norm(row.get("username")) == alert.username.lower()
        )
        earlier = other_ts <= alert.timestamp
        close = abs(alert.timestamp - other_ts.to_pydatetime()) <= DUPLICATE_WINDOW
        if same and earlier and close:
            # Tie-break on identical timestamps: only the lexicographically smaller id is "original".
            if other_ts == alert.timestamp and other_id > alert.alert_id.lower():
                continue
            if best is None or other_ts < best[0]:
                best = (other_ts, str(row.get("alert_id")))
    return best[1] if best else None


def find_related_alerts(alert: SecurityAlert, alerts_df: Optional[pd.DataFrame]) -> list[str]:
    """Find alerts of the same incident.

    Alerts within 24 hours are linked when they share a source IP or username; the
    connected group containing ``alert`` is returned (so chains of alerts are found).
    """
    if alerts_df is None or alerts_df.empty:
        return []
    nodes: dict[str, dict[str, str]] = {
        alert.alert_id: {"ip": alert.source_ip.lower(), "user": alert.username.lower()}
    }
    for _, row in alerts_df.iterrows():
        other_id = str(row.get("alert_id", "")).strip()
        other_ts = pd.to_datetime(row.get("timestamp"), utc=True, errors="coerce")
        if not other_id or other_id == alert.alert_id or pd.isna(other_ts):
            continue
        if abs(alert.timestamp - other_ts.to_pydatetime()) > CORRELATION_WINDOW:
            continue
        nodes[other_id] = {"ip": _norm(row.get("source_ip")), "user": _norm(row.get("username"))}

    parent = {key: key for key in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    ignore = {"", "(multiple)"}
    owners: dict[tuple[str, str], str] = {}
    for node_id, attrs in nodes.items():
        for kind, value in attrs.items():
            if value in ignore:
                continue
            key = (kind, value)
            if key in owners:
                union(node_id, owners[key])
            else:
                owners[key] = node_id
    root = find(alert.alert_id)
    return sorted(n for n in nodes if n != alert.alert_id and find(n) == root)


def triage_alert(raw_alert: Optional[dict[str, Any]], alerts_df: Optional[pd.DataFrame] = None
                 ) -> tuple[Optional[SecurityAlert], TriageResult]:
    """Run the full triage on one raw alert."""
    alert, errors = validate_alert(raw_alert)
    alert_id = str((raw_alert or {}).get("alert_id", "UNKNOWN")) or "UNKNOWN"
    if alert is None:
        return None, TriageResult(
            alert_id=alert_id, is_valid=False, validation_errors=errors,
            category=IncidentCategory.INSUFFICIENT, forward_to_investigation=False,
            notes=["Alert failed validation; investigation cannot proceed."],
        )

    category = categorize_alert(alert.alert_type, alert.description)
    initial = assign_initial_severity(alert, category)
    duplicate_of = find_duplicate(alert, alerts_df)
    related = find_related_alerts(alert, alerts_df)
    is_fp, fp_reason = detect_false_positive(alert)

    notes: list[str] = []
    if category == IncidentCategory.INSUFFICIENT:
        notes.append("Alert type could not be categorised automatically.")
    if duplicate_of:
        notes.append(f"Duplicate of {duplicate_of}; treated as part of the same incident.")
    if related:
        notes.append(f"Linked to {len(related)} other alert(s): {', '.join(related)}.")
    if initial != alert.severity:
        notes.append(f"Severity raised from {alert.severity.value} to {initial.value} (volume/malware rule).")

    return alert, TriageResult(
        alert_id=alert.alert_id,
        is_valid=True,
        category=IncidentCategory.FALSE_POSITIVE if is_fp else category,
        initial_severity=initial,
        is_duplicate=bool(duplicate_of),
        duplicate_of=duplicate_of,
        is_false_positive=is_fp,
        false_positive_reason=fp_reason,
        related_alert_ids=related,
        forward_to_investigation=not is_fp,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# LangGraph nodes
# --------------------------------------------------------------------------- #


def receive_alert_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 1: receive and validate the incoming alert."""
    alert, errors = validate_alert(state.get("raw_alert"))
    if alert is None:
        return {
            "alert": None,
            "errors": errors,
            "limitations": ["The alert is invalid or incomplete, so no investigation was performed."],
            "agent_trace": [f"Receive Alert: REJECTED ({'; '.join(errors)})"],
        }
    return {"alert": alert, "agent_trace": [f"Receive Alert: accepted {alert.alert_id} ({alert.alert_type})"]}


def alert_triage_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 2: Alert Triage Agent."""
    _, triage = triage_alert(state.get("raw_alert"), state.get("alerts_df"))
    summary = (
        f"Alert Triage: category={triage.category.value}, severity={triage.initial_severity.value}, "
        f"duplicate={triage.is_duplicate}, false_positive={triage.is_false_positive}, "
        f"linked_alerts={len(triage.related_alert_ids)}"
    )
    return {"triage": triage, "agent_trace": [summary]}
