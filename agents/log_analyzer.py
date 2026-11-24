"""Agent 2 - Log Analysis Agent.

Uses pandas to analyse the security logs around an alert: failed-login bursts, unusual
login locations/hours, impossible travel, denied access, port scans, large outbound
transfers, DNS beaconing and account changes. An optional scikit-learn IsolationForest
adds an *informational* anomaly signal (it never drives the risk score on its own).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Optional

import numpy as np
import pandas as pd

from graph.state import InvestigationState
from models.schemas import (
    Finding,
    IndicatorSet,
    LogAnalysisResult,
    LogMetrics,
    SecurityAlert,
    Severity,
)
from utils.netutils import is_internal_ip

# --- Detection thresholds (constants so the rules are transparent) ---
WINDOW_BEFORE = timedelta(hours=6)
WINDOW_AFTER = timedelta(hours=6)
OFF_HOURS = range(0, 6)  # 00:00-05:59 UTC
BRUTE_FORCE_MIN_FAILED = 10
BRUTE_FORCE_MIN_USERS = 3
BRUTE_FORCE_MIN_FAILED_MULTI_USER = 5
BURST_WINDOW = timedelta(minutes=5)
SUCCESS_AFTER_FAILURES_MIN = 5
IMPOSSIBLE_TRAVEL_MAX_GAP = timedelta(hours=3)
DENIED_ACCESS_MIN = 3
PORT_SCAN_MIN_PORTS = 15
LARGE_TRANSFER_BYTES = 100 * 1024 * 1024  # 100 MB
REPEATED_DNS_MIN = 10
BEACON_MAX_VARIATION = 0.25  # std / mean of the query interval
ML_MIN_ROWS = 50
ML_MAX_FIT_ROWS = 5000

FAILURE_STATUSES = {"failure", "failed", "fail", "denied"}
ACCOUNT_EVENTS = {"account_change", "privilege_change"}


def _fmt(row: pd.Series) -> str:
    """One-line description of a log row used as evidence."""
    parts = [row["timestamp"].strftime("%Y-%m-%d %H:%M:%SZ"), str(row["event_type"]), str(row["status"])]
    for label, col in (("user", "username"), ("src", "source_ip"), ("dst", "destination_ip"),
                       ("host", "hostname"), ("country", "country"), ("resource", "resource"),
                       ("domain", "domain")):
        value = str(row.get(col, "") or "")
        if value and value != "nan":
            parts.append(f"{label}={value}")
    if pd.notna(row.get("destination_port")):
        parts.append(f"port={int(row['destination_port'])}")
    if pd.notna(row.get("bytes_out")) and row["bytes_out"] > 0:
        parts.append(f"bytes_out={int(row['bytes_out'])}")
    return " ".join(parts)


def _max_in_window(times: list[pd.Timestamp], window: timedelta = BURST_WINDOW) -> int:
    """Largest number of timestamps that fall inside any single ``window`` (two pointers)."""
    best, left = 0, 0
    ordered = sorted(times)
    for right, current in enumerate(ordered):
        while current - ordered[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def select_related_events(alert: SecurityAlert, logs: pd.DataFrame) -> pd.DataFrame:
    """Return log events inside the time window that share an entity with the alert."""
    start, end = alert.timestamp - WINDOW_BEFORE, alert.timestamp + WINDOW_AFTER
    window = logs[(logs["timestamp"] >= start) & (logs["timestamp"] <= end)]
    user = "" if alert.username in ("", "(multiple)") else alert.username.lower()
    mask = pd.Series(False, index=window.index)
    if alert.source_ip:
        mask |= window["source_ip"] == alert.source_ip
    if user:
        mask |= window["username"].str.lower() == user
    if alert.domain:
        mask |= window["domain"].str.lower() == alert.domain.lower()
    if alert.file_hash:
        mask |= window["file_hash"].str.lower() == alert.file_hash.lower()
    if not (alert.source_ip or user) and alert.hostname:
        mask |= window["hostname"].str.lower() == alert.hostname.lower()
    return window[mask].sort_values("timestamp")


def _ml_anomaly_indices(logs: pd.DataFrame) -> set[int]:
    """Indices of log rows flagged by an IsolationForest (empty if too little data)."""
    if len(logs) < ML_MIN_ROWS:
        return set()
    from sklearn.ensemble import IsolationForest

    features = pd.DataFrame({
        "hour": logs["timestamp"].dt.hour,
        "log_bytes": np.log1p(logs["bytes_out"].fillna(0).clip(lower=0)),
        "port": logs["destination_port"].fillna(0),
        "is_failure": logs["status"].isin(FAILURE_STATUSES | {"blocked"}).astype(int),
        "is_login": (logs["event_type"] == "login").astype(int),
    })
    sample = features.sample(n=min(len(features), ML_MAX_FIT_ROWS), random_state=42)
    model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    model.fit(sample)
    flags = model.predict(features)
    return set(logs.index[flags == -1])


def analyze_logs(alert: SecurityAlert, logs: Optional[pd.DataFrame], use_ml: bool = True
                 ) -> LogAnalysisResult:
    """Analyse the logs related to ``alert`` and return findings, metrics and indicators."""
    limitations: list[str] = []
    indicators = IndicatorSet(
        ips=[ip for ip in (alert.source_ip, alert.destination_ip) if ip and not is_internal_ip(ip)],
        domains=[alert.domain] if alert.domain else [],
        hashes=[alert.file_hash] if alert.file_hash else [],
        usernames=[alert.username] if alert.username not in ("", "(multiple)") else [],
        hosts=[alert.hostname] if alert.hostname else [],
    )
    if logs is None or logs.empty:
        limitations.append("No security logs were available, so log analysis could not be performed.")
        return LogAnalysisResult(indicators=indicators, limitations=limitations,
                                 summary="No logs available; no log-based findings.")

    related = select_related_events(alert, logs)
    metrics = LogMetrics(total_related_events=len(related))
    if related.empty:
        limitations.append(
            "No log entries matched this alert's IP/user/domain/hash in the analysis window "
            f"(±{int(WINDOW_BEFORE.total_seconds() // 3600)}h). The alert could not be corroborated."
        )
        return LogAnalysisResult(metrics=metrics, indicators=indicators, limitations=limitations,
                                 summary="No related log events found.")

    findings: list[Finding] = []
    metrics.first_event = related["timestamp"].min().strftime("%Y-%m-%d %H:%M:%SZ")
    metrics.last_event = related["timestamp"].max().strftime("%Y-%m-%d %H:%M:%SZ")
    metrics.peak_events_5min = _max_in_window(list(related["timestamp"]))

    window_start = alert.timestamp - WINDOW_BEFORE
    history_all = logs[logs["timestamp"] < window_start]

    logins = related[related["event_type"] == "login"]
    failures = logins[logins["status"].isin(FAILURE_STATUSES)]
    successes = logins[logins["status"] == "success"]

    # ---- failed logins / brute force -------------------------------------------------
    metrics.failed_logins = len(failures)
    metrics.distinct_users_targeted = int(failures["username"].replace("", np.nan).nunique())
    if len(failures):
        metrics.failed_burst_max = _max_in_window(list(failures["timestamp"]))
    brute_force = metrics.failed_logins >= BRUTE_FORCE_MIN_FAILED or (
        metrics.distinct_users_targeted >= BRUTE_FORCE_MIN_USERS
        and metrics.failed_logins >= BRUTE_FORCE_MIN_FAILED_MULTI_USER)
    if brute_force:
        findings.append(Finding(
            finding_type="BRUTE_FORCE", severity=Severity.HIGH, event_count=metrics.failed_logins,
            description=(f"{metrics.failed_logins} failed logins (peak {metrics.failed_burst_max} within "
                         f"5 minutes) against {metrics.distinct_users_targeted} account(s)."),
            evidence=[_fmt(r) for _, r in failures.head(5).iterrows()]))
    elif metrics.failed_logins:
        findings.append(Finding(
            finding_type="FAILED_LOGINS_BELOW_THRESHOLD", severity=Severity.LOW, suspicious=False,
            event_count=metrics.failed_logins,
            description=(f"{metrics.failed_logins} failed login(s) against "
                         f"{metrics.distinct_users_targeted} account(s): below the brute-force threshold."),
            evidence=[_fmt(r) for _, r in failures.head(3).iterrows()]))

    # ---- per-user login history (baseline) -------------------------------------------
    unusual_logins: list[pd.Series] = []
    off_hours_logins: list[pd.Series] = []
    success_after_failures_events: list[pd.Series] = []
    baseline_users = 0
    for _, login in successes.iterrows():
        user = login["username"]
        hist = history_all[(history_all["username"] == user) & (history_all["event_type"] == "login")
                           & (history_all["status"] == "success")] if user else history_all.iloc[0:0]
        if not hist.empty:
            baseline_users += 1
            known_countries = set(hist["country"]) - {""}
            if login["country"] and known_countries and login["country"] not in known_countries:
                unusual_logins.append(login)
            off_ratio = float(hist["timestamp"].dt.hour.isin(list(OFF_HOURS)).mean())
            if login["timestamp"].hour in OFF_HOURS and off_ratio < 0.5:
                off_hours_logins.append(login)
        # success after repeated failures from the same source IP
        if login["source_ip"]:
            prior = failures[(failures["source_ip"] == login["source_ip"])
                             & (failures["timestamp"] < login["timestamp"])]
            known_ip = (not hist.empty) and login["source_ip"] in set(hist["source_ip"])
            if len(prior) >= SUCCESS_AFTER_FAILURES_MIN and (
                    not known_ip or brute_force):
                success_after_failures_events.append(login)
    metrics.baseline_available = baseline_users > 0
    if len(successes) and baseline_users == 0:
        limitations.append(
            "No earlier login history exists for the involved account(s), so unusual-location "
            "and off-hours checks could not be performed.")

    metrics.unusual_location_logins = len(unusual_logins)
    metrics.off_hours_logins = len(off_hours_logins)
    metrics.success_after_failures = bool(success_after_failures_events)

    if unusual_logins:
        findings.append(Finding(
            finding_type="UNUSUAL_LOCATION", severity=Severity.MEDIUM, event_count=len(unusual_logins),
            description="Successful login from a country not seen in this user's earlier history.",
            evidence=[_fmt(r) for r in unusual_logins[:5]]))
    if off_hours_logins:
        findings.append(Finding(
            finding_type="OFF_HOURS_LOGIN", severity=Severity.LOW, event_count=len(off_hours_logins),
            description="Successful login at an hour that is unusual for this user (00:00-05:59 UTC).",
            evidence=[_fmt(r) for r in off_hours_logins[:5]]))
    if success_after_failures_events:
        findings.append(Finding(
            finding_type="SUCCESS_AFTER_FAILURES", severity=Severity.CRITICAL,
            event_count=len(success_after_failures_events),
            description="Successful login from the same IP that previously failed repeatedly "
                        "(possible account compromise).",
            evidence=[_fmt(r) for r in success_after_failures_events[:5]]))

    # ---- impossible travel -----------------------------------------------------------
    travel_evidence: list[str] = []
    for user in successes["username"].replace("", np.nan).dropna().unique():
        user_logins = logs[(logs["username"] == user) & (logs["event_type"] == "login")
                           & (logs["status"] == "success")
                           & (logs["timestamp"] >= window_start - timedelta(hours=3))
                           & (logs["timestamp"] <= alert.timestamp + WINDOW_AFTER)].sort_values("timestamp")
        rows = list(user_logins.iterrows())
        for (_, a), (_, b) in zip(rows, rows[1:]):
            if (a["country"] and b["country"] and a["country"] != b["country"]
                    and b["timestamp"] - a["timestamp"] <= IMPOSSIBLE_TRAVEL_MAX_GAP):
                gap = int((b["timestamp"] - a["timestamp"]).total_seconds() // 60)
                travel_evidence.append(
                    f"{user}: {a['country']} -> {b['country']} within {gap} minute(s) "
                    f"({a['timestamp'].strftime('%H:%M')}Z then {b['timestamp'].strftime('%H:%M')}Z)")
    metrics.impossible_travel = bool(travel_evidence)
    if travel_evidence:
        findings.append(Finding(
            finding_type="IMPOSSIBLE_TRAVEL", severity=Severity.HIGH, event_count=len(travel_evidence),
            description="Successful logins from different countries too close together in time.",
            evidence=travel_evidence[:5]))

    # ---- unauthorized access ---------------------------------------------------------
    denied = related[(related["event_type"] == "access") & (related["status"] == "denied")]
    metrics.denied_access = len(denied)
    if len(denied) >= DENIED_ACCESS_MIN:
        resources = sorted(set(denied["resource"]) - {""})
        findings.append(Finding(
            finding_type="UNAUTHORIZED_ACCESS", severity=Severity.HIGH, event_count=len(denied),
            description=f"{len(denied)} denied access attempts on restricted resources "
                        f"({', '.join(resources[:4]) or 'unspecified'}).",
            evidence=[_fmt(r) for _, r in denied.head(5).iterrows()]))

    # ---- network behaviour -----------------------------------------------------------
    net = related[related["event_type"] == "network_connection"]
    if not net.empty:
        ports = net.dropna(subset=["destination_port"]).groupby("source_ip")["destination_port"].nunique()
        metrics.distinct_ports = int(ports.max()) if len(ports) else 0
        if metrics.distinct_ports >= PORT_SCAN_MIN_PORTS:
            metrics.port_scan = True
            scan_rows = net.dropna(subset=["destination_port"])
            findings.append(Finding(
                finding_type="PORT_SCAN", severity=Severity.MEDIUM, event_count=len(scan_rows),
                description=f"Connections to {metrics.distinct_ports} distinct destination ports from one source.",
                evidence=[_fmt(r) for _, r in scan_rows.head(4).iterrows()]))
        big = net[(net["bytes_out"].fillna(0) >= LARGE_TRANSFER_BYTES)
                  & (~net["destination_ip"].map(is_internal_ip))]
        metrics.max_bytes_out = int(net["bytes_out"].fillna(0).max())
        if len(big):
            metrics.large_transfer = True
            findings.append(Finding(
                finding_type="LARGE_OUTBOUND_TRANSFER", severity=Severity.HIGH, event_count=len(big),
                description=f"Outbound transfer of {int(big['bytes_out'].max()) / 1_048_576:.0f} MB "
                            "to an external address.",
                evidence=[_fmt(r) for _, r in big.head(3).iterrows()]))

    dns = related[(related["event_type"] == "dns_query") & (related["domain"] != "")]
    for domain, group in dns.groupby("domain"):
        if len(group) >= REPEATED_DNS_MIN:
            metrics.repeated_dns = True
            gaps = group["timestamp"].sort_values().diff().dropna().dt.total_seconds()
            regular = bool(len(gaps) and gaps.mean() > 0 and (gaps.std(ddof=0) / gaps.mean()) <= BEACON_MAX_VARIATION)
            metrics.beaconing = metrics.beaconing or regular
            findings.append(Finding(
                finding_type="DNS_BEACONING" if regular else "REPEATED_DNS",
                severity=Severity.HIGH if regular else Severity.MEDIUM, event_count=len(group),
                description=(f"{len(group)} DNS queries to '{domain}'"
                             + (f" at a regular ~{gaps.mean():.0f}s interval (beacon-like)." if regular else ".")),
                evidence=[_fmt(r) for _, r in group.head(3).iterrows()]))

    # ---- account changes -------------------------------------------------------------
    changes = related[related["event_type"].isin(ACCOUNT_EVENTS)]
    metrics.account_changes = len(changes)
    metrics.privilege_changes = int((changes["event_type"] == "privilege_change").sum())
    if len(changes):
        findings.append(Finding(
            finding_type="ACCOUNT_CHANGE", severity=Severity.HIGH, event_count=len(changes),
            description=f"{len(changes)} account/privilege change event(s) in the window.",
            evidence=[_fmt(r) for _, r in changes.head(5).iterrows()]))

    # ---- optional ML anomaly signal (informational only) -----------------------------
    if use_ml:
        try:
            flagged = _ml_anomaly_indices(logs)
        except Exception as exc:  # never let the optional model break the investigation
            flagged = set()
            limitations.append(f"Optional anomaly model skipped ({type(exc).__name__}).")
        hits = related[related.index.isin(flagged)]
        metrics.ml_anomalies = len(hits)
        if len(hits):
            findings.append(Finding(
                finding_type="ML_ANOMALY", severity=Severity.LOW, suspicious=False,
                event_count=len(hits),
                description=f"IsolationForest flagged {len(hits)} related event(s) as statistical outliers "
                            "(informational; not used for classification).",
                evidence=[_fmt(r) for _, r in hits.head(3).iterrows()]))

    metrics.suspicious_event_count = sum(f.event_count for f in findings if f.suspicious)

    # ---- indicators ------------------------------------------------------------------
    ips = set(indicators.ips)
    for col in ("source_ip", "destination_ip"):
        ips.update(ip for ip in related[col].unique() if ip and not is_internal_ip(ip))
    indicators.ips = sorted(ips)
    indicators.domains = sorted(set(indicators.domains) | {d for d in related["domain"].unique() if d})
    indicators.hashes = sorted(set(indicators.hashes) | {h for h in related["file_hash"].unique() if h})
    indicators.usernames = sorted(set(indicators.usernames) | {u for u in related["username"].unique() if u})
    indicators.hosts = sorted(set(indicators.hosts) | {h for h in related["hostname"].unique() if h})

    suspicious = [f for f in findings if f.suspicious]
    summary = (
        f"{metrics.total_related_events} related event(s); "
        + (f"{len(suspicious)} suspicious finding type(s): "
           + ", ".join(f.finding_type for f in suspicious) + "."
           if suspicious else "no suspicious behaviour detected.")
    )
    return LogAnalysisResult(findings=findings, metrics=metrics, indicators=indicators,
                             limitations=limitations, summary=summary)


def log_analysis_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 3: Log Analysis Agent."""
    alert = state["alert"]
    result = analyze_logs(alert, state.get("logs_df"))
    return {
        "log_analysis": result,
        "limitations": result.limitations,
        "agent_trace": [f"Log Analysis: {result.summary}"],
    }
