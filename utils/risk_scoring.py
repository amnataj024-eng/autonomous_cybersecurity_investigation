"""Transparent, deterministic risk-scoring methodology (0-100), version 1.1.

The score is the sum of seven capped components (maximum points in brackets):

    1. Alert severity (20)            5. Unusual login activity (15)
    2. Suspicious event volume (10)   6. Correlated events (10)
    3. Repeated failed auth (10)      7. Behaviour indicators (15): post-compromise, privilege, denied access, beaconing, scans
    4. Threat-intel matches (20)

Total maximum = 100. After summing, a few clearly documented adjustments apply:
    * "Minimum score" rules for indicators that are serious on their own
      (e.g. a privilege change, a verified malicious hash, a successful login after a
      brute-force attack followed by data transfer).
    * A cap for false positives / normal activity and a floor for high-severity alerts
      that could not be verified because data is missing.

Levels: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from models.schemas import (
    IncidentCategory,
    LogAnalysisResult,
    RiskAssessment,
    RiskLevel,
    ScoreComponent,
    Severity,
    ThreatIntelResult,
)

METHODOLOGY_VERSION = "1.1"

SEVERITY_POINTS = {Severity.LOW: 3, Severity.MEDIUM: 8, Severity.HIGH: 14, Severity.CRITICAL: 20}
TI_CONFIDENCE_POINTS = {"high": 15, "medium": 12, "low": 8}
FALSE_POSITIVE_CAP = 20
INSUFFICIENT_DATA_FLOOR = 25  # Medium: missing evidence must not look like "safe"


def level_from_score(score: int) -> RiskLevel:
    """Map a 0-100 score to a risk level (0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical)."""
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _tier(value: int, tiers: list[tuple[int, int]]) -> int:
    """Return points for the first (threshold, points) tier that ``value`` reaches."""
    for threshold, points in tiers:
        if value >= threshold:
            return points
    return 0


@dataclass
class RiskInputs:
    """Everything the scoring function needs (kept explicit for testability)."""

    alert_severity: Severity
    classification: IncidentCategory
    log_analysis: Optional[LogAnalysisResult]
    threat_intel: Optional[ThreatIntelResult]
    related_alert_count: int = 0


def _minimum_score_rules(inputs: RiskInputs) -> list[tuple[int, str]]:
    """Return (minimum_score, reason) pairs for serious indicators."""
    metrics = inputs.log_analysis.metrics if inputs.log_analysis else None
    verified = inputs.threat_intel.verified_matches if inputs.threat_intel else []
    rules: list[tuple[int, str]] = []
    has_hash = any(m.indicator_type == "hash" for m in verified)
    has_c2 = any("command" in m.threat_type.lower() for m in verified)
    has_exfil = any("exfil" in m.threat_type.lower() for m in verified)
    if metrics:
        if metrics.success_after_failures and (metrics.large_transfer or verified):
            rules.append((75, "successful login after repeated failures combined with data transfer "
                              "or a verified threat-intelligence match (likely account takeover)"))
        if metrics.large_transfer and has_exfil:
            rules.append((60, "large outbound transfer to a verified exfiltration destination"))
        if metrics.privilege_changes:
            rules.append((50, "privilege change detected (possible persistence / privilege escalation)"))
        if has_hash and (metrics.beaconing or has_c2):
            rules.append((75, "verified malicious file hash together with command-and-control communication"))
        elif has_c2 and metrics.beaconing:
            rules.append((50, "beacon-like traffic to a verified command-and-control domain"))
    if has_hash:
        rules.append((50, "file hash matches a verified malicious indicator"))
    return rules


def calculate_risk(inputs: RiskInputs) -> RiskAssessment:
    """Calculate the risk score, level and a full explanation of each component."""
    logs = inputs.log_analysis
    metrics = logs.metrics if logs else None
    ti = inputs.threat_intel
    components: list[ScoreComponent] = []

    # 1. Alert severity (max 20)
    components.append(ScoreComponent(
        name="Alert severity", points=SEVERITY_POINTS[inputs.alert_severity], max_points=20,
        explanation=f"Initial severity is {inputs.alert_severity.value}."))

    # 2. Number of suspicious events (max 10)
    suspicious = metrics.suspicious_event_count if metrics else 0
    components.append(ScoreComponent(
        name="Suspicious event volume",
        points=_tier(suspicious, [(50, 10), (20, 8), (10, 6), (5, 4), (1, 2)]), max_points=10,
        explanation=f"{suspicious} suspicious event(s) found in related logs."))

    # 3. Repeated failed authentication (max 10)
    burst = metrics.failed_burst_max if metrics else 0
    failed = metrics.failed_logins if metrics else 0
    users = metrics.distinct_users_targeted if metrics else 0
    brute = bool(metrics and (failed >= 10 or (users >= 3 and failed >= 5)))
    if brute:
        pts = _tier(max(burst, failed // 2), [(20, 10), (10, 8), (5, 6), (1, 4)])
    else:
        pts = 2 if failed >= 3 else 0
    components.append(ScoreComponent(
        name="Repeated failed authentication", points=pts, max_points=10,
        explanation=(f"{failed} failed login(s), peak {burst} within 5 minutes, "
                     f"{users} account(s) targeted.")))

    # 4. Threat intelligence (max 20)
    pts = 0
    if ti and ti.verified_matches:
        best = max(TI_CONFIDENCE_POINTS.get(m.confidence.lower(), 8) for m in ti.verified_matches)
        pts = min(20, best + 2 * (len(ti.verified_matches) - 1))
        expl = f"{len(ti.verified_matches)} verified match(es) in the local threat-intel dataset."
    elif ti and ti.unverified_matches:
        pts = 3
        expl = f"{len(ti.unverified_matches)} unverified match(es) only (low weight)."
    else:
        expl = "No threat-intelligence matches (absence of a match is not proof of safety)."
    components.append(ScoreComponent(
        name="Threat intelligence matches", points=pts, max_points=20, explanation=expl))

    # 5. Unusual login activity (max 15)
    pts, notes = 0, []
    if metrics:
        if metrics.impossible_travel:
            pts += 8
            notes.append("impossible travel")
        if metrics.unusual_location_logins:
            pts += 6
            notes.append(f"{metrics.unusual_location_logins} login(s) from an unusual location")
        if metrics.off_hours_logins:
            pts += 3
            notes.append(f"{metrics.off_hours_logins} off-hours login(s)")
    components.append(ScoreComponent(
        name="Unusual login activity", points=min(pts, 15), max_points=15,
        explanation=", ".join(notes) if notes else "No unusual login patterns."))

    # 6. Correlated suspicious events (max 10)
    types = len({f.finding_type for f in logs.findings if f.suspicious}) if logs else 0
    pts = _tier(inputs.related_alert_count, [(5, 7), (3, 5), (2, 3), (1, 2)]) + (3 if types >= 3 else 0)
    components.append(ScoreComponent(
        name="Correlated events", points=min(pts, 10), max_points=10,
        explanation=(f"{inputs.related_alert_count} other alert(s) linked to the same IP/user; "
                     f"{types} distinct suspicious behaviour type(s) in logs.")))

    # 7. Behaviour / post-compromise indicators (max 15)
    pts, notes = 0, []
    if metrics:
        if metrics.success_after_failures:
            pts += 5
            notes.append("successful login after repeated failures")
        if metrics.large_transfer:
            pts += 5
            notes.append("large outbound transfer")
        if metrics.privilege_changes:
            pts += 15
            notes.append("privilege change")
        elif metrics.account_changes:
            pts += 10
            notes.append("account change")
        if metrics.denied_access >= 10:
            pts += 8
            notes.append(f"{metrics.denied_access} denied access attempts")
        elif metrics.denied_access >= 3:
            pts += 5
            notes.append(f"{metrics.denied_access} denied access attempts")
        if metrics.beaconing:
            pts += 8
            notes.append("beacon-like DNS traffic")
        elif metrics.repeated_dns:
            pts += 4
            notes.append("repeated DNS queries")
        if metrics.port_scan:
            pts += 4
            notes.append("port scanning")
    components.append(ScoreComponent(
        name="Behaviour indicators", points=min(pts, 15), max_points=15,
        explanation=", ".join(notes) if notes else "None observed."))

    raw = sum(c.points for c in components)
    score, adjustments = raw, []

    if inputs.classification not in (IncidentCategory.FALSE_POSITIVE, IncidentCategory.NORMAL):
        rules = _minimum_score_rules(inputs)
        if rules:
            floor, reason = max(rules, key=lambda r: r[0])
            if score < floor:
                score = floor
                adjustments.append(f"Score raised to the minimum of {floor}: {reason}.")
    elif score > FALSE_POSITIVE_CAP:
        score = FALSE_POSITIVE_CAP
        adjustments.append(
            f"Score capped at {FALSE_POSITIVE_CAP} because the alert was classified as "
            f"'{inputs.classification.value}'.")
    if (inputs.classification == IncidentCategory.INSUFFICIENT
            and inputs.alert_severity in (Severity.HIGH, Severity.CRITICAL)
            and score < INSUFFICIENT_DATA_FLOOR):
        score = INSUFFICIENT_DATA_FLOOR
        adjustments.append(
            f"Score raised to {INSUFFICIENT_DATA_FLOOR} (Medium): a {inputs.alert_severity.value} "
            "alert could not be verified because supporting data is missing.")

    score = max(0, min(100, score))
    level = level_from_score(score)
    top = sorted(components, key=lambda c: c.points, reverse=True)
    drivers = ", ".join(f"{c.name} ({c.points}/{c.max_points})" for c in top[:3] if c.points > 0) or "none"
    explanation = (f"Risk score {score}/100 ({level.value}). Component total was {raw}"
                   + (f", adjusted to {score}" if score != raw else "") + f". Main drivers: {drivers}.")
    return RiskAssessment(score=score, level=level, components=components, adjustments=adjustments,
                          explanation=explanation, methodology_version=METHODOLOGY_VERSION)
