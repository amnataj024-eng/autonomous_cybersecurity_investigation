"""Pydantic data models shared by every agent, the workflow and the UI.

All data in this project is SYNTHETIC demonstration data.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Alert / finding severity."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class RiskLevel(str, Enum):
    """Final risk level derived from the 0-100 risk score."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentCategory(str, Enum):
    """Incident classification categories."""

    BRUTE_FORCE = "Brute-force login attempts"
    SUSPICIOUS_LOGIN = "Suspicious login activity"
    UNAUTHORIZED_ACCESS = "Unauthorized access attempts"
    MALWARE = "Potential malware indicators"
    NETWORK_ANOMALY = "Network anomalies"
    SUSPICIOUS_ACCOUNT = "Suspicious account activity"
    FALSE_POSITIVE = "False positive"
    NORMAL = "Normal activity"
    INSUFFICIENT = "Insufficient information"


class Verdict(str, Enum):
    """Overall investigation verdict."""

    GENUINE = "Likely genuine incident"
    FALSE_POSITIVE = "Likely false positive"
    BENIGN = "Benign / normal activity"
    INCONCLUSIVE = "Inconclusive (insufficient information)"


class ApprovalStatus(str, Enum):
    """Human approval status (always simulated)."""

    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING_HUMAN_REVIEW"
    APPROVED = "APPROVED_SIMULATED"
    REJECTED = "REJECTED_SIMULATED"


# --------------------------------------------------------------------------- #
# Input models
# --------------------------------------------------------------------------- #

_SEVERITY_ALIASES = {
    "informational": "Low",
    "info": "Low",
    "low": "Low",
    "medium": "Medium",
    "moderate": "Medium",
    "high": "High",
    "critical": "Critical",
}


def _clean_str(value: Any) -> str:
    """Convert NaN/None/whitespace values to an empty string."""
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"nan", "none", "nat"} else text


class SecurityAlert(BaseModel):
    """A validated incoming security alert."""

    alert_id: str = Field(min_length=1)
    timestamp: datetime
    alert_type: str = Field(min_length=1)
    severity: Severity
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    hostname: str = ""
    description: str = ""
    event_count: int = Field(default=1, ge=0)
    file_hash: str = ""
    domain: str = ""
    rule_name: str = ""

    @field_validator(
        "alert_id", "alert_type", "source_ip", "destination_ip", "username", "hostname",
        "description", "file_hash", "domain", "rule_name", mode="before",
    )
    @classmethod
    def _strip_text(cls, value: Any) -> str:
        return _clean_str(value)

    @field_validator("severity", mode="before")
    @classmethod
    def _normalise_severity(cls, value: Any) -> Any:
        text = _clean_str(value).lower()
        if text in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[text]
        raise ValueError(
            f"Invalid severity '{value}'. Use one of: Low, Medium, High, Critical."
        )

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: Any) -> datetime:
        text = _clean_str(value)
        if not text:
            raise ValueError("timestamp is required")
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp '{value}' (expected ISO 8601)") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @field_validator("event_count", mode="before")
    @classmethod
    def _parse_count(cls, value: Any) -> int:
        text = _clean_str(value)
        if not text:
            return 1
        try:
            return int(float(text))
        except ValueError as exc:
            raise ValueError(f"event_count must be a number, got '{value}'") from exc

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"'{value}' is not a valid IP address") from exc
        return value

    @model_validator(mode="after")
    def _need_an_entity(self) -> "SecurityAlert":
        entity = (self.source_ip, self.username, self.hostname, self.file_hash, self.domain)
        if not any(e and e != "(multiple)" for e in entity):
            raise ValueError(
                "Alert has no source_ip, username, hostname, domain or file_hash to investigate"
            )
        return self


# --------------------------------------------------------------------------- #
# Agent output models
# --------------------------------------------------------------------------- #


class TriageResult(BaseModel):
    """Output of the Alert Triage Agent."""

    alert_id: str
    is_valid: bool = True
    validation_errors: list[str] = Field(default_factory=list)
    category: IncidentCategory = IncidentCategory.INSUFFICIENT
    initial_severity: Severity = Severity.LOW
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    is_false_positive: bool = False
    false_positive_reason: str = ""
    related_alert_ids: list[str] = Field(default_factory=list)
    forward_to_investigation: bool = True
    notes: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """One finding produced by the Log Analysis Agent."""

    finding_type: str
    description: str
    severity: Severity = Severity.MEDIUM
    event_count: int = 0
    suspicious: bool = True
    evidence: list[str] = Field(default_factory=list)


class LogMetrics(BaseModel):
    """Numeric metrics extracted from the related log events."""

    total_related_events: int = 0
    failed_logins: int = 0
    failed_burst_max: int = 0
    distinct_users_targeted: int = 0
    success_after_failures: bool = False
    impossible_travel: bool = False
    unusual_location_logins: int = 0
    off_hours_logins: int = 0
    denied_access: int = 0
    port_scan: bool = False
    distinct_ports: int = 0
    large_transfer: bool = False
    max_bytes_out: int = 0
    repeated_dns: bool = False
    beaconing: bool = False
    account_changes: int = 0
    privilege_changes: int = 0
    ml_anomalies: int = 0
    suspicious_event_count: int = 0
    peak_events_5min: int = 0
    baseline_available: bool = False
    first_event: Optional[str] = None
    last_event: Optional[str] = None


class IndicatorSet(BaseModel):
    """Indicators of compromise extracted from the alert and logs."""

    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class LogAnalysisResult(BaseModel):
    """Output of the Log Analysis Agent."""

    findings: list[Finding] = Field(default_factory=list)
    metrics: LogMetrics = Field(default_factory=LogMetrics)
    indicators: IndicatorSet = Field(default_factory=IndicatorSet)
    limitations: list[str] = Field(default_factory=list)
    summary: str = ""


class IndicatorMatch(BaseModel):
    """A threat-intelligence match for one indicator."""

    indicator: str
    indicator_type: str
    threat_type: str
    confidence: str
    status: Literal["verified", "unverified"]
    explanation: str
    source: str = ""


class ThreatIntelResult(BaseModel):
    """Output of the Threat Intelligence Agent."""

    verified_matches: list[IndicatorMatch] = Field(default_factory=list)
    unverified_matches: list[IndicatorMatch] = Field(default_factory=list)
    unmatched_indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    summary: str = ""


class EvidenceItem(BaseModel):
    """A numbered piece of evidence used by the investigation."""

    evidence_id: str
    statement: str
    source: str


class InvestigationResult(BaseModel):
    """Output of the Incident Investigation Agent."""

    classification: IncidentCategory
    verdict: Verdict
    confidence: Literal["Low", "Medium", "High"] = "Low"
    attack_pattern: str = ""
    evidence: list[EvidenceItem] = Field(default_factory=list)
    secondary_categories: list[IncidentCategory] = Field(default_factory=list)
    narrative: str = ""
    limitations: list[str] = Field(default_factory=list)
    llm_status: str = "not_configured"
    llm_agrees_with_rules: Optional[bool] = None


class ScoreComponent(BaseModel):
    """One component of the transparent risk score."""

    name: str
    points: int
    max_points: int
    explanation: str


class RiskAssessment(BaseModel):
    """Output of the Risk Assessment Agent."""

    score: int = Field(ge=0, le=100)
    level: RiskLevel
    components: list[ScoreComponent] = Field(default_factory=list)
    adjustments: list[str] = Field(default_factory=list)
    explanation: str = ""
    methodology_version: str = "1.0"


class RecommendedAction(BaseModel):
    """A recommended (never executed) defensive action."""

    title: str
    description: str
    action_type: Literal[
        "Investigation", "Containment", "Monitoring", "Hardening", "Escalation", "Documentation"
    ]
    priority: Literal["Immediate", "High", "Normal", "Low"] = "Normal"
    requires_human_approval: bool = False
    simulated_only: bool = True


class ResponsePlan(BaseModel):
    """Output of the Response Recommendation Agent."""

    actions: list[RecommendedAction] = Field(default_factory=list)
    escalate_to_human: bool = False
    escalation_reason: str = ""
    automated_actions_executed: int = 0
    notice: str = (
        "SIMULATION ONLY: no containment or remediation action has been or will be "
        "executed automatically. Every action needs human approval."
    )


class IncidentReport(BaseModel):
    """Final investigation report produced by the Report Generation Agent."""

    report_id: str
    generated_at: str
    alert: dict[str, Any]
    final_classification: IncidentCategory
    verdict: Verdict
    triage: Optional[TriageResult] = None
    log_analysis: Optional[LogAnalysisResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    investigation: Optional[InvestigationResult] = None
    risk: Optional[RiskAssessment] = None
    response: Optional[ResponsePlan] = None
    approval_status: ApprovalStatus = ApprovalStatus.NOT_REQUIRED
    approval_log: list[str] = Field(default_factory=list)
    executive_summary: str = ""
    limitations: list[str] = Field(default_factory=list)
    agent_trace: list[str] = Field(default_factory=list)
    analysis_mode: str = "DEMO (rule-based)"
    data_notice: str = "All data used is synthetic demonstration data."


# --------------------------------------------------------------------------- #
# LLM output models (validated before use)
# --------------------------------------------------------------------------- #


class LLMInvestigationOutput(BaseModel):
    """Structured output requested from the LLM for the investigation narrative."""

    narrative: str = Field(min_length=20, max_length=2000)
    attack_pattern: str = Field(min_length=3, max_length=300)
    suggested_classification: IncidentCategory
    cited_evidence_ids: list[str] = Field(min_length=1)


class LLMSummaryOutput(BaseModel):
    """Structured output requested from the LLM for the executive summary."""

    executive_summary: str = Field(min_length=20, max_length=1500)
