"""Agent 5 - Risk Assessment Agent.

Turns the combined evidence into a 0-100 risk score and a Low/Medium/High/Critical
level using the transparent methodology in ``utils/risk_scoring.py``.
"""

from __future__ import annotations

from typing import Any, Optional

from graph.state import InvestigationState
from models.schemas import (
    InvestigationResult,
    LogAnalysisResult,
    RiskAssessment,
    ThreatIntelResult,
    TriageResult,
)
from utils.risk_scoring import RiskInputs, calculate_risk


def assess_risk(
    triage: TriageResult,
    investigation: InvestigationResult,
    logs: Optional[LogAnalysisResult] = None,
    ti: Optional[ThreatIntelResult] = None,
) -> RiskAssessment:
    """Calculate the risk assessment for one investigated alert."""
    return calculate_risk(RiskInputs(
        alert_severity=triage.initial_severity,
        classification=investigation.classification,
        log_analysis=logs,
        threat_intel=ti,
        related_alert_count=len(triage.related_alert_ids),
    ))


def risk_assessor_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 6: Risk Assessment Agent."""
    risk = assess_risk(state["triage"], state["investigation"],
                       state.get("log_analysis"), state.get("threat_intel"))
    return {"risk": risk, "agent_trace": [f"Risk Assessment: score {risk.score}/100 ({risk.level.value})"]}
