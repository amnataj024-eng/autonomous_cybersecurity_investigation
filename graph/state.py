"""Shared LangGraph state.

Every agent reads from and writes to this dictionary; no agent calls another directly.
List fields marked with ``operator.add`` are *accumulated* across nodes (LangGraph reducer).
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Optional, TypedDict

from models.schemas import (
    IncidentReport,
    InvestigationResult,
    LogAnalysisResult,
    ResponsePlan,
    RiskAssessment,
    SecurityAlert,
    ThreatIntelResult,
    TriageResult,
)


class InvestigationState(TypedDict, total=False):
    """State passed between the workflow nodes."""

    # ---- inputs ----
    raw_alert: dict[str, Any]
    alerts_df: Any  # pandas.DataFrame of all alerts (for duplicates / correlation)
    logs_df: Any  # pandas.DataFrame of security logs
    threat_intel_df: Any  # pandas.DataFrame of the local threat-intel dataset

    # ---- agent outputs ----
    alert: Optional[SecurityAlert]
    triage: TriageResult
    log_analysis: LogAnalysisResult
    threat_intel: ThreatIntelResult
    investigation: InvestigationResult
    risk: RiskAssessment
    response: ResponsePlan
    approval_status: str
    report: IncidentReport

    # ---- accumulated across nodes ----
    agent_trace: Annotated[list[str], operator.add]
    limitations: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
