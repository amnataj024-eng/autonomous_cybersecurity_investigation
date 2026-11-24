"""LangGraph StateGraph that wires the seven agents together.

Flow:  receive -> triage -> [false positive? fast-track] -> logs -> threat intel ->
       investigation -> risk -> response -> approval check -> [escalate] -> report
Invalid alerts skip straight to the report with a stated limitation.
"""

from __future__ import annotations

from typing import Any, Optional

import pandas as pd
from langgraph.graph import END, START, StateGraph

from agents import (
    alert_triage_node,
    escalate_node,
    false_positive_fast_track_node,
    human_approval_check_node,
    incident_investigator_node,
    invalid_input_node,
    log_analysis_node,
    receive_alert_node,
    report_generator_node,
    response_recommender_node,
    risk_assessor_node,
    threat_intel_node,
)
from graph.state import InvestigationState
from models.schemas import ApprovalStatus, IncidentReport
from utils.llm import LLMClient


class WorkflowError(RuntimeError):
    """Raised when the workflow fails unexpectedly."""


# ---- conditional routing functions ----------------------------------------------------


def route_after_receive(state: InvestigationState) -> str:
    """Invalid alerts cannot be investigated; they go straight to the report."""
    return "valid" if state.get("alert") is not None else "invalid"


def route_after_triage(state: InvestigationState) -> str:
    """Obvious false positives are classified immediately; everything else is investigated."""
    triage = state["triage"]
    return "false_positive" if triage.is_false_positive else "investigate"


def route_after_approval_check(state: InvestigationState) -> str:
    """High/Critical incidents are escalated for (simulated) human review."""
    return "escalate" if state.get("approval_status") == ApprovalStatus.PENDING.value else "report"


def build_workflow(llm: Optional[LLMClient] = None) -> Any:
    """Build and compile the LangGraph workflow."""
    graph = StateGraph(InvestigationState)

    graph.add_node("receive_alert", receive_alert_node)
    graph.add_node("alert_triage", alert_triage_node)
    graph.add_node("log_analysis", log_analysis_node)
    graph.add_node("threat_intelligence", threat_intel_node)
    graph.add_node("incident_investigation", lambda state: incident_investigator_node(state, llm=llm))
    graph.add_node("false_positive_fast_track", false_positive_fast_track_node)
    graph.add_node("invalid_input", invalid_input_node)
    graph.add_node("risk_assessment", risk_assessor_node)
    graph.add_node("response_recommendation", response_recommender_node)
    graph.add_node("human_approval_check", human_approval_check_node)
    graph.add_node("escalate_for_review", escalate_node)
    graph.add_node("report_generation", lambda state: report_generator_node(state, llm=llm))

    graph.add_edge(START, "receive_alert")
    graph.add_conditional_edges("receive_alert", route_after_receive,
                                {"valid": "alert_triage", "invalid": "invalid_input"})
    graph.add_edge("invalid_input", "report_generation")
    graph.add_conditional_edges("alert_triage", route_after_triage,
                                {"false_positive": "false_positive_fast_track", "investigate": "log_analysis"})
    graph.add_edge("false_positive_fast_track", "risk_assessment")
    graph.add_edge("log_analysis", "threat_intelligence")
    graph.add_edge("threat_intelligence", "incident_investigation")
    graph.add_edge("incident_investigation", "risk_assessment")
    graph.add_edge("risk_assessment", "response_recommendation")
    graph.add_edge("response_recommendation", "human_approval_check")
    graph.add_conditional_edges("human_approval_check", route_after_approval_check,
                                {"escalate": "escalate_for_review", "report": "report_generation"})
    graph.add_edge("escalate_for_review", "report_generation")
    graph.add_edge("report_generation", END)
    return graph.compile()


def investigate_alert(
    raw_alert: dict[str, Any],
    alerts_df: Optional[pd.DataFrame],
    logs_df: Optional[pd.DataFrame],
    threat_intel_df: Optional[pd.DataFrame],
    llm: Optional[LLMClient] = None,
    compiled_graph: Any = None,
) -> IncidentReport:
    """Run the full workflow for one alert and return the final report."""
    app = compiled_graph or build_workflow(llm)
    try:
        final_state = app.invoke({
            "raw_alert": dict(raw_alert or {}),
            "alerts_df": alerts_df,
            "logs_df": logs_df,
            "threat_intel_df": threat_intel_df,
            "agent_trace": [],
            "limitations": [],
            "errors": [],
        })
    except Exception as exc:  # unexpected failure: surface a clear message
        raise WorkflowError(f"Investigation workflow failed: {type(exc).__name__}: {exc}") from exc
    return final_state["report"]


def investigate_all(
    alerts_df: pd.DataFrame,
    logs_df: Optional[pd.DataFrame],
    threat_intel_df: Optional[pd.DataFrame],
    llm: Optional[LLMClient] = None,
) -> dict[str, IncidentReport]:
    """Investigate every alert in ``alerts_df`` (the graph is compiled once)."""
    app = build_workflow(llm)
    reports: dict[str, IncidentReport] = {}
    for _, row in alerts_df.iterrows():
        raw = row.to_dict()
        report = investigate_alert(raw, alerts_df, logs_df, threat_intel_df, llm, compiled_graph=app)
        reports[str(raw.get("alert_id", report.report_id))] = report
    return reports


def workflow_mermaid(llm: Optional[LLMClient] = None) -> str:
    """Return the Mermaid definition of the compiled graph (used to check the README diagram)."""
    return build_workflow(llm).get_graph().draw_mermaid()
