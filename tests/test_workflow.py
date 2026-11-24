import pytest

from graph.workflow import (
    build_workflow, investigate_alert, investigate_all, route_after_approval_check, route_after_triage,
    workflow_mermaid,
)
from models.schemas import ApprovalStatus, IncidentCategory, RiskLevel, Verdict


def test_graph_contains_all_nodes():
    mermaid = workflow_mermaid()
    for node in ("receive_alert", "alert_triage", "log_analysis", "threat_intelligence", "incident_investigation",
                 "risk_assessment", "response_recommendation", "human_approval_check", "report_generation"):
        assert node in mermaid


def test_full_path_runs_all_agents_in_order(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1008"), alerts_df, logs_df, ti_df)
    names = [s.split(":")[0] for s in rep.agent_trace]
    assert names == ["Receive Alert", "Alert Triage", "Log Analysis", "Threat Intelligence",
                     "Incident Investigation", "Risk Assessment", "Response Recommendation", "Human Approval Check"]


def test_false_positive_route_skips_deep_investigation(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1017"), alerts_df, logs_df, ti_df)
    assert rep.final_classification == IncidentCategory.FALSE_POSITIVE
    assert rep.log_analysis is None and rep.risk is not None
    assert any("fast-tracked" in s for s in rep.agent_trace)


def test_high_risk_is_escalated(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1010"), alerts_df, logs_df, ti_df)
    assert rep.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert rep.approval_status == ApprovalStatus.PENDING
    assert any(s.startswith("Escalation") for s in rep.agent_trace)


def test_invalid_alert_is_reported_not_investigated(alerts_df, logs_df, ti_df):
    rep = investigate_alert({"alert_id": "BAD-1", "severity": "nope"}, alerts_df, logs_df, ti_df)
    assert rep.final_classification == IncidentCategory.INSUFFICIENT and rep.verdict == Verdict.INCONCLUSIVE
    assert rep.risk is None and rep.limitations and rep.triage is None


def test_missing_logs_and_intel_do_not_crash(raw_alert, alerts_df):
    rep = investigate_alert(raw_alert("ALR-1001"), alerts_df, None, None)
    assert rep.limitations and rep.final_classification in (IncidentCategory.INSUFFICIENT, IncidentCategory.BRUTE_FORCE)


def test_empty_alert_input(alerts_df, logs_df, ti_df):
    rep = investigate_alert({}, alerts_df, logs_df, ti_df)
    assert rep.verdict == Verdict.INCONCLUSIVE


def test_routing_functions():
    assert route_after_approval_check({"approval_status": "PENDING_HUMAN_REVIEW"}) == "escalate"
    assert route_after_approval_check({"approval_status": "NOT_REQUIRED"}) == "report"


def test_investigate_all_covers_every_alert(alerts_df, logs_df, ti_df):
    reports = investigate_all(alerts_df, logs_df, ti_df)
    assert len(reports) == len(alerts_df)
    cats = {r.final_classification for r in reports.values()}
    assert {IncidentCategory.FALSE_POSITIVE, IncidentCategory.NORMAL, IncidentCategory.INSUFFICIENT,
            IncidentCategory.BRUTE_FORCE, IncidentCategory.MALWARE} <= cats
    assert all(r.response.automated_actions_executed == 0 for r in reports.values() if r.response)
