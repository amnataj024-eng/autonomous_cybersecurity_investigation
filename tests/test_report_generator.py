import json

import pytest

from agents.report_generator import apply_human_decision, render_text_report, report_to_json, save_report
from graph.workflow import investigate_alert
from models.schemas import ApprovalStatus, IncidentReport


@pytest.fixture
def report(raw_alert, alerts_df, logs_df, ti_df, demo_llm):
    return investigate_alert(raw_alert("ALR-1003"), alerts_df, logs_df, ti_df, demo_llm)


def test_text_report_contains_all_sections(report):
    text = render_text_report(report)
    for heading in ("ORIGINAL ALERT", "EXECUTIVE SUMMARY", "LOG ANALYSIS FINDINGS", "THREAT INTELLIGENCE",
                    "RISK ASSESSMENT", "RECOMMENDED DEFENSIVE ACTIONS", "FINAL INCIDENT CLASSIFICATION"):
        assert heading in text
    assert "SIMULATED" in text and "ALR-1003" in text


def test_json_export_round_trips(report):
    data = json.loads(report_to_json(report))
    assert data["risk"]["score"] == report.risk.score
    assert IncidentReport.model_validate(data).report_id == report.report_id


def test_save_report_writes_files(report, tmp_path):
    json_path, txt_path = save_report(report, tmp_path)
    assert json_path.exists() and txt_path.exists()
    assert "INCIDENT INVESTIGATION REPORT" in txt_path.read_text(encoding="utf-8")


def test_human_decision_is_simulated_and_logged(report):
    updated = apply_human_decision(report, "approve", "looks right")
    assert updated.approval_status == ApprovalStatus.APPROVED
    assert "nothing was executed" in updated.approval_log[-1]
    assert report.approval_status == ApprovalStatus.PENDING  # original untouched
    assert apply_human_decision(report, "reject").approval_status == ApprovalStatus.REJECTED


def test_decision_validation(report, raw_alert, alerts_df, logs_df, ti_df):
    with pytest.raises(ValueError):
        apply_human_decision(report, "maybe")
    low = investigate_alert(raw_alert("ALR-1012"), alerts_df, logs_df, ti_df)
    with pytest.raises(ValueError):
        apply_human_decision(low, "approve")


def test_llm_summary_used_and_fallback(raw_alert, alerts_df, logs_df, ti_df, make_llm):
    good = make_llm({"executive_summary": "The incident was classified with a high risk score and all actions are simulated."})
    rep = investigate_alert(raw_alert("ALR-1008"), alerts_df, logs_df, ti_df, good)
    assert rep.executive_summary.startswith("The incident was classified") and "LLM-assisted" in rep.analysis_mode
    failing = make_llm(error=ConnectionError("down"))
    rep = investigate_alert(raw_alert("ALR-1008"), alerts_df, logs_df, ti_df, failing)
    assert rep.analysis_mode.startswith("Rule-based fallback") and "ALR-1008" in rep.executive_summary
    assert any("LLM unavailable" in x for x in rep.limitations)
