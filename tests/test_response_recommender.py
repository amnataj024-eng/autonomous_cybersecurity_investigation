from graph.workflow import investigate_alert
from models.schemas import ApprovalStatus


def test_high_risk_escalates_and_never_executes(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1003"), alerts_df, logs_df, ti_df)
    plan = rep.response
    assert plan.escalate_to_human and plan.automated_actions_executed == 0
    assert all(a.simulated_only for a in plan.actions)
    assert any(a.action_type == "Containment" and a.requires_human_approval for a in plan.actions)
    assert plan.actions[0].action_type == "Escalation"
    assert rep.approval_status == ApprovalStatus.PENDING


def test_compromise_playbook_includes_credential_reset(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1001"), alerts_df, logs_df, ti_df)
    assert any("Reset credentials" in a.title for a in rep.response.actions)


def test_false_positive_gets_closure_actions(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1015"), alerts_df, logs_df, ti_df)
    assert not rep.response.escalate_to_human
    assert not any(a.action_type == "Containment" for a in rep.response.actions)
    assert rep.approval_status == ApprovalStatus.NOT_REQUIRED


def test_insufficient_information_recommends_collecting_evidence(raw_alert, alerts_df, logs_df, ti_df):
    rep = investigate_alert(raw_alert("ALR-1018"), alerts_df, logs_df, ti_df)
    assert any("Collect missing evidence" in a.title for a in rep.response.actions)
