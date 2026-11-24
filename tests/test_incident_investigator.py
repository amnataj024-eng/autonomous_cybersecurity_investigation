import json

from agents.alert_triage import triage_alert
from agents.incident_investigator import investigate
from agents.log_analyzer import analyze_logs
from agents.threat_intelligence import match_indicators
from models.schemas import IncidentCategory, Verdict


def run(raw_alert, alerts_df, logs_df, ti_df, alert_id, llm=None):
    alert, triage = triage_alert(raw_alert(alert_id), alerts_df)
    logs = analyze_logs(alert, logs_df)
    ti = match_indicators(logs.indicators, ti_df)
    return investigate(alert, triage, logs, ti, llm)


def test_expected_classifications(raw_alert, alerts_df, logs_df, ti_df):
    expected = {
        "ALR-1001": IncidentCategory.BRUTE_FORCE, "ALR-1004": IncidentCategory.NETWORK_ANOMALY,
        "ALR-1005": IncidentCategory.SUSPICIOUS_LOGIN, "ALR-1006": IncidentCategory.NETWORK_ANOMALY,
        "ALR-1008": IncidentCategory.UNAUTHORIZED_ACCESS, "ALR-1009": IncidentCategory.SUSPICIOUS_ACCOUNT,
        "ALR-1010": IncidentCategory.MALWARE, "ALR-1012": IncidentCategory.NORMAL,
        "ALR-1013": IncidentCategory.FALSE_POSITIVE, "ALR-1018": IncidentCategory.INSUFFICIENT,
        "ALR-1019": IncidentCategory.FALSE_POSITIVE,
    }
    for alert_id, category in expected.items():
        assert run(raw_alert, alerts_df, logs_df, ti_df, alert_id).classification == category, alert_id


def test_genuine_incident_has_evidence_and_pattern(raw_alert, alerts_df, logs_df, ti_df):
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1003")
    assert r.verdict == Verdict.GENUINE and r.evidence and "brute force" in r.attack_pattern
    assert "data exfiltration" in r.attack_pattern and r.confidence == "High"


def test_unverified_indicator_is_not_treated_as_proof(raw_alert, alerts_df, logs_df, ti_df):
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1019")
    assert r.verdict == Verdict.FALSE_POSITIVE and r.confidence == "Low"


def test_missing_data_is_reported_not_invented(raw_alert, alerts_df, logs_df, ti_df):
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1018")
    assert r.verdict == Verdict.INCONCLUSIVE and r.limitations and not r.evidence


def test_llm_narrative_is_used_when_valid(raw_alert, alerts_df, logs_df, ti_df, make_llm):
    llm = make_llm({"narrative": "The evidence (E1) shows repeated failed logins followed by a success.",
                    "attack_pattern": "Credential attack", "suggested_classification": "Brute-force login attempts",
                    "cited_evidence_ids": ["E1"]})
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1001", llm)
    assert r.llm_status == "used" and r.llm_agrees_with_rules is True
    assert r.classification == IncidentCategory.BRUTE_FORCE


def test_llm_cannot_override_classification(raw_alert, alerts_df, logs_df, ti_df, make_llm):
    llm = make_llm({"narrative": "This looks like malware activity based on E1 evidence only.",
                    "attack_pattern": "Malware", "suggested_classification": "Potential malware indicators",
                    "cited_evidence_ids": ["E1"]})
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1001", llm)
    assert r.classification == IncidentCategory.BRUTE_FORCE and r.llm_agrees_with_rules is False
    assert any("rule-based result was kept" in x for x in r.limitations)


def test_llm_hallucinated_evidence_and_ips_are_rejected(raw_alert, alerts_df, logs_df, ti_df, make_llm):
    bad_ids = make_llm({"narrative": "Narrative long enough to pass validation here.", "attack_pattern": "x y z",
                        "suggested_classification": "False positive", "cited_evidence_ids": ["E99"]})
    assert run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1001", bad_ids).llm_status.startswith("failed")
    bad_ip = make_llm({"narrative": "Traffic from 8.8.4.4 was observed attacking the VPN gateway.",
                       "attack_pattern": "attack", "suggested_classification": "Brute-force login attempts",
                       "cited_evidence_ids": ["E1"]})
    r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1001", bad_ip)
    assert r.llm_status.startswith("failed") and "8.8.4.4" not in r.narrative


def test_llm_failures_fall_back_to_rules(raw_alert, alerts_df, logs_df, ti_df, make_llm):
    for llm in (make_llm(error=TimeoutError("timeout")), make_llm("not json"), make_llm({"narrative": "short"})):
        r = run(raw_alert, alerts_df, logs_df, ti_df, "ALR-1001", llm)
        assert r.llm_status.startswith("failed") and r.classification == IncidentCategory.BRUTE_FORCE
        assert r.narrative
