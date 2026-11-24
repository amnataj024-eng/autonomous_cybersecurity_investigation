import pytest

from agents.risk_assessor import assess_risk
from models.schemas import (
    Finding, IncidentCategory, IndicatorMatch, LogAnalysisResult, LogMetrics, RiskLevel,
    Severity, ThreatIntelResult,
)
from utils.risk_scoring import RiskInputs, calculate_risk, level_from_score


@pytest.mark.parametrize("score,level", [(0, RiskLevel.LOW), (24, RiskLevel.LOW), (25, RiskLevel.MEDIUM),
                                         (49, RiskLevel.MEDIUM), (50, RiskLevel.HIGH), (74, RiskLevel.HIGH),
                                         (75, RiskLevel.CRITICAL), (100, RiskLevel.CRITICAL)])
def test_level_boundaries(score, level):
    assert level_from_score(score) == level


def _inputs(**kw):
    base = dict(alert_severity=Severity.MEDIUM, classification=IncidentCategory.BRUTE_FORCE,
                log_analysis=None, threat_intel=None)
    return RiskInputs(**{**base, **kw})


def test_minimal_inputs_score_only_severity():
    r = calculate_risk(_inputs())
    assert r.score == 8 and r.level == RiskLevel.LOW and len(r.components) == 7


def test_component_maxima_sum_to_100():
    r = calculate_risk(_inputs())
    assert sum(c.max_points for c in r.components) == 100


def test_score_is_always_between_0_and_100():
    metrics = LogMetrics(failed_logins=500, failed_burst_max=400, distinct_users_targeted=20,
                         impossible_travel=True, unusual_location_logins=3, off_hours_logins=3,
                         success_after_failures=True, large_transfer=True, privilege_changes=2,
                         denied_access=50, beaconing=True, port_scan=True, suspicious_event_count=900)
    findings = [Finding(finding_type=t, description="x") for t in "ABCD"]
    match = IndicatorMatch(indicator="1.1.1.1", indicator_type="ip", threat_type="Command and control",
                           confidence="High", status="verified", explanation="x")
    r = calculate_risk(_inputs(alert_severity=Severity.CRITICAL, related_alert_count=9,
                               log_analysis=LogAnalysisResult(metrics=metrics, findings=findings),
                               threat_intel=ThreatIntelResult(verified_matches=[match] * 6)))
    assert 0 <= r.score <= 100 and r.level == RiskLevel.CRITICAL


def test_false_positive_is_capped():
    metrics = LogMetrics(failed_logins=60, failed_burst_max=50, distinct_users_targeted=5, suspicious_event_count=60)
    r = calculate_risk(_inputs(alert_severity=Severity.CRITICAL, classification=IncidentCategory.FALSE_POSITIVE,
                               log_analysis=LogAnalysisResult(metrics=metrics)))
    assert r.score <= 20 and r.adjustments


def test_insufficient_data_floor_for_high_alerts():
    r = calculate_risk(_inputs(alert_severity=Severity.HIGH, classification=IncidentCategory.INSUFFICIENT))
    assert r.score == 25 and r.level == RiskLevel.MEDIUM


def test_privilege_change_floor():
    metrics = LogMetrics(privilege_changes=1, account_changes=1, suspicious_event_count=2)
    r = calculate_risk(_inputs(classification=IncidentCategory.SUSPICIOUS_ACCOUNT,
                               log_analysis=LogAnalysisResult(metrics=metrics)))
    assert r.score >= 50 and any("minimum" in a for a in r.adjustments)


def test_scenarios_end_to_end(raw_alert, alerts_df, logs_df, ti_df):
    from graph.workflow import investigate_alert
    expected = {"ALR-1003": RiskLevel.CRITICAL, "ALR-1009": RiskLevel.HIGH, "ALR-1005": RiskLevel.MEDIUM,
                "ALR-1012": RiskLevel.LOW, "ALR-1017": RiskLevel.LOW}
    for alert_id, level in expected.items():
        rep = investigate_alert(raw_alert(alert_id), alerts_df, logs_df, ti_df)
        assert rep.risk.level == level, alert_id


def test_assess_risk_wrapper(raw_alert, alerts_df, logs_df, ti_df):
    from agents.alert_triage import triage_alert
    from agents.incident_investigator import investigate
    from agents.log_analyzer import analyze_logs
    from agents.threat_intelligence import match_indicators
    alert, triage = triage_alert(raw_alert("ALR-1010"), alerts_df)
    logs = analyze_logs(alert, logs_df)
    ti = match_indicators(logs.indicators, ti_df)
    risk = assess_risk(triage, investigate(alert, triage, logs, ti), logs, ti)
    assert risk.level == RiskLevel.CRITICAL and "explanation" and risk.explanation
