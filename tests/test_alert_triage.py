import pytest

from agents.alert_triage import (
    assign_initial_severity, categorize_alert, detect_false_positive,
    find_duplicate, find_related_alerts, triage_alert, validate_alert,
)
from models.schemas import IncidentCategory, Severity

BASE = {"alert_id": "T-1", "timestamp": "2026-11-18T10:00:00Z", "alert_type": "failed_login_burst",
        "severity": "High", "source_ip": "203.0.113.5", "username": "bob", "event_count": "12"}


def test_valid_alert_is_accepted():
    alert, errors = validate_alert(BASE)
    assert errors == [] and alert.severity == Severity.HIGH and alert.event_count == 12


@pytest.mark.parametrize("change,fragment", [
    ({"severity": "urgent"}, "severity"),
    ({"timestamp": "not-a-date"}, "timestamp"),
    ({"source_ip": "999.1.1.1"}, "source_ip"),
    ({"alert_id": ""}, "alert_id"),
])
def test_invalid_alert_reports_errors(change, fragment):
    alert, errors = validate_alert({**BASE, **change})
    assert alert is None and any(fragment in e for e in errors)


def test_empty_and_entityless_alerts_rejected():
    assert validate_alert({})[0] is None
    entityless = {k: v for k, v in BASE.items() if k not in ("source_ip", "username")}
    assert validate_alert(entityless)[0] is None


def test_categorization_table_and_keywords():
    assert categorize_alert("port_scan") == IncidentCategory.NETWORK_ANOMALY
    assert categorize_alert("malware_detected") == IncidentCategory.MALWARE
    assert categorize_alert("weird_type", "possible ransomware found") == IncidentCategory.MALWARE
    assert categorize_alert("mystery", "nothing useful") == IncidentCategory.INSUFFICIENT


def test_false_positive_rules(raw_alert):
    for alert_id in ("ALR-1014", "ALR-1015", "ALR-1016", "ALR-1017"):
        alert, _ = validate_alert(raw_alert(alert_id))
        assert detect_false_positive(alert)[0], alert_id
    for alert_id in ("ALR-1001", "ALR-1009", "ALR-1010"):
        alert, _ = validate_alert(raw_alert(alert_id))
        assert not detect_false_positive(alert)[0], alert_id


def test_duplicate_detection(raw_alert, alerts_df):
    alert, _ = validate_alert(raw_alert("ALR-1002"))
    assert find_duplicate(alert, alerts_df) == "ALR-1001"
    original, _ = validate_alert(raw_alert("ALR-1001"))
    assert find_duplicate(original, alerts_df) is None


def test_related_alerts_form_incident_chain(raw_alert, alerts_df):
    alert, _ = validate_alert(raw_alert("ALR-1001"))
    related = find_related_alerts(alert, alerts_df)
    assert {"ALR-1002", "ALR-1003", "ALR-1004"} <= set(related)
    assert "ALR-1012" not in related


def test_initial_severity_bump():
    alert, _ = validate_alert({**BASE, "severity": "Medium", "event_count": "30"})
    assert assign_initial_severity(alert, IncidentCategory.NETWORK_ANOMALY) == Severity.HIGH


def test_triage_result_for_invalid_alert():
    alert, triage = triage_alert({"alert_id": "X", "severity": "bad"}, None)
    assert alert is None and not triage.is_valid and not triage.forward_to_investigation


def test_triage_forwards_suspicious_alert(raw_alert, alerts_df):
    _, triage = triage_alert(raw_alert("ALR-1008"), alerts_df)
    assert triage.forward_to_investigation and triage.category == IncidentCategory.UNAUTHORIZED_ACCESS
