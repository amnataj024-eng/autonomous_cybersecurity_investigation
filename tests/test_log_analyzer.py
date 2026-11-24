import pandas as pd

from agents.alert_triage import validate_alert
from agents.log_analyzer import _max_in_window, analyze_logs
from utils.data_loader import validate_logs


def analyze(raw_alert, logs_df, alert_id, **kw):
    alert, _ = validate_alert(raw_alert(alert_id))
    return analyze_logs(alert, logs_df, **kw)


def types(result):
    return {f.finding_type for f in result.findings if f.suspicious}


def test_brute_force_and_success_after_failures(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1001")
    assert {"BRUTE_FORCE", "SUCCESS_AFTER_FAILURES"} <= types(r)
    assert r.metrics.failed_logins >= 40 and r.metrics.success_after_failures
    assert "203.0.113.45" in r.indicators.ips


def test_impossible_travel_and_unusual_location(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1005")
    assert {"IMPOSSIBLE_TRAVEL", "UNUSUAL_LOCATION"} <= types(r)


def test_port_scan_detected(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1006")
    assert r.metrics.port_scan and r.metrics.distinct_ports >= 15


def test_unauthorized_access_detected(raw_alert, logs_df):
    assert "UNAUTHORIZED_ACCESS" in types(analyze(raw_alert, logs_df, "ALR-1008"))


def test_account_change_detected(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1009")
    assert "ACCOUNT_CHANGE" in types(r) and r.metrics.privilege_changes == 1


def test_beaconing_detected(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1011")
    assert r.metrics.beaconing and "DNS_BEACONING" in types(r)


def test_normal_activity_has_no_suspicious_findings(raw_alert, logs_df):
    assert types(analyze(raw_alert, logs_df, "ALR-1012")) == set()


def test_benign_failed_logins_below_threshold(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1013")
    assert "BRUTE_FORCE" not in types(r) and not r.metrics.success_after_failures


def test_no_related_logs_reports_limitation(raw_alert, logs_df):
    r = analyze(raw_alert, logs_df, "ALR-1018")
    assert r.metrics.total_related_events == 0 and r.limitations


def test_missing_logs_reports_limitation(raw_alert):
    alert, _ = validate_alert(raw_alert("ALR-1001"))
    for empty in (None, pd.DataFrame()):
        assert analyze_logs(alert, empty).limitations


def test_ml_can_be_disabled(raw_alert, logs_df):
    assert analyze(raw_alert, logs_df, "ALR-1001", use_ml=False).metrics.ml_anomalies == 0


def test_burst_window_helper():
    base = pd.Timestamp("2026-01-01", tz="UTC")
    times = [base + pd.Timedelta(seconds=10 * i) for i in range(6)] + [base + pd.Timedelta(hours=2)]
    assert _max_in_window(times) == 6


def test_validate_logs_handles_bad_input():
    _, rep = validate_logs(pd.DataFrame({"foo": ["x"]}))
    assert not rep.valid and "Missing required" in rep.errors[0]
    _, rep = validate_logs(pd.DataFrame())
    assert not rep.valid
    df = pd.DataFrame({"timestamp": ["2026-01-01T00:00:00Z", "garbage"], "event_type": ["login", "login"],
                       "source_ip": ["1.2.3.4", "1.2.3.4"]})
    cleaned, rep = validate_logs(df)
    assert rep.valid and rep.rows_kept == 1 and rep.warnings
