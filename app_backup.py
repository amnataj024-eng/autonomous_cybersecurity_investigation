"""Streamlit dashboard for the Autonomous Cybersecurity Incident Investigation system.

Run with:  streamlit run app.py
All data is synthetic demonstration data and every response action is SIMULATED.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agents.alert_triage import categorize_alert
from agents.report_generator import apply_human_decision, render_text_report, report_to_json
from graph.workflow import WorkflowError, build_workflow, investigate_alert
from models.schemas import ApprovalStatus, IncidentCategory, IncidentReport, RiskLevel
from utils.data_loader import (
    load_alerts,
    load_logs,
    load_threat_intel,
    read_csv_strings,
    validate_logs,
)
from utils.llm import get_llm_client

st.set_page_config(page_title="Cyber Incident Investigator", page_icon="🛡️", layout="wide")

PAGES = ["Dashboard", "Alert Management", "Investigation", "Security Logs",
         "Incident Reports", "Human Approval"]
LEVEL_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.6rem; max-width: 1400px;}
    div[data-testid="stMetric"] {background: var(--secondary-background-color);
        border-radius: 12px; padding: 14px 16px; border: 1px solid rgba(128,128,128,.25);}
    .badge {display:inline-block; padding: 2px 12px; border-radius: 999px; color: white;
        font-weight: 600; font-size: 0.85rem;}
    .sim-banner {border-left: 5px solid #1976d2; padding: 8px 14px; border-radius: 6px;
        background: var(--secondary-background-color); margin-bottom: 1rem;}
    @media (max-width: 800px) {.block-container {padding: 1rem 0.6rem;}}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# State helpers
# --------------------------------------------------------------------------- #


def init_state() -> None:
    """Load the sample datasets once per browser session."""
    if st.session_state.get("initialised"):
        return
    st.session_state.data_error = ""
    try:
        st.session_state.alerts_df = load_alerts()
        st.session_state.logs_df = load_logs()
        st.session_state.ti_df = load_threat_intel()
    except (OSError, ValueError) as exc:
        st.session_state.data_error = str(exc)
        st.session_state.alerts_df = pd.DataFrame()
        st.session_state.logs_df = pd.DataFrame()
        st.session_state.ti_df = pd.DataFrame()
    st.session_state.reports = {}
    st.session_state.logs_source = "Sample data"
    st.session_state.page = PAGES[0]
    st.session_state.run_pending = None
    ids = list(st.session_state.alerts_df.get("alert_id", []))
    st.session_state.inv_alert = ids[0] if ids else None
    st.session_state.initialised = True


def get_llm():
    """Return the LLM client for the current sidebar setting."""
    enabled = st.session_state.get("use_llm", True)
    cached = st.session_state.get("_llm")
    if cached is None or cached.enabled != enabled:
        cached = get_llm_client(enabled=enabled)
        st.session_state["_llm"] = cached
    return cached


def badge(text: str, level: str) -> str:
    return f'<span class="badge" style="background:{LEVEL_COLORS.get(level, "#546e7a")}">{text}</span>'


def run_investigation(alert_id: str) -> IncidentReport | None:
    """Investigate one alert with the LangGraph workflow and store the report."""
    alerts = st.session_state.alerts_df
    row = alerts[alerts["alert_id"] == alert_id]
    if row.empty:
        st.error(f"Alert {alert_id} was not found.")
        return None
    try:
        with st.spinner(f"Agents are investigating {alert_id}..."):
            report = investigate_alert(row.iloc[0].to_dict(), alerts, st.session_state.logs_df,
                                       st.session_state.ti_df, get_llm())
    except WorkflowError as exc:
        st.error(str(exc))
        return None
    st.session_state.reports[alert_id] = report
    return report


def run_all_investigations() -> None:
    """Investigate every alert (the workflow graph is compiled once)."""
    alerts = st.session_state.alerts_df
    llm = get_llm()
    graph = build_workflow(llm)
    bar = st.progress(0.0, text="Starting...")
    failures = 0
    for i, (_, row) in enumerate(alerts.iterrows(), start=1):
        raw = row.to_dict()
        try:
            st.session_state.reports[raw["alert_id"]] = investigate_alert(
                raw, alerts, st.session_state.logs_df, st.session_state.ti_df, llm, compiled_graph=graph)
        except WorkflowError:
            failures += 1
        bar.progress(i / len(alerts), text=f"Investigated {i}/{len(alerts)} alerts")
    bar.empty()
    if failures:
        st.warning(f"{failures} alert(s) could not be investigated.")
    else:
        st.success(f"Investigated {len(alerts)} alerts.")


def go_to_investigation(alert_id: str) -> None:
    """Button callback: jump to the Investigation page and queue the run."""
    st.session_state.inv_alert = alert_id
    st.session_state.run_pending = alert_id
    st.session_state.page = "Investigation"


# --------------------------------------------------------------------------- #
# Reusable renderers
# --------------------------------------------------------------------------- #


def render_report(report: IncidentReport) -> None:
    """Show agent-by-agent findings, indicators, risk and classification."""
    risk = report.risk
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk score", f"{risk.score}/100" if risk else "n/a")
    c2.metric("Risk level", risk.level.value if risk else "n/a")
    c3.metric("Classification", report.final_classification.value)
    c4.metric("Human approval", report.approval_status.value.replace("_", " ").title())
    if risk:
        st.progress(risk.score / 100, text=f"Risk {risk.score}/100 - {risk.level.value}")
    st.info(report.executive_summary)
    st.caption(f"Analysis mode: {report.analysis_mode}  |  Verdict: {report.verdict.value}")

    tabs = st.tabs(["Alert Triage", "Log Analysis", "Threat Intelligence", "Investigation",
                    "Risk Score", "Response", "Agent Trace"])
    with tabs[0]:
        t = report.triage
        if t:
            st.write(f"**Category:** {t.category.value}  \n**Initial severity:** {t.initial_severity.value}")
            st.write(f"**Duplicate:** {'Yes, of ' + str(t.duplicate_of) if t.is_duplicate else 'No'}")
            st.write(f"**False positive:** {'Yes - ' + t.false_positive_reason if t.is_false_positive else 'No'}")
            st.write(f"**Linked alerts:** {', '.join(t.related_alert_ids) or 'none'}")
            for note in t.notes:
                st.caption(note)
        else:
            st.warning("Triage did not run: " + "; ".join(report.limitations))
    with tabs[1]:
        la = report.log_analysis
        if la:
            st.write(la.summary)
            for f in la.findings:
                label = f"[{f.severity.value}] {f.finding_type}" + ("" if f.suspicious else " (informational)")
                with st.expander(f"{label} - {f.event_count} event(s)"):
                    st.write(f.description)
                    for ev in f.evidence:
                        st.code(ev, language="text")
            ind = la.indicators
            rows = [{"Indicator": v, "Type": k} for k, vals in
                    (("IP", ind.ips), ("Domain", ind.domains), ("File hash", ind.hashes)) for v in vals]
            if rows:
                st.markdown("**Extracted indicators**")
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        else:
            st.info("Log analysis was not performed for this alert.")
    with tabs[2]:
        ti = report.threat_intel
        if ti:
            st.write(ti.summary)
            for m in ti.verified_matches:
                st.error(f"VERIFIED: {m.explanation}")
            for m in ti.unverified_matches:
                st.warning(f"UNVERIFIED: {m.explanation}")
            if ti.unmatched_indicators:
                st.caption("No record in the local dataset (not proof of safety): "
                           + ", ".join(x[:32] for x in ti.unmatched_indicators))
        else:
            st.info("Threat-intelligence checks were not performed for this alert.")
    with tabs[3]:
        inv = report.investigation
        if inv:
            st.write(f"**Classification:** {inv.classification.value}  \n**Verdict:** {inv.verdict.value}  \n"
                     f"**Confidence:** {inv.confidence}  \n**Attack pattern:** {inv.attack_pattern}")
            st.write(inv.narrative)
            if inv.evidence:
                st.dataframe(pd.DataFrame([e.model_dump() for e in inv.evidence]),
                             hide_index=True, width="stretch")
        for item in report.limitations:
            st.caption(f"Limitation: {item}")
    with tabs[4]:
        if risk:
            st.dataframe(pd.DataFrame([c.model_dump() for c in risk.components]),
                         hide_index=True, width="stretch")
            for adj in risk.adjustments:
                st.warning(adj)
            st.write(risk.explanation)
        else:
            st.info("No risk score was calculated.")
    with tabs[5]:
        if report.response:
            st.markdown('<div class="sim-banner">SIMULATION ONLY - nothing is executed automatically. '
                        "Every action needs human approval.</div>", unsafe_allow_html=True)
            st.dataframe(pd.DataFrame([a.model_dump() for a in report.response.actions])[
                ["priority", "title", "action_type", "requires_human_approval", "description"]],
                hide_index=True, width="stretch")
            if report.response.escalation_reason:
                st.warning(report.response.escalation_reason)
    with tabs[6]:
        for i, step in enumerate(report.agent_trace, 1):
            st.write(f"{i}. {step}")


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #


def page_dashboard() -> None:
    st.title("🛡️ Security Operations Dashboard")
    st.markdown('<div class="sim-banner">Demonstration environment: synthetic data only. '
                "Recommended actions are simulated and never executed.</div>", unsafe_allow_html=True)
    alerts, reports = st.session_state.alerts_df, st.session_state.reports
    fp = sum(r.final_classification == IncidentCategory.FALSE_POSITIVE for r in reports.values())
    high = sum(bool(r.risk and r.risk.level == RiskLevel.HIGH) for r in reports.values())
    crit = sum(bool(r.risk and r.risk.level == RiskLevel.CRITICAL) for r in reports.values())
    cols = st.columns(5)
    cols[0].metric("Total alerts", len(alerts))
    cols[1].metric("Investigated incidents", len(reports))
    cols[2].metric("False positives", fp)
    cols[3].metric("High-risk incidents", high)
    cols[4].metric("Critical incidents", crit)

    if st.button("▶ Investigate all alerts", type="primary", disabled=alerts.empty):
        run_all_investigations()
        st.rerun()

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        if not alerts.empty:
            order = ["Low", "Medium", "High", "Critical"]
            counts = alerts["severity"].value_counts().reindex(order).fillna(0)
            st.bar_chart(counts)
    with right:
        st.subheader("Investigated incidents by classification")
        if reports:
            st.bar_chart(pd.Series([r.final_classification.value for r in reports.values()]).value_counts())
        else:
            st.info("No investigations yet. Click 'Investigate all alerts' or open an alert.")

    if reports:
        st.subheader("Investigated incidents (highest risk first)")
        rows = [{"Alert": aid, "Type": r.alert.get("alert_type"), "Classification": r.final_classification.value,
                 "Risk score": r.risk.score if r.risk else None,
                 "Risk level": r.risk.level.value if r.risk else "n/a",
                 "Approval": r.approval_status.value} for aid, r in reports.items()]
        table = pd.DataFrame(rows).sort_values("Risk score", ascending=False, na_position="last")
        st.dataframe(table, hide_index=True, width="stretch")


def page_alerts() -> None:
    st.title("Alert Management")
    alerts = st.session_state.alerts_df
    if alerts.empty:
        st.warning("No alerts are loaded.")
        return
    view = alerts.copy()
    view["category"] = [categorize_alert(t, d).value for t, d in zip(view["alert_type"], view["description"])]
    c1, c2, c3 = st.columns([2, 1, 1])
    query = c1.text_input("Search (id, IP, user, host, description...)")
    severities = c2.multiselect("Severity", ["Low", "Medium", "High", "Critical"])
    categories = c3.multiselect("Category", sorted(view["category"].unique()))
    if query:
        mask = view.astype(str).apply(lambda col: col.str.contains(query, case=False, regex=False)).any(axis=1)
        view = view[mask]
    if severities:
        view = view[view["severity"].isin(severities)]
    if categories:
        view = view[view["category"].isin(categories)]
    st.caption(f"Showing {len(view)} of {len(alerts)} alerts")
    st.dataframe(view[["alert_id", "timestamp", "severity", "category", "alert_type", "source_ip",
                       "username", "hostname", "description"]], hide_index=True, width="stretch")
    if view.empty:
        return
    st.subheader("Select an alert to investigate")
    choice = st.selectbox("Alert", list(view["alert_id"]), key="alert_page_select")
    row = view[view["alert_id"] == choice].iloc[0]
    st.write(f"**{row['alert_type']}** ({row['severity']}) - {row['description']}")
    st.button("🔍 Investigate this alert", type="primary", on_click=go_to_investigation, args=(choice,))
    if choice in st.session_state.reports:
        st.caption("This alert has already been investigated; investigating again refreshes the report.")


def page_investigation() -> None:
    st.title("Investigation")
    alerts = st.session_state.alerts_df
    if alerts.empty:
        st.warning("No alerts are loaded.")
        return
    ids = list(alerts["alert_id"])
    if st.session_state.get("inv_alert") not in ids:
        st.session_state.inv_alert = ids[0]
    alert_id = st.selectbox("Alert to investigate", ids, key="inv_alert")
    pending = st.session_state.run_pending
    if pending:
        st.session_state.run_pending = None
        run_investigation(pending)
    elif st.button("▶ Run investigation", type="primary"):
        run_investigation(alert_id)
    report = st.session_state.reports.get(alert_id)
    if report is None:
        st.info("Select an alert and click 'Run investigation'.")
        return
    st.subheader(f"{alert_id} - {report.alert.get('alert_type')}")
    render_report(report)


def page_logs() -> None:
    st.title("Security Logs")
    st.caption(f"Current log source: **{st.session_state.logs_source}**")
    with st.expander("Upload a CSV log file", expanded=False):
        st.write("Required columns: `timestamp`, `event_type`, `source_ip`. Optional: `status`, `username`, "
                 "`destination_ip`, `hostname`, `country`, `destination_port`, `bytes_out`, `resource`, "
                 "`domain`, `file_hash`.")
        uploaded = st.file_uploader("CSV file", type="csv", key="log_upload")
        if uploaded is not None:
            try:
                raw = read_csv_strings(uploaded)
            except Exception as exc:  # unreadable / empty / wrong encoding
                st.error(f"Could not read the file as CSV: {type(exc).__name__}")
                raw = None
            if raw is not None:
                cleaned, report = validate_logs(raw)
                for err in report.errors:
                    st.error(err)
                for warn in report.warnings:
                    st.warning(warn)
                if report.valid:
                    st.success(f"Validation passed: {report.rows_kept} of {report.rows_in} rows are usable.")
                    st.dataframe(cleaned.head(20), hide_index=True, width="stretch")
                    if st.button("Use these logs for investigations"):
                        st.session_state.logs_df = cleaned
                        st.session_state.logs_source = f"Uploaded: {uploaded.name}"
                        st.session_state.reports = {}
                        st.rerun()
        if st.session_state.logs_source != "Sample data" and st.button("Reset to sample logs"):
            st.session_state.logs_df = load_logs()
            st.session_state.logs_source = "Sample data"
            st.session_state.reports = {}
            st.rerun()

    logs = st.session_state.logs_df
    if logs.empty:
        st.warning("No logs are loaded.")
        return
    c1, c2, c3 = st.columns([2, 1, 1])
    query = c1.text_input("Search logs")
    events = c2.multiselect("Event type", sorted(logs["event_type"].unique()))
    statuses = c3.multiselect("Status", sorted(logs["status"].unique()))
    view = logs
    if query:
        mask = view.astype(str).apply(lambda col: col.str.contains(query, case=False, regex=False)).any(axis=1)
        view = view[mask]
    if events:
        view = view[view["event_type"].isin(events)]
    if statuses:
        view = view[view["status"].isin(statuses)]
    st.caption(f"Showing {len(view)} of {len(logs)} log entries")
    st.dataframe(view, hide_index=True, width="stretch")


def page_reports() -> None:
    st.title("Incident Reports")
    reports = st.session_state.reports
    if not reports:
        st.info("No reports yet. Investigate an alert first.")
        return
    alert_id = st.selectbox("Report", list(reports), key="report_select")
    report = reports[alert_id]
    c1, c2 = st.columns(2)
    c1.download_button("⬇ Download JSON", report_to_json(report), file_name=f"{report.report_id}.json",
                       mime="application/json", width="stretch")
    c2.download_button("⬇ Download TXT", render_text_report(report), file_name=f"{report.report_id}.txt",
                       mime="text/plain", width="stretch")
    st.subheader("Recommended defensive actions (simulated)")
    if report.response:
        st.dataframe(pd.DataFrame([a.model_dump() for a in report.response.actions])[
            ["priority", "title", "action_type", "requires_human_approval", "description"]],
            hide_index=True, width="stretch")
    with st.expander("Full report text", expanded=True):
        st.code(render_text_report(report), language="text", wrap_lines=True)


def page_approval() -> None:
    st.title("Human Approval")
    st.markdown('<div class="sim-banner"><b>SIMULATION:</b> Approve / Reject only records a decision in this '
                "demo. No real security action is ever executed.</div>", unsafe_allow_html=True)
    reports = st.session_state.reports
    pending = {k: r for k, r in reports.items() if r.approval_status == ApprovalStatus.PENDING}
    decided = {k: r for k, r in reports.items()
               if r.approval_status in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED)}
    if not reports:
        st.info("Investigate alerts first; High and Critical incidents will appear here.")
        return
    st.subheader(f"Awaiting review ({len(pending)})")
    if not pending:
        st.success("No incidents are waiting for review.")
    for alert_id, report in pending.items():
        level = report.risk.level.value if report.risk else "n/a"
        with st.expander(f"{alert_id} - {report.final_classification.value} - {level} "
                         f"({report.risk.score if report.risk else '-'}/100)"):
            st.markdown(badge(level, level), unsafe_allow_html=True)
            st.write(report.executive_summary)
            if report.response:
                for action in report.response.actions:
                    st.write(f"- **{action.title}** ({action.priority}): {action.description}")
            note = st.text_input("Reviewer note (optional)", key=f"note_{alert_id}")
            a, b = st.columns(2)
            if a.button("✅ Approve (simulated)", key=f"approve_{alert_id}", width="stretch"):
                st.session_state.reports[alert_id] = apply_human_decision(report, "approve", note)
                st.rerun()
            if b.button("⛔ Reject (simulated)", key=f"reject_{alert_id}", width="stretch"):
                st.session_state.reports[alert_id] = apply_human_decision(report, "reject", note)
                st.rerun()
    if decided:
        st.subheader("Decisions recorded")
        st.dataframe(pd.DataFrame([{"Alert": k, "Decision": r.approval_status.value,
                                    "Log": r.approval_log[-1] if r.approval_log else ""}
                                   for k, r in decided.items()]), hide_index=True, width="stretch")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> None:
    init_state()
    with st.sidebar:
        st.header("🛡️ Incident Investigator")
        st.radio("Navigation", PAGES, key="page")
        st.divider()
        st.checkbox("Use Groq LLM when configured", value=True, key="use_llm",
                    help="Without a valid GROQ_API_KEY the app runs in DEMO mode (rule-based).")
        st.caption(f"Mode: **{get_llm().mode_label}**")
        st.caption("All data is synthetic demonstration data.")
    if st.session_state.data_error:
        st.error(f"Could not load the sample data: {st.session_state.data_error}")
    {"Dashboard": page_dashboard, "Alert Management": page_alerts, "Investigation": page_investigation,
     "Security Logs": page_logs, "Incident Reports": page_reports,
     "Human Approval": page_approval}[st.session_state.page]()


main()
