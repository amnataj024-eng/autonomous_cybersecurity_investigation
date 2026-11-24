
"""
Autonomous Cybersecurity Incident Investigation
Professional Streamlit SOC Dashboard

Run:
    streamlit run app.py

IMPORTANT:
All data is synthetic demonstration data.
All response actions are simulated.
No real security action is executed.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from agents.alert_triage import categorize_alert
from agents.report_generator import (
    apply_human_decision,
    render_text_report,
    report_to_json,
)
from graph.workflow import WorkflowError, build_workflow, investigate_alert
from models.schemas import (
    ApprovalStatus,
    IncidentCategory,
    IncidentReport,
    RiskLevel,
)
from utils.data_loader import (
    load_alerts,
    load_logs,
    load_threat_intel,
    read_csv_strings,
    validate_logs,
)
from utils.llm import get_llm_client


# ---------------------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------------------

st.set_page_config(
    page_title="Sentinel SOC | Cyber Incident Investigator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PAGES = [
    "Dashboard",
    "Alert Management",
    "Investigation",
    "Security Logs",
    "Incident Reports",
    "Human Approval",
]

LEVEL_COLORS = {
    "Low": "#16a34a",
    "Medium": "#eab308",
    "High": "#f97316",
    "Critical": "#ef4444",
}


# ---------------------------------------------------------------------
# PROFESSIONAL DARK SOC THEME
# ---------------------------------------------------------------------

st.markdown(
    """
    <style>

    /* Main background */
    .stApp {
        background: linear-gradient(
            135deg,
            #07111f 0%,
            #0b1728 55%,
            #101e32 100%
        );
        color: #e5edf7;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #081321;
        border-right: 1px solid #1e344d;
    }

    section[data-testid="stSidebar"] * {
        color: #dce8f5;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(
            145deg,
            #12243a,
            #0d1b2d
        );
        border: 1px solid #24415e;
        border-radius: 14px;
        padding: 18px;
        box-shadow: 0 5px 18px rgba(0,0,0,0.18);
    }

    div[data-testid="stMetricLabel"] {
        color: #9bb4cc;
    }

    div[data-testid="stMetricValue"] {
        color: #39c6f4;
        font-weight: 700;
    }

    /* Headings */
    h1, h2, h3 {
        color: #f1f7ff !important;
        font-weight: 700 !important;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(
            90deg,
            #0877c9,
            #05a6cf
        );
        color: white;
        border: 1px solid #28b8e8;
        border-radius: 9px;
        padding: 0.55rem 1.1rem;
        font-weight: 600;
        transition: 0.2s ease;
    }

    .stButton > button:hover {
        background: #079bd5;
        border-color: #65d9ff;
        color: white;
    }

    /* Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid #263e58;
        border-radius: 10px;
        overflow: hidden;
    }

    /* Tabs */
    button[data-baseweb="tab"] {
        color: #a9bfd5;
        font-weight: 600;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: #39c6f4;
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 999px;
        color: white;
        font-weight: 600;
        font-size: 0.82rem;
    }

    /* Simulation banner */
    .sim-banner {
        border-left: 5px solid #20a8ed;
        padding: 12px 16px;
        border-radius: 8px;
        background: #122b43;
        color: #bce8ff;
        margin-bottom: 1rem;
    }

    /* Section label */
    .section-label {
        color: #39c6f4;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 2px;
        margin-bottom: 5px;
    }

    /* Sidebar brand */
    .brand-box {
        background: #10243a;
        border: 1px solid #24415e;
        border-radius: 12px;
        padding: 15px;
        margin-bottom: 18px;
    }

    .brand-title {
        color: #39c6f4;
        font-size: 20px;
        font-weight: 800;
        letter-spacing: 2px;
    }

    .brand-subtitle {
        color: #9bb4cc;
        font-size: 11px;
        letter-spacing: 1px;
    }

    /* Responsive */
    @media (max-width: 800px) {
        .block-container {
            padding: 1rem 0.6rem;
        }
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------------------

def init_state() -> None:
    """Load sample datasets once per browser session."""

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
    st.session_state.page = "Dashboard"
    st.session_state.run_pending = None

    ids = list(st.session_state.alerts_df.get("alert_id", []))

    st.session_state.inv_alert = ids[0] if ids else None
    st.session_state.initialised = True


# ---------------------------------------------------------------------
# LLM CLIENT
# ---------------------------------------------------------------------

def get_llm():
    """Return the LLM client for the current sidebar setting."""

    enabled = st.session_state.get("use_llm", True)
    cached = st.session_state.get("_llm")

    if cached is None or cached.enabled != enabled:
        cached = get_llm_client(enabled=enabled)
        st.session_state["_llm"] = cached

    return cached


# ---------------------------------------------------------------------
# REUSABLE HELPERS
# ---------------------------------------------------------------------

def badge(text: str, level: str) -> str:
    color = LEVEL_COLORS.get(level, "#546e7a")

    return (
        f'<span class="badge" '
        f'style="background:{color}">{text}</span>'
    )


def run_investigation(alert_id: str) -> IncidentReport | None:
    """Investigate one alert and store its report."""

    alerts = st.session_state.alerts_df

    row = alerts[alerts["alert_id"] == alert_id]

    if row.empty:
        st.error(f"Alert {alert_id} was not found.")
        return None

    try:
        with st.spinner(f"AI agents are investigating {alert_id}..."):

            report = investigate_alert(
                row.iloc[0].to_dict(),
                alerts,
                st.session_state.logs_df,
                st.session_state.ti_df,
                get_llm(),
            )

    except WorkflowError as exc:
        st.error(str(exc))
        return None

    st.session_state.reports[alert_id] = report

    return report


def run_all_investigations() -> None:
    """Investigate all loaded alerts."""

    alerts = st.session_state.alerts_df

    if alerts.empty:
        st.warning("No alerts available.")
        return

    llm = get_llm()
    graph = build_workflow(llm)

    progress = st.progress(0.0, text="Starting investigations...")

    failures = 0
    total = len(alerts)

    for i, (_, row) in enumerate(alerts.iterrows(), start=1):

        raw = row.to_dict()

        try:
            report = investigate_alert(
                raw,
                alerts,
                st.session_state.logs_df,
                st.session_state.ti_df,
                llm,
                compiled_graph=graph,
            )

            st.session_state.reports[raw["alert_id"]] = report

        except WorkflowError:
            failures += 1

        progress.progress(
            i / total,
            text=f"Investigated {i} of {total} alerts",
        )

    progress.empty()

    if failures:
        st.warning(f"{failures} alert(s) could not be investigated.")
    else:
        st.success(f"Successfully investigated {total} alerts.")


def go_to_investigation(alert_id: str) -> None:
    """Navigate to investigation page."""

    st.session_state.inv_alert = alert_id
    st.session_state.run_pending = alert_id
    st.session_state.page = "Investigation"


# ---------------------------------------------------------------------
# REPORT RENDERER
# ---------------------------------------------------------------------

def render_report(report: IncidentReport) -> None:
    """Display findings from all investigation agents."""

    risk = report.risk

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Risk Score",
        f"{risk.score}/100" if risk else "N/A",
    )

    c2.metric(
        "Risk Level",
        risk.level.value if risk else "N/A",
    )

    c3.metric(
        "Classification",
        report.final_classification.value,
    )

    c4.metric(
        "Human Approval",
        report.approval_status.value.replace("_", " ").title(),
    )

    if risk:
        st.progress(
            risk.score / 100,
            text=f"Risk Score: {risk.score}/100",
        )

    st.info(report.executive_summary)

    st.caption(
        f"Analysis mode: {report.analysis_mode} | "
        f"Verdict: {report.verdict.value}"
    )

    tabs = st.tabs([
        "Alert Triage",
        "Log Analysis",
        "Threat Intelligence",
        "Investigation",
        "Risk Score",
        "Response",
        "Agent Trace",
    ])

    # Alert Triage
    with tabs[0]:

        triage = report.triage

        if triage:

            st.write(f"**Category:** {triage.category.value}")
            st.write(
                f"**Initial Severity:** "
                f"{triage.initial_severity.value}"
            )

            st.write(
                "**Duplicate:** "
                + (
                    f"Yes, of {triage.duplicate_of}"
                    if triage.is_duplicate
                    else "No"
                )
            )

            st.write(
                "**False Positive:** "
                + (
                    f"Yes - {triage.false_positive_reason}"
                    if triage.is_false_positive
                    else "No"
                )
            )

            st.write(
                "**Linked Alerts:** "
                + (", ".join(triage.related_alert_ids) or "None")
            )

            for note in triage.notes:
                st.caption(note)

        else:
            st.warning(
                "Triage did not run: "
                + "; ".join(report.limitations)
            )

    # Log Analysis
    with tabs[1]:

        log_analysis = report.log_analysis

        if log_analysis:

            st.write(log_analysis.summary)

            for finding in log_analysis.findings:

                label = (
                    f"[{finding.severity.value}] "
                    f"{finding.finding_type}"
                )

                if not finding.suspicious:
                    label += " (Informational)"

                with st.expander(
                    f"{label} - {finding.event_count} event(s)"
                ):

                    st.write(finding.description)

                    for evidence in finding.evidence:
                        st.code(evidence, language="text")

            indicators = log_analysis.indicators

            rows = [
                {"Indicator": value, "Type": kind}
                for kind, values in [
                    ("IP", indicators.ips),
                    ("Domain", indicators.domains),
                    ("File Hash", indicators.hashes),
                ]
                for value in values
            ]

            if rows:
                st.markdown("**Extracted Indicators**")

                st.dataframe(
                    pd.DataFrame(rows),
                    hide_index=True,
                    width="stretch",
                )

        else:
            st.info("Log analysis was not performed.")

    # Threat Intelligence
    with tabs[2]:

        threat_intel = report.threat_intel

        if threat_intel:

            st.write(threat_intel.summary)

            for match in threat_intel.verified_matches:
                st.error(f"VERIFIED: {match.explanation}")

            for match in threat_intel.unverified_matches:
                st.warning(f"UNVERIFIED: {match.explanation}")

            if threat_intel.unmatched_indicators:
                st.caption(
                    "No record in local dataset: "
                    + ", ".join(
                        x[:32]
                        for x in threat_intel.unmatched_indicators
                    )
                )

        else:
            st.info("Threat intelligence checks were not performed.")

    # Investigation
    with tabs[3]:

        investigation = report.investigation

        if investigation:

            st.write(
                f"**Classification:** "
                f"{investigation.classification.value}"
            )

            st.write(
                f"**Verdict:** {investigation.verdict.value}"
            )

            st.write(
                f"**Confidence:** {investigation.confidence}"
            )

            st.write(
                f"**Attack Pattern:** "
                f"{investigation.attack_pattern}"
            )

            st.write(investigation.narrative)

            if investigation.evidence:

                st.dataframe(
                    pd.DataFrame([
                        item.model_dump()
                        for item in investigation.evidence
                    ]),
                    hide_index=True,
                    width="stretch",
                )

        for item in report.limitations:
            st.caption(f"Limitation: {item}")

    # Risk Score
    with tabs[4]:

        if risk:

            st.dataframe(
                pd.DataFrame([
                    item.model_dump()
                    for item in risk.components
                ]),
                hide_index=True,
                width="stretch",
            )

            for adjustment in risk.adjustments:
                st.warning(adjustment)

            st.write(risk.explanation)

        else:
            st.info("No risk score was calculated.")

    # Response
    with tabs[5]:

        st.markdown(
            '<div class="sim-banner">'
            'SIMULATION ONLY - Nothing is executed automatically. '
            'Every action requires human approval.'
            '</div>',
            unsafe_allow_html=True,
        )

        if report.response:

            actions = pd.DataFrame([
                item.model_dump()
                for item in report.response.actions
            ])

            st.dataframe(
                actions[
                    [
                        "priority",
                        "title",
                        "action_type",
                        "requires_human_approval",
                        "description",
                    ]
                ],
                hide_index=True,
                width="stretch",
            )

            if report.response.escalation_reason:
                st.warning(report.response.escalation_reason)

    # Agent Trace
    with tabs[6]:

        for i, step in enumerate(report.agent_trace, start=1):
            st.write(f"{i}. {step}")


# ---------------------------------------------------------------------
# PAGE 1: DASHBOARD
# ---------------------------------------------------------------------

def page_dashboard() -> None:

    st.markdown(
        '<div class="section-label">'
        'SECURITY OPERATIONS CENTER / OVERVIEW'
        '</div>',
        unsafe_allow_html=True,
    )

    st.title("Security Operations Dashboard")

    st.markdown(
        '<div class="sim-banner">'
        '<b>DEMO ENVIRONMENT</b> | Synthetic security data only | '
        'Response actions are simulated and never executed.'
        '</div>',
        unsafe_allow_html=True,
    )

    alerts = st.session_state.alerts_df
    reports = st.session_state.reports

    fp = sum(
        r.final_classification == IncidentCategory.FALSE_POSITIVE
        for r in reports.values()
    )

    high = sum(
        bool(r.risk and r.risk.level == RiskLevel.HIGH)
        for r in reports.values()
    )

    critical = sum(
        bool(r.risk and r.risk.level == RiskLevel.CRITICAL)
        for r in reports.values()
    )

    st.subheader("Security Overview")

    cols = st.columns(5)

    cols[0].metric("Total Alerts", len(alerts))
    cols[1].metric("Investigated", len(reports))
    cols[2].metric("False Positives", fp)
    cols[3].metric("High Risk", high)
    cols[4].metric("Critical", critical)

    st.divider()

    left, right = st.columns(2)

    with left:

        st.subheader("Alert Severity Distribution")

        if not alerts.empty:

            order = ["Low", "Medium", "High", "Critical"]

            counts = (
                alerts["severity"]
                .value_counts()
                .reindex(order)
                .fillna(0)
            )

            st.bar_chart(counts, color="#19a7e0")

        else:
            st.info("No alerts available.")

    with right:

        st.subheader("Investigation Classification")

        if reports:

            classification_counts = pd.Series(
                [
                    r.final_classification.value
                    for r in reports.values()
                ]
            ).value_counts()

            st.bar_chart(
                classification_counts,
                color="#16c6b5",
            )

        else:
            st.info("No investigations completed yet.")

    st.divider()

    st.subheader("Investigation Center")

    st.write(
        "Run the investigation workflow to analyze available "
        "security alerts using the investigation agents."
    )

    if st.button(
        "▶ INVESTIGATE ALL ALERTS",
        type="primary",
        disabled=alerts.empty,
        use_container_width=True,
    ):

        run_all_investigations()
        st.rerun()

    st.divider()

    st.subheader("Recent Security Incidents")

    if reports:

        rows = [
            {
                "Alert ID": alert_id,
                "Alert Type": report.alert.get("alert_type"),
                "Classification": report.final_classification.value,
                "Risk Score": (
                    report.risk.score if report.risk else None
                ),
                "Risk Level": (
                    report.risk.level.value
                    if report.risk else "N/A"
                ),
                "Approval": report.approval_status.value,
            }
            for alert_id, report in reports.items()
        ]

        table = pd.DataFrame(rows).sort_values(
            "Risk Score",
            ascending=False,
            na_position="last",
        )

        st.dataframe(
            table,
            hide_index=True,
            width="stretch",
        )

    else:
        st.info(
            "No incidents investigated yet. "
            "Start an investigation to see results here."
        )


# ---------------------------------------------------------------------
# PAGE 2: ALERT MANAGEMENT
# ---------------------------------------------------------------------

def page_alerts() -> None:

    st.title("Alert Management")

    st.caption(
        "Search, filter and investigate available security alerts."
    )

    alerts = st.session_state.alerts_df

    if alerts.empty:
        st.warning("No alerts are loaded.")
        return

    view = alerts.copy()

    view["category"] = [
        categorize_alert(alert_type, description).value
        for alert_type, description in zip(
            view["alert_type"],
            view["description"],
        )
    ]

    c1, c2, c3 = st.columns([2, 1, 1])

    query = c1.text_input("Search Alerts", key="alert_search")

    severities = c2.multiselect(
        "Severity",
        ["Low", "Medium", "High", "Critical"],
    )

    categories = c3.multiselect(
        "Category",
        sorted(view["category"].unique()),
    )

    if query:

        mask = view.astype(str).apply(
            lambda col: col.str.contains(
                query,
                case=False,
                regex=False,
            )
        ).any(axis=1)

        view = view[mask]

    if severities:
        view = view[view["severity"].isin(severities)]

    if categories:
        view = view[view["category"].isin(categories)]

    st.caption(
        f"Showing {len(view)} of {len(alerts)} alerts"
    )

    display_columns = [
        "alert_id",
        "timestamp",
        "severity",
        "category",
        "alert_type",
        "source_ip",
        "username",
        "hostname",
        "description",
    ]

    st.dataframe(
        view[display_columns],
        hide_index=True,
        width="stretch",
    )

    if view.empty:
        return

    st.divider()
    st.subheader("Investigate Selected Alert")

    choice = st.selectbox(
        "Select Alert",
        list(view["alert_id"]),
        key="alert_page_select",
    )

    row = view[view["alert_id"] == choice].iloc[0]

    st.write(
        f"**{row['alert_type']}** | "
        f"**Severity:** {row['severity']}"
    )

    st.write(row["description"])

    st.button(
        "Investigate This Alert",
        type="primary",
        on_click=go_to_investigation,
        args=(choice,),
    )

    if choice in st.session_state.reports:
        st.caption(
            "This alert has already been investigated. "
            "You can run it again to refresh the report."
        )


# ---------------------------------------------------------------------
# PAGE 3: INVESTIGATION
# ---------------------------------------------------------------------

def page_investigation() -> None:

    st.title("Incident Investigation")

    st.caption(
        "AI-assisted security incident analysis and investigation."
    )

    alerts = st.session_state.alerts_df

    if alerts.empty:
        st.warning("No alerts are loaded.")
        return

    ids = list(alerts["alert_id"])

    if st.session_state.get("inv_alert") not in ids:
        st.session_state.inv_alert = ids[0]

    alert_id = st.selectbox(
        "Select Alert to Investigate",
        ids,
        key="inv_alert",
    )

    pending = st.session_state.run_pending

    if pending:

        st.session_state.run_pending = None
        run_investigation(pending)

    elif st.button(
        "▶ RUN INVESTIGATION",
        type="primary",
    ):

        run_investigation(alert_id)

    report = st.session_state.reports.get(alert_id)

    if report is None:

        st.info(
            "Select an alert and click Run Investigation "
            "to generate the analysis."
        )

        return

    st.divider()

    st.subheader(
        f"{alert_id} - {report.alert.get('alert_type')}"
    )

    render_report(report)


# ---------------------------------------------------------------------
# PAGE 4: SECURITY LOGS
# ---------------------------------------------------------------------

def page_logs() -> None:

    st.title("Security Logs")

    st.caption(
        f"Current log source: {st.session_state.logs_source}"
    )

    with st.expander(
        "Upload CSV Log File",
        expanded=False,
    ):

        st.write(
            "Required columns: timestamp, event_type, source_ip. "
            "Optional columns include status, username, destination_ip, "
            "hostname, country, destination_port, bytes_out, resource, "
            "domain and file_hash."
        )

        uploaded = st.file_uploader(
            "Choose CSV File",
            type="csv",
            key="log_upload",
        )

        if uploaded is not None:

            try:
                raw = read_csv_strings(uploaded)

            except Exception as exc:

                st.error(
                    f"Could not read CSV: {type(exc).__name__}"
                )

                raw = None

            if raw is not None:

                cleaned, validation = validate_logs(raw)

                for error in validation.errors:
                    st.error(error)

                for warning in validation.warnings:
                    st.warning(warning)

                if validation.valid:

                    st.success(
                        f"Validation passed: "
                        f"{validation.rows_kept} of "
                        f"{validation.rows_in} rows are usable."
                    )

                    st.dataframe(
                        cleaned.head(20),
                        hide_index=True,
                        width="stretch",
                    )

                    if st.button(
                        "Use These Logs for Investigations"
                    ):

                        st.session_state.logs_df = cleaned

                        st.session_state.logs_source = (
                            f"Uploaded: {uploaded.name}"
                        )

                        st.session_state.reports = {}

                        st.rerun()

        if (
            st.session_state.logs_source != "Sample data"
            and st.button("Reset to Sample Logs")
        ):

            st.session_state.logs_df = load_logs()
            st.session_state.logs_source = "Sample data"
            st.session_state.reports = {}

            st.rerun()

    logs = st.session_state.logs_df

    if logs.empty:
        st.warning("No logs are loaded.")
        return

    st.divider()

    c1, c2, c3 = st.columns([2, 1, 1])

    query = c1.text_input("Search Logs")

    events = c2.multiselect(
        "Event Type",
        sorted(logs["event_type"].unique()),
    )

    statuses = c3.multiselect(
        "Status",
        sorted(logs["status"].unique()),
    )

    view = logs

    if query:

        mask = view.astype(str).apply(
            lambda col: col.str.contains(
                query,
                case=False,
                regex=False,
            )
        ).any(axis=1)

        view = view[mask]

    if events:
        view = view[view["event_type"].isin(events)]

    if statuses:
        view = view[view["status"].isin(statuses)]

    st.caption(
        f"Showing {len(view)} of {len(logs)} log entries"
    )

    st.dataframe(
        view,
        hide_index=True,
        width="stretch",
    )


# ---------------------------------------------------------------------
# PAGE 5: INCIDENT REPORTS
# ---------------------------------------------------------------------

def page_reports() -> None:

    st.title("Incident Reports")

    st.caption(
        "Review and download generated incident investigation reports."
    )

    reports = st.session_state.reports

    if not reports:

        st.info(
            "No reports available. Investigate an alert first."
        )

        return

    alert_id = st.selectbox(
        "Select Report",
        list(reports),
        key="report_select",
    )

    report = reports[alert_id]

    st.divider()

    c1, c2 = st.columns(2)

    c1.download_button(
        "Download JSON Report",
        report_to_json(report),
        file_name=f"{report.report_id}.json",
        mime="application/json",
        width="stretch",
    )

    c2.download_button(
        "Download TXT Report",
        render_text_report(report),
        file_name=f"{report.report_id}.txt",
        mime="text/plain",
        width="stretch",
    )

    st.divider()

    st.subheader("Recommended Defensive Actions")

    st.caption(
        "SIMULATION ONLY - These actions are recommendations, "
        "not executed security operations."
    )

    if report.response:

        actions = pd.DataFrame([
            action.model_dump()
            for action in report.response.actions
        ])

        st.dataframe(
            actions[
                [
                    "priority",
                    "title",
                    "action_type",
                    "requires_human_approval",
                    "description",
                ]
            ],
            hide_index=True,
            width="stretch",
        )

    with st.expander(
        "View Full Report",
        expanded=True,
    ):

        st.code(
            render_text_report(report),
            language="text",
            wrap_lines=True,
        )


# ---------------------------------------------------------------------
# PAGE 6: HUMAN APPROVAL
# ---------------------------------------------------------------------

def page_approval() -> None:

    st.title("Human Approval Center")

    st.markdown(
        '<div class="sim-banner">'
        '<b>SIMULATION:</b> Approve / Reject only records a decision '
        'in this demonstration. No real security action is executed.'
        '</div>',
        unsafe_allow_html=True,
    )

    reports = st.session_state.reports

    pending = {
        key: report
        for key, report in reports.items()
        if report.approval_status == ApprovalStatus.PENDING
    }

    decided = {
        key: report
        for key, report in reports.items()
        if report.approval_status in (
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
        )
    }

    if not reports:

        st.info(
            "Investigate alerts first. Incidents requiring review "
            "will appear here."
        )

        return

    st.subheader(
        f"Awaiting Review ({len(pending)})"
    )

    if not pending:
        st.success("No incidents are waiting for review.")

    for alert_id, report in pending.items():

        level = (
            report.risk.level.value
            if report.risk else "N/A"
        )

        score = (
            report.risk.score
            if report.risk else "-"
        )

        with st.expander(
            f"{alert_id} - "
            f"{report.final_classification.value} - "
            f"{level} ({score}/100)"
        ):

            st.markdown(
                badge(level, level),
                unsafe_allow_html=True,
            )

            st.write(report.executive_summary)

            if report.response:

                st.markdown("**Recommended Actions**")

                for action in report.response.actions:

                    st.write(
                        f"- **{action.title}** "
                        f"({action.priority}): "
                        f"{action.description}"
                    )

            note = st.text_input(
                "Reviewer Note (Optional)",
                key=f"note_{alert_id}",
            )

            a, b = st.columns(2)

            if a.button(
                "Approve (Simulated)",
                key=f"approve_{alert_id}",
                width="stretch",
            ):

                st.session_state.reports[alert_id] = (
                    apply_human_decision(
                        report,
                        "approve",
                        note,
                    )
                )

                st.rerun()

            if b.button(
                "Reject (Simulated)",
                key=f"reject_{alert_id}",
                width="stretch",
            ):

                st.session_state.reports[alert_id] = (
                    apply_human_decision(
                        report,
                        "reject",
                        note,
                    )
                )

                st.rerun()

    if decided:

        st.divider()

        st.subheader("Recorded Decisions")

        decision_rows = [
            {
                "Alert": key,
                "Decision": report.approval_status.value,
                "Log": (
                    report.approval_log[-1]
                    if report.approval_log else ""
                ),
            }
            for key, report in decided.items()
        ]

        st.dataframe(
            pd.DataFrame(decision_rows),
            hide_index=True,
            width="stretch",
        )


# ---------------------------------------------------------------------
# MAIN APPLICATION
# ---------------------------------------------------------------------

def main() -> None:

    init_state()

    # Sidebar
    with st.sidebar:

        st.markdown(
            """
            <div class="brand-box">
                <div class="brand-title">SENTINEL SOC</div>
                <div class="brand-subtitle">
                    INCIDENT INVESTIGATION PLATFORM
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.caption("NAVIGATION")

        st.radio(
            "Select Page",
            PAGES,
            key="page",
            label_visibility="collapsed",
        )

        st.divider()

        st.markdown("### AI Configuration")

        st.checkbox(
            "Use Groq LLM when configured",
            value=True,
            key="use_llm",
            help=(
                "Without a valid GROQ_API_KEY, "
                "the application uses rule-based DEMO mode."
            ),
        )

        try:

            st.caption(
                f"Analysis Mode: **{get_llm().mode_label}**"
            )

        except Exception as exc:

            st.warning(
                f"LLM configuration unavailable: {type(exc).__name__}"
            )

        st.divider()

        st.markdown("### Environment")

        st.caption("Environment: DEMONSTRATION")
        st.caption("Data Source: Synthetic Dataset")
        st.caption("Response Mode: Simulated")

        st.divider()

        st.caption("SENTINEL SOC")
        st.caption("Cybersecurity Investigation System")

    # Data error
    if st.session_state.data_error:

        st.error(
            "Could not load sample data: "
            + st.session_state.data_error
        )

    # Page routing
    pages = {
        "Dashboard": page_dashboard,
        "Alert Management": page_alerts,
        "Investigation": page_investigation,
        "Security Logs": page_logs,
        "Incident Reports": page_reports,
        "Human Approval": page_approval,
    }

    selected_page = st.session_state.page

    pages[selected_page]()


# ---------------------------------------------------------------------
# APPLICATION ENTRY POINT
# ---------------------------------------------------------------------

if __name__ == "__main__":
    main()
