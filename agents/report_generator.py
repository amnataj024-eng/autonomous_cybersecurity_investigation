"""Agent 7 - Report Generation Agent.

Builds the final incident report from the shared state, renders it as TXT / JSON and
records (simulated) human approval decisions. The executive summary is written by the
LLM when available and validated; otherwise a deterministic template is used.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from graph.state import InvestigationState
from models.schemas import (
    ApprovalStatus,
    IncidentCategory,
    IncidentReport,
    LLMSummaryOutput,
    Verdict,
)
from utils.llm import LLMClient

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUMMARY_SYSTEM_PROMPT = (
    "You are a SOC analyst writing a short executive summary (3-5 sentences) of a security "
    "incident investigation. Use ONLY the facts in the user message. Do not invent IP addresses, "
    "users, numbers or events. Mention the classification, risk score and that all response "
    "actions are simulated and need human approval."
)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _template_summary(report: IncidentReport) -> str:
    alert = report.alert
    parts = [
        f"Alert {alert.get('alert_id', 'UNKNOWN')} ({alert.get('alert_type', 'unknown type')}, "
        f"{alert.get('severity', 'unknown')} severity) was investigated by the multi-agent system and "
        f"classified as '{report.final_classification.value}' ({report.verdict.value})."
    ]
    if report.risk:
        parts.append(f"The calculated risk score is {report.risk.score}/100 ({report.risk.level.value}).")
    else:
        parts.append("No risk score could be calculated because the alert was not investigated.")
    if report.investigation and report.investigation.attack_pattern:
        parts.append(f"Observed pattern: {report.investigation.attack_pattern.rstrip('.')}.")
    if report.response:
        parts.append(f"{len(report.response.actions)} defensive action(s) are recommended; all are "
                     "simulated and require human approval.")
    if report.approval_status == ApprovalStatus.PENDING:
        parts.append("The incident is escalated and waiting for human review.")
    return " ".join(parts)


def _llm_summary(report: IncidentReport, llm: Optional[LLMClient]) -> tuple[str, str]:
    """Return ``(summary, status)``; falls back to the template on any LLM problem."""
    template = _template_summary(report)
    if llm is None or not llm.is_available:
        return template, "not_configured"
    payload = {
        "alert": report.alert,
        "classification": report.final_classification.value,
        "verdict": report.verdict.value,
        "risk": report.risk.model_dump() if report.risk else None,
        "evidence": [e.statement for e in (report.investigation.evidence if report.investigation else [])][:8],
        "recommended_actions": [a.title for a in (report.response.actions if report.response else [])][:6],
        "approval_status": report.approval_status.value,
        "limitations": report.limitations[:5],
    }
    outcome = llm.generate_structured(SUMMARY_SYSTEM_PROMPT, payload, LLMSummaryOutput)
    if not outcome.ok:
        return template, outcome.status
    text = outcome.data.executive_summary  # type: ignore[union-attr]
    known = str(payload)
    if any(ip not in known for ip in IPV4_PATTERN.findall(text)):
        return template, "failed: summary mentioned an IP address that is not in the evidence"
    return text, "used"


def build_report(state: InvestigationState, llm: Optional[LLMClient] = None) -> IncidentReport:
    """Assemble the final IncidentReport from the shared state."""
    alert = state.get("alert")
    alert_dict: dict[str, Any] = alert.model_dump(mode="json") if alert else dict(state.get("raw_alert") or {})
    investigation = state.get("investigation")
    now = datetime.now(timezone.utc)
    alert_id = str(alert_dict.get("alert_id") or "UNKNOWN")

    limitations = list(state.get("limitations", []))
    if investigation:
        limitations += investigation.limitations
    errors = state.get("errors", [])
    if errors:
        limitations += [f"Input problem: {e}" for e in errors]

    report = IncidentReport(
        report_id=f"RPT-{alert_id}-{now.strftime('%Y%m%d%H%M%S')}",
        generated_at=now.strftime("%Y-%m-%d %H:%M:%SZ"),
        alert=alert_dict,
        final_classification=investigation.classification if investigation else IncidentCategory.INSUFFICIENT,
        verdict=investigation.verdict if investigation else Verdict.INCONCLUSIVE,
        triage=state.get("triage"),
        log_analysis=state.get("log_analysis"),
        threat_intel=state.get("threat_intel"),
        investigation=investigation,
        risk=state.get("risk"),
        response=state.get("response"),
        approval_status=ApprovalStatus(state.get("approval_status", ApprovalStatus.NOT_REQUIRED.value)),
        limitations=_dedupe(limitations),
        agent_trace=list(state.get("agent_trace", [])),
    )

    triage = state.get("triage")
    if triage is not None and triage.is_false_positive:
        summary, summary_status = _template_summary(report), "not_used"  # skip the LLM for trivial cases
    else:
        summary, summary_status = _llm_summary(report, llm)
    report.executive_summary = summary

    statuses = [investigation.llm_status if investigation else "not_used", summary_status]
    if any(s == "used" for s in statuses):
        report.analysis_mode = "LLM-assisted (Groq) with rule-based classification"
    elif any(s.startswith("failed") for s in statuses):
        failure = next(s for s in statuses if s.startswith("failed"))
        report.analysis_mode = "Rule-based fallback (LLM error)"
        report.limitations = _dedupe(report.limitations + [f"LLM unavailable or rejected ({failure}); "
                                                           "deterministic rule-based output was used."])
    else:
        report.analysis_mode = "DEMO (rule-based)"
    return report


# --------------------------------------------------------------------------- #
# Rendering and export
# --------------------------------------------------------------------------- #


def render_text_report(report: IncidentReport) -> str:
    """Render the report as readable plain text."""
    line = "=" * 78
    out: list[str] = [line, "INCIDENT INVESTIGATION REPORT", line,
                      f"Report ID : {report.report_id}", f"Generated : {report.generated_at}",
                      f"Mode      : {report.analysis_mode}", f"NOTICE    : {report.data_notice}",
                      "            All recommended actions are SIMULATED and need human approval.", ""]

    out += ["1. ORIGINAL ALERT", "-" * 78]
    for key in ("alert_id", "timestamp", "alert_type", "severity", "source_ip", "destination_ip",
                "username", "hostname", "domain", "file_hash", "event_count", "rule_name", "description"):
        value = report.alert.get(key)
        if value not in (None, ""):
            out.append(f"  {key:<15}: {value}")
    out.append("")

    out += ["2. EXECUTIVE SUMMARY", "-" * 78, report.executive_summary, ""]

    if report.triage:
        t = report.triage
        out += ["3. ALERT TRIAGE", "-" * 78,
               f"  Category          : {t.category.value}", f"  Initial severity  : {t.initial_severity.value}",
               f"  Duplicate         : {'yes (of ' + str(t.duplicate_of) + ')' if t.is_duplicate else 'no'}",
               f"  False positive    : {'yes - ' + t.false_positive_reason if t.is_false_positive else 'no'}",
               f"  Linked alerts     : {', '.join(t.related_alert_ids) or 'none'}", ""]

    out += ["4. LOG ANALYSIS FINDINGS", "-" * 78]
    if report.log_analysis:
        la = report.log_analysis
        out.append(f"  {la.summary}")
        for f in la.findings:
            tag = "" if f.suspicious else " (informational)"
            out.append(f"  - [{f.severity.value}] {f.finding_type}{tag}: {f.description}")
            for ev in f.evidence[:2]:
                out.append(f"        evidence: {ev}")
        ind = la.indicators
        out.append(f"  Indicators: IPs={ind.ips or '-'} domains={ind.domains or '-'} "
                   f"hashes={[h[:16] + '...' for h in ind.hashes] or '-'}")
    else:
        out.append("  Not performed (see the investigation notes).")
    out.append("")

    out += ["5. THREAT INTELLIGENCE (local synthetic dataset)", "-" * 78]
    if report.threat_intel:
        ti = report.threat_intel
        out.append(f"  {ti.summary}")
        for m in ti.verified_matches:
            out.append(f"  - VERIFIED   : {m.explanation}")
        for m in ti.unverified_matches:
            out.append(f"  - UNVERIFIED : {m.explanation}")
        if ti.unmatched_indicators:
            out.append(f"  - No record  : {', '.join(x[:24] for x in ti.unmatched_indicators)}")
    else:
        out.append("  Not performed.")
    out.append("")

    out += ["6. INVESTIGATION RESULT", "-" * 78]
    if report.investigation:
        inv = report.investigation
        out += [f"  Classification : {inv.classification.value}", f"  Verdict        : {inv.verdict.value}",
                f"  Confidence     : {inv.confidence}", f"  Attack pattern : {inv.attack_pattern}",
                f"  Narrative      : {inv.narrative}", "  Evidence:"]
        out += [f"    {e.evidence_id} ({e.source}): {e.statement}" for e in inv.evidence] or ["    (none)"]
    out.append("")

    out += ["7. RISK ASSESSMENT", "-" * 78]
    if report.risk:
        r = report.risk
        out.append(f"  Score: {r.score}/100   Level: {r.level.value}")
        out += [f"    {c.name:<34} {c.points:>2}/{c.max_points:<2}  {c.explanation}" for c in r.components]
        out += [f"  Adjustment: {a}" for a in r.adjustments]
        out.append(f"  {r.explanation}")
    else:
        out.append("  Not calculated.")
    out.append("")

    out += ["8. RECOMMENDED DEFENSIVE ACTIONS (SIMULATED - NOT EXECUTED)", "-" * 78]
    if report.response:
        for i, a in enumerate(report.response.actions, 1):
            approval = " [needs human approval]" if a.requires_human_approval else ""
            out.append(f"  {i}. [{a.priority}] {a.title} ({a.action_type}){approval}")
            out.append(f"       {a.description}")
        if report.response.escalation_reason:
            out.append(f"  Escalation: {report.response.escalation_reason}")
    else:
        out.append("  None.")
    out += ["", f"9. HUMAN APPROVAL STATUS: {report.approval_status.value}"]
    out += [f"   - {entry}" for entry in report.approval_log]
    out += ["", "10. LIMITATIONS", "-" * 78]
    out += [f"  - {item}" for item in report.limitations] or ["  - None recorded."]
    out += ["", "11. FINAL INCIDENT CLASSIFICATION", "-" * 78,
            f"  {report.final_classification.value} - {report.verdict.value}", "",
            "AGENT TRACE", "-" * 78]
    out += [f"  {i}. {step}" for i, step in enumerate(report.agent_trace, 1)]
    out.append(line)
    return "\n".join(out)


def report_to_json(report: IncidentReport) -> str:
    """Serialise the report as pretty JSON."""
    return report.model_dump_json(indent=2)


def save_report(report: IncidentReport, directory: Path | str) -> tuple[Path, Path]:
    """Write the JSON and TXT versions of a report to ``directory``."""
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", report.report_id)
    json_path, txt_path = folder / f"{safe_id}.json", folder / f"{safe_id}.txt"
    json_path.write_text(report_to_json(report), encoding="utf-8")
    txt_path.write_text(render_text_report(report), encoding="utf-8")
    return json_path, txt_path


def apply_human_decision(report: IncidentReport, decision: str, note: str = "",
                         reviewer: str = "analyst") -> IncidentReport:
    """Record a SIMULATED human decision. No real action is ever executed."""
    decision = decision.strip().lower()
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")
    if report.approval_status == ApprovalStatus.NOT_REQUIRED:
        raise ValueError("This incident does not require human approval.")
    updated = report.model_copy(deep=True)
    updated.approval_status = (ApprovalStatus.APPROVED if decision == "approve" else ApprovalStatus.REJECTED)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    verb = "approved" if decision == "approve" else "rejected"
    updated.approval_log.append(
        f"{stamp} - {reviewer} {verb} the recommended actions (SIMULATED; nothing was executed)."
        + (f" Note: {note}" if note else ""))
    return updated


# --------------------------------------------------------------------------- #
# LangGraph node
# --------------------------------------------------------------------------- #


def report_generator_node(state: InvestigationState, llm: Optional[LLMClient] = None) -> dict[str, Any]:
    """Workflow step 9: Report Generation Agent."""
    report = build_report(state, llm)
    return {"report": report, "agent_trace": ["Report Generation: final report created"]}
