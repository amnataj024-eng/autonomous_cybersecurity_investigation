"""Agent 6 - Response Recommendation Agent.

Produces SIMULATED defensive recommendations. Nothing is ever executed: every
containment action is flagged ``requires_human_approval`` and ``simulated_only``.
High and Critical risk incidents are escalated for human review.
"""

from __future__ import annotations

from typing import Any, Optional

from graph.state import InvestigationState
from models.schemas import (
    ApprovalStatus,
    IncidentCategory,
    InvestigationResult,
    LogAnalysisResult,
    RecommendedAction,
    ResponsePlan,
    RiskAssessment,
    RiskLevel,
    SecurityAlert,
    ThreatIntelResult,
)

Action = RecommendedAction


def _playbook(category: IncidentCategory, alert: SecurityAlert, logs: Optional[LogAnalysisResult],
              compromised: bool) -> list[RecommendedAction]:
    ip = alert.source_ip or "the source IP"
    user = alert.username if alert.username not in ("", "(multiple)") else "the targeted account(s)"
    host = alert.hostname or "the affected host"

    if category == IncidentCategory.BRUTE_FORCE:
        actions = [
            Action(title="Review authentication logs", action_type="Investigation", priority="High",
                   description=f"Review all login attempts from {ip} and list every account that was targeted."),
            Action(title="Block source IP (simulated)", action_type="Containment", priority="Immediate",
                   requires_human_approval=True,
                   description=f"Add {ip} to the perimeter/VPN deny list after approval by the security team."),
            Action(title="Enable MFA and account lockout", action_type="Hardening", priority="Normal",
                   description="Require MFA for remote access and enforce lockout/rate limiting on the VPN gateway."),
            Action(title="Monitor for repeat attempts", action_type="Monitoring", priority="Normal",
                   description=f"Alert on any further authentication failures from {ip} or its network range."),
        ]
        if compromised:
            actions[1:1] = [
                Action(title="Reset credentials and revoke sessions (simulated)", action_type="Containment",
                       priority="Immediate", requires_human_approval=True,
                       description=f"A login succeeded after repeated failures. Force a password reset for {user}, "
                                   "revoke active sessions and tokens after human approval."),
                Action(title="Check for data access and transfer", action_type="Investigation", priority="Immediate",
                       description=f"Review what {user} accessed after the successful login and any outbound transfers."),
            ]
        return actions
    if category == IncidentCategory.SUSPICIOUS_LOGIN:
        return [
            Action(title="Verify the login with the user", action_type="Investigation", priority="High",
                   description=f"Contact {user} through a trusted channel to confirm whether they signed in."),
            Action(title="Force re-authentication with MFA (simulated)", action_type="Containment", priority="High",
                   requires_human_approval=True,
                   description=f"Revoke active sessions for {user} and require MFA, after approval."),
            Action(title="Review mailbox and account changes", action_type="Investigation", priority="Normal",
                   description="Check for new mailbox rules, forwarding or MFA changes made after the login."),
            Action(title="Add geo-based conditional access", action_type="Hardening", priority="Low",
                   description="Consider conditional-access rules for logins from unfamiliar countries."),
        ]
    if category == IncidentCategory.UNAUTHORIZED_ACCESS:
        return [
            Action(title="Review the account's permissions", action_type="Investigation", priority="High",
                   description=f"Check why {user} attempted to reach restricted resources and what permissions they hold."),
            Action(title="Restrict the account temporarily (simulated)", action_type="Containment", priority="High",
                   requires_human_approval=True,
                   description=f"Suspend access to the restricted resources for {user} pending review, after approval."),
            Action(title="Notify the data owner and manager", action_type="Escalation", priority="Normal",
                   description="Inform the owner of the restricted resources and the user's manager."),
            Action(title="Audit access-control policy", action_type="Hardening", priority="Low",
                   description="Verify least-privilege access for the affected resources."),
        ]
    if category == IncidentCategory.MALWARE:
        return [
            Action(title="Isolate the host (simulated)", action_type="Containment", priority="Immediate",
                   requires_human_approval=True,
                   description=f"Network-isolate {host} through the EDR console after approval."),
            Action(title="Preserve forensic evidence", action_type="Investigation", priority="High",
                   description=f"Collect memory and disk artefacts from {host} before remediation."),
            Action(title="Block hash and domain indicators (simulated)", action_type="Containment", priority="High",
                   requires_human_approval=True,
                   description="Add the matching file hash and domain to endpoint and DNS blocklists after approval."),
            Action(title="Reset credentials used on the host", action_type="Hardening", priority="Normal",
                   description=f"Reset passwords for accounts that signed in on {host}."),
        ]
    if category == IncidentCategory.NETWORK_ANOMALY:
        return [
            Action(title="Analyse network flows", action_type="Investigation", priority="High",
                   description=f"Review flow/firewall logs for {ip} and the destinations involved."),
            Action(title="Block suspicious external addresses (simulated)", action_type="Containment",
                   priority="High", requires_human_approval=True,
                   description="Block the flagged external IPs/domains at the firewall after approval."),
            Action(title="Check for data loss", action_type="Investigation", priority="High",
                   description="Determine whether sensitive data left the network (DLP review)."),
            Action(title="Monitor the affected hosts", action_type="Monitoring", priority="Normal",
                   description="Increase logging on the involved hosts and watch for repeated activity."),
        ]
    if category == IncidentCategory.SUSPICIOUS_ACCOUNT:
        return [
            Action(title="Validate the account change", action_type="Investigation", priority="Immediate",
                   description=f"Confirm with the change owner whether the changes made by {user} were approved."),
            Action(title="Disable the new/changed account (simulated)", action_type="Containment",
                   priority="Immediate", requires_human_approval=True,
                   description="Disable the newly created account and revert privilege changes after approval."),
            Action(title="Audit privileged groups", action_type="Hardening", priority="Normal",
                   description="Review membership of administrative groups for other unauthorised changes."),
            Action(title="Rotate service-account secrets", action_type="Hardening", priority="Normal",
                   description=f"Rotate credentials for {user} if it is a service account."),
        ]
    if category == IncidentCategory.FALSE_POSITIVE:
        return [
            Action(title="Confirm and close as false positive", action_type="Documentation", priority="Low",
                   description="Have an analyst confirm the finding, then close the alert with a note."),
            Action(title="Tune the detection rule", action_type="Hardening", priority="Low",
                   description=f"Review rule '{alert.rule_name or alert.alert_type}' for tuning or a documented allow-list "
                               "entry through the normal change process."),
        ]
    if category == IncidentCategory.NORMAL:
        return [
            Action(title="No action required", action_type="Documentation", priority="Low",
                   description="Logs show routine behaviour. Document the review and close the alert."),
            Action(title="Optionally tune the rule", action_type="Hardening", priority="Low",
                   description="Consider adjusting the rule thresholds to reduce low-value alerts."),
        ]
    return [  # INSUFFICIENT
        Action(title="Collect missing evidence", action_type="Investigation", priority="High",
               description="Identify and connect the log source for this alert, then re-run the investigation."),
        Action(title="Manual analyst review", action_type="Escalation", priority="Normal",
               description="Ask an analyst to verify the alert with the system owner."),
        Action(title="Monitor the entity", action_type="Monitoring", priority="Normal",
               description=f"Watch {ip} / {user} for further alerts while evidence is gathered."),
    ]


def recommend_response(
    alert: SecurityAlert,
    investigation: InvestigationResult,
    risk: RiskAssessment,
    logs: Optional[LogAnalysisResult] = None,
    ti: Optional[ThreatIntelResult] = None,
) -> ResponsePlan:
    """Build the simulated response plan and decide whether to escalate to a human."""
    compromised = bool(logs and logs.metrics.success_after_failures)
    actions = _playbook(investigation.classification, alert, logs, compromised)

    if ti and ti.verified_matches and investigation.classification not in (
            IncidentCategory.FALSE_POSITIVE, IncidentCategory.NORMAL):
        bad = ", ".join(m.indicator for m in ti.verified_matches[:5])
        actions.append(Action(
            title="Add verified indicators to watch-lists (simulated)", action_type="Containment",
            priority="High", requires_human_approval=True,
            description=f"Share verified indicators ({bad}) with detection and blocking tools after approval."))

    escalate = risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    if escalate:
        urgency = "immediately" if risk.level == RiskLevel.CRITICAL else "within the hour"
        reason = (f"Risk is {risk.level.value} ({risk.score}/100). A human analyst must review {urgency} "
                  "and approve any containment.")
        actions.insert(0, Action(
            title="Escalate to the on-call security analyst", action_type="Escalation", priority="Immediate",
            requires_human_approval=True,
            description="Hand the incident to a human for review; no automatic action is taken."))
    else:
        reason = ""
        if risk.level == RiskLevel.MEDIUM:
            actions.append(Action(
                title="Analyst review during business hours", action_type="Escalation", priority="Normal",
                description="Queue for routine analyst review; escalate if new related alerts appear."))
    if investigation.limitations and investigation.classification == IncidentCategory.INSUFFICIENT:
        reason = reason or "Insufficient information: manual review recommended."

    order = {"Immediate": 0, "High": 1, "Normal": 2, "Low": 3}
    actions.sort(key=lambda a: order[a.priority])
    return ResponsePlan(actions=actions, escalate_to_human=escalate, escalation_reason=reason)


# --------------------------------------------------------------------------- #
# LangGraph nodes
# --------------------------------------------------------------------------- #


def response_recommender_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 7: Response Recommendation Agent."""
    plan = recommend_response(state["alert"], state["investigation"], state["risk"],
                              state.get("log_analysis"), state.get("threat_intel"))
    return {"response": plan, "agent_trace": [
        f"Response Recommendation: {len(plan.actions)} simulated action(s), escalate={plan.escalate_to_human}"]}


def human_approval_check_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 8a: decide whether human approval is required."""
    plan = state["response"]
    status = ApprovalStatus.PENDING if plan.escalate_to_human else ApprovalStatus.NOT_REQUIRED
    return {"approval_status": status.value,
            "agent_trace": [f"Human Approval Check: {status.value}"]}


def escalate_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 8b: mark the incident as waiting for a human (nothing is executed)."""
    return {"agent_trace": ["Escalation: incident queued for human review; no automated action taken"]}
