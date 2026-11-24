"""Agent 4 - Incident Investigation Agent.

Combines triage, log and threat-intelligence findings, correlates them, and decides
whether the alert is a genuine incident or a false positive.

* The classification is ALWAYS produced by transparent, evidence-weighted rules.
* The LLM (when configured) only writes the narrative. Its answer is validated with
  Pydantic, must cite real evidence ids, and may not mention IP addresses that are
  absent from the evidence. If anything is wrong the rule-based narrative is used.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Optional

from graph.state import InvestigationState
from models.schemas import (
    EvidenceItem,
    IncidentCategory,
    InvestigationResult,
    LLMInvestigationOutput,
    LogAnalysisResult,
    SecurityAlert,
    Severity,
    ThreatIntelResult,
    TriageResult,
    Verdict,
)
from utils.llm import LLMClient

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Evidence weights per category (documented in the README).
FINDING_WEIGHTS: dict[str, list[tuple[IncidentCategory, float]]] = {
    "BRUTE_FORCE": [(IncidentCategory.BRUTE_FORCE, 5)],
    "SUCCESS_AFTER_FAILURES": [(IncidentCategory.BRUTE_FORCE, 3)],
    "UNUSUAL_LOCATION": [(IncidentCategory.SUSPICIOUS_LOGIN, 3)],
    "IMPOSSIBLE_TRAVEL": [(IncidentCategory.SUSPICIOUS_LOGIN, 5)],
    "OFF_HOURS_LOGIN": [(IncidentCategory.SUSPICIOUS_LOGIN, 1)],
    "UNAUTHORIZED_ACCESS": [(IncidentCategory.UNAUTHORIZED_ACCESS, 5)],
    "PORT_SCAN": [(IncidentCategory.NETWORK_ANOMALY, 4)],
    "LARGE_OUTBOUND_TRANSFER": [(IncidentCategory.NETWORK_ANOMALY, 4)],
    "DNS_BEACONING": [(IncidentCategory.NETWORK_ANOMALY, 3)],
    "REPEATED_DNS": [(IncidentCategory.NETWORK_ANOMALY, 2)],
    "ACCOUNT_CHANGE": [(IncidentCategory.SUSPICIOUS_ACCOUNT, 5)],
}
TRIAGE_HINT_WEIGHT = 3.0
REAL_CATEGORIES = [
    IncidentCategory.BRUTE_FORCE, IncidentCategory.SUSPICIOUS_LOGIN,
    IncidentCategory.UNAUTHORIZED_ACCESS, IncidentCategory.MALWARE,
    IncidentCategory.NETWORK_ANOMALY, IncidentCategory.SUSPICIOUS_ACCOUNT,
]

LLM_SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing an investigation narrative. Use ONLY the evidence "
    "items provided in the user message. Never invent IP addresses, usernames, domains, counts "
    "or events. Cite the evidence ids (e.g. E1, E2) that support your statements in "
    "cited_evidence_ids. suggested_classification must be one of the allowed categories. "
    "Be concise and factual. This is a defensive, simulated academic exercise."
)


def _ti_category_weights(threat_type: str, indicator_type: str) -> list[tuple[IncidentCategory, float]]:
    """Translate a verified threat-intel record into category weights."""
    text = threat_type.lower()
    weights: list[tuple[IncidentCategory, float]] = []
    if indicator_type == "hash":
        weights.append((IncidentCategory.MALWARE, 6))
    if any(k in text for k in ("malware", "trojan", "ransom", "command and control", "dropper")):
        weights.append((IncidentCategory.MALWARE, 6 if "command" in text else 5))
    elif any(k in text for k in ("brute", "credential")):
        weights.append((IncidentCategory.BRUTE_FORCE, 2))
    elif any(k in text for k in ("scanner", "scan")):
        weights.append((IncidentCategory.NETWORK_ANOMALY, 2))
    elif "exfil" in text:
        weights.append((IncidentCategory.NETWORK_ANOMALY, 3))
    elif "phish" in text:
        weights.append((IncidentCategory.SUSPICIOUS_LOGIN, 2))
    return weights


def build_evidence(triage: TriageResult, logs: Optional[LogAnalysisResult],
                   ti: Optional[ThreatIntelResult]) -> list[EvidenceItem]:
    """Create numbered evidence items from the previous agents' outputs."""
    items: list[str | tuple[str, str]] = []
    if triage.related_alert_ids:
        items.append((f"{len(triage.related_alert_ids)} other alert(s) are linked to the same IP/user: "
                      f"{', '.join(triage.related_alert_ids)}.", "Alert Triage"))
    if triage.is_duplicate:
        items.append((f"Alert duplicates {triage.duplicate_of}.", "Alert Triage"))
    if logs:
        for finding in logs.findings:
            if finding.suspicious:
                items.append((f"[{finding.finding_type}] {finding.description}", "Log Analysis"))
    if ti:
        for match in ti.verified_matches:
            items.append((f"VERIFIED threat-intel match: {match.indicator} ({match.indicator_type}) is "
                          f"'{match.threat_type}', confidence {match.confidence}.", "Threat Intelligence"))
        for match in ti.unverified_matches:
            items.append((f"UNVERIFIED threat-intel record (weak signal): {match.indicator} "
                          f"({match.indicator_type}) listed as '{match.threat_type}'.", "Threat Intelligence"))
    return [EvidenceItem(evidence_id=f"E{i}", statement=s, source=src)
            for i, (s, src) in enumerate(items, start=1)]


def score_categories(triage: TriageResult, logs: Optional[LogAnalysisResult],
                     ti: Optional[ThreatIntelResult]) -> dict[IncidentCategory, float]:
    """Add up evidence weights per category."""
    scores: dict[IncidentCategory, float] = defaultdict(float)
    if triage.category in REAL_CATEGORIES:
        scores[triage.category] += TRIAGE_HINT_WEIGHT
    if logs:
        for finding in logs.findings:
            if finding.suspicious:
                for category, weight in FINDING_WEIGHTS.get(finding.finding_type, []):
                    scores[category] += weight
    if ti:
        for match in ti.verified_matches:
            for category, weight in _ti_category_weights(match.threat_type, match.indicator_type):
                scores[category] += weight
    return dict(scores)


def _signal_count(logs: Optional[LogAnalysisResult], ti: Optional[ThreatIntelResult]) -> int:
    suspicious = sum(1 for f in (logs.findings if logs else []) if f.suspicious)
    return suspicious + (len(ti.verified_matches) if ti else 0)


def describe_attack_pattern(logs: Optional[LogAnalysisResult], ti: Optional[ThreatIntelResult]) -> str:
    """Summarise the attack pattern implied by the evidence."""
    types = {f.finding_type for f in (logs.findings if logs else []) if f.suspicious}
    verified = ti.verified_matches if ti else []
    parts: list[str] = []
    if "BRUTE_FORCE" in types:
        parts.append("credential guessing (brute force)")
    if "SUCCESS_AFTER_FAILURES" in types:
        parts.append("successful login after repeated failures (possible account takeover)")
    if "IMPOSSIBLE_TRAVEL" in types:
        parts.append("logins from different countries within a short time (possible credential misuse)")
    elif "UNUSUAL_LOCATION" in types:
        parts.append("login from an unfamiliar country")
    if "OFF_HOURS_LOGIN" in types:
        parts.append("login at an unusual hour")
    if "UNAUTHORIZED_ACCESS" in types:
        parts.append("repeated attempts to reach restricted resources")
    if "PORT_SCAN" in types:
        parts.append("reconnaissance (port scanning)")
    if "LARGE_OUTBOUND_TRANSFER" in types:
        parts.append("possible data exfiltration")
    if "DNS_BEACONING" in types:
        parts.append("beacon-like DNS communication")
    elif "REPEATED_DNS" in types:
        parts.append("repeated DNS queries to one domain")
    if "ACCOUNT_CHANGE" in types:
        parts.append("new account or privilege change (possible persistence)")
    if any(m.indicator_type == "hash" for m in verified):
        parts.append("execution of a file matching a known malicious hash")
    if any("command" in m.threat_type.lower() for m in verified):
        parts.append("contact with a known command-and-control domain")
    if {"SUCCESS_AFTER_FAILURES", "LARGE_OUTBOUND_TRANSFER"} <= types:
        parts.append("overall chain: credential attack -> initial access -> data exfiltration")
    return "; ".join(parts) if parts else "No attack pattern identified from the available evidence."


def _confidence(signals: int) -> str:
    return "High" if signals >= 3 else "Medium" if signals == 2 else "Low"


def _rule_based_narrative(alert: SecurityAlert, result: InvestigationResult) -> str:
    cited = "; ".join(f"{e.evidence_id}: {e.statement}" for e in result.evidence[:6])
    base = (f"Alert {alert.alert_id} ({alert.alert_type}, {alert.severity.value}) was classified as "
            f"'{result.classification.value}' ({result.verdict.value}, confidence {result.confidence}).")
    if cited:
        base += f" Supporting evidence - {cited}"
    elif result.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN):
        base += " The related logs did not corroborate any suspicious behaviour."
    return base


def _llm_enhance(alert: SecurityAlert, result: InvestigationResult, llm: Optional[LLMClient]
                 ) -> InvestigationResult:
    """Optionally replace the narrative with a validated LLM narrative."""
    if llm is None or not llm.is_available:
        result.llm_status = "not_configured"
        return result
    payload = {
        "alert": {"id": alert.alert_id, "type": alert.alert_type, "severity": alert.severity.value,
                  "description": alert.description},
        "rule_based_classification": result.classification.value,
        "allowed_categories": [c.value for c in IncidentCategory],
        "evidence": [e.model_dump() for e in result.evidence],
    }
    outcome = llm.generate_structured(LLM_SYSTEM_PROMPT, payload, LLMInvestigationOutput)
    if not outcome.ok:
        result.llm_status = outcome.status
        return result
    data: LLMInvestigationOutput = outcome.data  # type: ignore[assignment]
    known_ids = {e.evidence_id for e in result.evidence}
    if not known_ids:
        result.llm_status = "failed: no evidence to cite; rule-based narrative used"
        return result
    if not set(data.cited_evidence_ids) <= known_ids:
        result.llm_status = "failed: response cited evidence that does not exist"
        return result
    known_text = " ".join([alert.model_dump_json(), *(e.statement for e in result.evidence)])
    if any(ip not in known_text for ip in IPV4_PATTERN.findall(data.narrative + " " + data.attack_pattern)):
        result.llm_status = "failed: response mentioned an IP address that is not in the evidence"
        return result
    result.narrative = data.narrative
    result.attack_pattern = data.attack_pattern
    result.llm_status = "used"
    result.llm_agrees_with_rules = data.suggested_classification == result.classification
    if not result.llm_agrees_with_rules:
        result.limitations.append(
            f"The LLM suggested '{data.suggested_classification.value}', but the evidence-based rules "
            f"classified this as '{result.classification.value}'; the rule-based result was kept.")
    return result


def investigate(alert: SecurityAlert, triage: TriageResult, logs: Optional[LogAnalysisResult],
                ti: Optional[ThreatIntelResult], llm: Optional[LLMClient] = None) -> InvestigationResult:
    """Correlate all findings and produce an evidence-based investigation result."""
    evidence = build_evidence(triage, logs, ti)
    scores = score_categories(triage, logs, ti)
    limitations: list[str] = []
    if logs:
        limitations += logs.limitations
    if ti:
        limitations += ti.limitations

    signals = _signal_count(logs, ti)
    log_events = logs.metrics.total_related_events if logs else 0
    has_unverified_only = bool(ti and ti.unverified_matches and not ti.verified_matches)
    secondary: list[IncidentCategory] = []

    if signals > 0 and scores:
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        classification = ranked[0][0]
        secondary = [c for c, s in ranked[1:] if s >= 3]
        verdict, confidence = Verdict.GENUINE, _confidence(signals)
        if log_events == 0:
            limitations.append("Classification relies on threat intelligence only; no log evidence was found.")
            confidence = "Low"
    elif log_events == 0:
        classification, verdict, confidence = IncidentCategory.INSUFFICIENT, Verdict.INCONCLUSIVE, "Low"
        limitations.append(
            "Not enough information to confirm or dismiss the alert: no matching logs and no "
            "verified threat-intelligence records. Manual follow-up is required.")
    elif alert.severity == Severity.LOW:
        classification, verdict, confidence = IncidentCategory.NORMAL, Verdict.BENIGN, "Medium"
    else:
        classification, verdict, confidence = IncidentCategory.FALSE_POSITIVE, Verdict.FALSE_POSITIVE, "Medium"
        if has_unverified_only:
            confidence = "Low"
            limitations.append("Only an unverified threat-intelligence record exists; it was not treated as proof.")

    result = InvestigationResult(
        classification=classification, verdict=verdict, confidence=confidence,  # type: ignore[arg-type]
        attack_pattern=describe_attack_pattern(logs, ti), evidence=evidence,
        secondary_categories=secondary, limitations=limitations)
    result.narrative = _rule_based_narrative(alert, result)
    return _llm_enhance(alert, result, llm)


# --------------------------------------------------------------------------- #
# LangGraph nodes
# --------------------------------------------------------------------------- #


def incident_investigator_node(state: InvestigationState, llm: Optional[LLMClient] = None) -> dict[str, Any]:
    """Workflow step 5: Incident Investigation Agent."""
    result = investigate(state["alert"], state["triage"], state.get("log_analysis"),
                         state.get("threat_intel"), llm)
    trace = (f"Incident Investigation: {result.classification.value} -> {result.verdict.value} "
             f"(confidence {result.confidence}, LLM: {result.llm_status.split(':')[0]})")
    return {"investigation": result, "limitations": result.limitations, "agent_trace": [trace]}


def false_positive_fast_track_node(state: InvestigationState) -> dict[str, Any]:
    """Conditional route: triage found an obvious false positive, so classify it directly."""
    triage = state["triage"]
    evidence = [EvidenceItem(evidence_id="E1", statement=triage.false_positive_reason, source="Alert Triage")]
    result = InvestigationResult(
        classification=IncidentCategory.FALSE_POSITIVE, verdict=Verdict.FALSE_POSITIVE, confidence="Medium",
        attack_pattern="None: benign activity matched a false-positive rule.", evidence=evidence,
        narrative=(f"Alert {triage.alert_id} was filtered at triage as a false positive. "
                   f"{triage.false_positive_reason} Deep investigation was skipped."),
        limitations=["Log analysis and threat-intelligence checks were skipped because the alert was "
                     "filtered as an obvious false positive at triage."],
        llm_status="not_used")
    return {"investigation": result, "limitations": result.limitations,
            "agent_trace": ["Incident Investigation: fast-tracked as false positive (investigation skipped)"]}


def invalid_input_node(state: InvestigationState) -> dict[str, Any]:
    """Conditional route: the alert is invalid, so report the limitation instead of inventing results."""
    errors = state.get("errors", [])
    result = InvestigationResult(
        classification=IncidentCategory.INSUFFICIENT, verdict=Verdict.INCONCLUSIVE, confidence="Low",
        attack_pattern="Unknown.", evidence=[],
        narrative="The alert could not be validated, so no investigation was performed. "
                  + ("Problems: " + "; ".join(errors) if errors else ""),
        limitations=["Investigation not possible: invalid or incomplete alert data."],
        llm_status="not_used")
    return {"investigation": result, "agent_trace": ["Incident Investigation: skipped (invalid alert)"]}
