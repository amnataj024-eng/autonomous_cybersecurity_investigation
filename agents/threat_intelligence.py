"""Agent 3 - Threat Intelligence Agent.

Compares IPs, domains and file hashes against the LOCAL synthetic threat-intelligence
CSV. No live feeds are queried and nothing is fabricated: an indicator that is not in
the dataset is reported as "no record", which is *not* evidence that it is safe.
"""

from __future__ import annotations

from typing import Any, Optional

import pandas as pd

from graph.state import InvestigationState
from models.schemas import IndicatorMatch, IndicatorSet, ThreatIntelResult


def _indicator_type(kind: str) -> str:
    return {"ips": "ip", "domains": "domain", "hashes": "hash"}[kind]


def match_indicators(indicators: IndicatorSet, ti_df: Optional[pd.DataFrame]) -> ThreatIntelResult:
    """Match indicators against the local dataset and split verified vs unverified."""
    limitations: list[str] = []
    total = len(indicators.ips) + len(indicators.domains) + len(indicators.hashes)
    if total == 0:
        return ThreatIntelResult(
            limitations=["No IP, domain or file-hash indicators were available to check."],
            summary="No indicators to check against threat intelligence.")
    if ti_df is None or ti_df.empty:
        return ThreatIntelResult(
            unmatched_indicators=[*indicators.ips, *indicators.domains, *indicators.hashes],
            limitations=["The threat-intelligence dataset is empty or missing; no matching was possible."],
            summary="Threat-intelligence dataset unavailable.")

    lookup: dict[tuple[str, str], pd.Series] = {}
    for _, row in ti_df.iterrows():
        lookup[(str(row["indicator_type"]).lower(), str(row["indicator"]).strip().lower())] = row

    verified: list[IndicatorMatch] = []
    unverified: list[IndicatorMatch] = []
    unmatched: list[str] = []
    for kind in ("ips", "domains", "hashes"):
        for value in getattr(indicators, kind):
            row = lookup.get((_indicator_type(kind), value.strip().lower()))
            if row is None:
                unmatched.append(value)
                continue
            status = "verified" if str(row["status"]).lower() == "verified" else "unverified"
            explanation = (
                f"{value} is listed in the local dataset as '{row['threat_type']}' "
                f"(confidence: {row['confidence']}, status: {status}). {row['description']}"
            ).strip()
            if status == "unverified":
                explanation += " This record is UNVERIFIED and should be treated as a weak signal."
            match = IndicatorMatch(
                indicator=value, indicator_type=_indicator_type(kind),
                threat_type=str(row["threat_type"]), confidence=str(row["confidence"]),
                status=status, explanation=explanation, source=str(row.get("source", "")))
            (verified if status == "verified" else unverified).append(match)

    if unmatched:
        limitations.append(
            f"{len(unmatched)} indicator(s) have no record in the local dataset. This does not prove "
            "they are safe; the dataset is small and synthetic.")
    summary = (f"{len(verified)} verified match(es), {len(unverified)} unverified match(es), "
               f"{len(unmatched)} indicator(s) with no record.")
    return ThreatIntelResult(verified_matches=verified, unverified_matches=unverified,
                             unmatched_indicators=unmatched, limitations=limitations, summary=summary)


def threat_intel_node(state: InvestigationState) -> dict[str, Any]:
    """Workflow step 4: Threat Intelligence Agent."""
    log_result = state.get("log_analysis")
    indicators = log_result.indicators if log_result else IndicatorSet()
    result = match_indicators(indicators, state.get("threat_intel_df"))
    return {
        "threat_intel": result,
        "limitations": result.limitations,
        "agent_trace": [f"Threat Intelligence: {result.summary}"],
    }
