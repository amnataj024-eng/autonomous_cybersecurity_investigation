import pandas as pd

from agents.threat_intelligence import match_indicators
from models.schemas import IndicatorSet


def test_verified_and_unverified_are_separated(ti_df):
    result = match_indicators(IndicatorSet(ips=["203.0.113.45", "198.51.100.23", "192.0.2.7"],
                                           domains=["c2-beacon.example"]), ti_df)
    assert {m.indicator for m in result.verified_matches} == {"203.0.113.45", "c2-beacon.example"}
    assert [m.indicator for m in result.unverified_matches] == ["198.51.100.23"]
    assert result.unmatched_indicators == ["192.0.2.7"]
    assert "UNVERIFIED" in result.unverified_matches[0].explanation


def test_hash_matching_is_case_insensitive(ti_df):
    known = ti_df[ti_df["indicator_type"] == "hash"].iloc[0]["indicator"]
    result = match_indicators(IndicatorSet(hashes=[known.upper()]), ti_df)
    assert len(result.verified_matches) + len(result.unverified_matches) == 1


def test_no_indicators_and_missing_dataset(ti_df):
    assert match_indicators(IndicatorSet(), ti_df).limitations
    missing = match_indicators(IndicatorSet(ips=["203.0.113.45"]), pd.DataFrame())
    assert missing.limitations and not missing.verified_matches


def test_unknown_indicator_is_not_fabricated(ti_df):
    result = match_indicators(IndicatorSet(ips=["198.51.100.250"]), ti_df)
    assert not result.verified_matches and not result.unverified_matches
    assert any("not prove" in x for x in result.limitations)
