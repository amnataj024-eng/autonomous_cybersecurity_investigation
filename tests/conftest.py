"""Shared fixtures: real synthetic datasets, a fake Groq client and helpers."""

import json
from types import SimpleNamespace

import pytest

from utils.data_loader import load_alerts, load_logs, load_threat_intel
from utils.llm import LLMClient


@pytest.fixture(scope="session")
def alerts_df():
    return load_alerts()


@pytest.fixture(scope="session")
def logs_df():
    return load_logs()


@pytest.fixture(scope="session")
def ti_df():
    return load_threat_intel()


@pytest.fixture
def raw_alert(alerts_df):
    """Return a function that gives the raw dict for an alert id."""
    def _get(alert_id):
        return alerts_df[alerts_df["alert_id"] == alert_id].iloc[0].to_dict()
    return _get


class FakeGroq:
    """Minimal stand-in for the Groq SDK client (no network)."""

    def __init__(self, content=None, error=None):
        self.content, self.error, self.calls = content, error, 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        text = self.content if isinstance(self.content, str) else json.dumps(self.content)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


@pytest.fixture
def make_llm():
    def _make(content=None, error=None):
        return LLMClient(api_key="test-key", model="test-model", client=FakeGroq(content, error))
    return _make


@pytest.fixture
def demo_llm(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    return LLMClient(api_key="", model="")
