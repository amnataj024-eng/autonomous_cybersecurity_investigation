import json

from models.schemas import LLMSummaryOutput
from utils.llm import DEFAULT_MODEL, LLMClient, get_llm_client

SCHEMA = LLMSummaryOutput
VALID = {"executive_summary": "A sufficiently long and valid summary of the incident."}


def test_demo_mode_without_credentials(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    client = LLMClient(api_key="", model="")
    assert not client.is_available and "DEMO" in client.mode_label
    result = client.generate_structured("sys", {}, SCHEMA)
    assert not result.ok and "DEMO" in result.error


def test_placeholder_values_mean_demo_mode():
    client = LLMClient(api_key="your_groq_api_key", model="your_supported_groq_model")
    assert not client.is_available and client.model == DEFAULT_MODEL


def test_env_variables_are_read(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("GROQ_MODEL", "my-model")
    client = get_llm_client()
    assert client.model == "my-model" and not client.is_available


def test_disabled_client_is_not_available(make_llm):
    client = make_llm(VALID)
    client.enabled = False
    assert not client.is_available


def test_valid_response_is_parsed(make_llm):
    result = make_llm(VALID).generate_structured("sys", {"a": 1}, SCHEMA)
    assert result.ok and result.data.executive_summary.startswith("A sufficiently")


def test_api_error_is_handled(make_llm):
    result = make_llm(error=TimeoutError("slow")).generate_structured("sys", {}, SCHEMA)
    assert not result.ok and "TimeoutError" in result.error


def test_invalid_json_and_schema_are_handled(make_llm):
    assert "not valid JSON" in make_llm("```not json```").generate_structured("s", {}, SCHEMA).error
    assert "schema" in make_llm({"executive_summary": "short"}).generate_structured("s", {}, SCHEMA).error
    assert not make_llm(json.dumps([1, 2])).generate_structured("s", {}, SCHEMA).ok


def test_request_uses_json_mode_and_timeout(make_llm):
    client = make_llm(VALID)
    captured = {}
    original = client._client.chat.completions.create

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    client._client.chat.completions.create = spy
    client.generate_structured("sys", {}, SCHEMA)
    assert captured["response_format"] == {"type": "json_object"} and captured["timeout"] > 0
