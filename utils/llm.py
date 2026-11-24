"""Groq LLM integration with a safe DEMO-mode fallback.

* The API key and model come from environment variables (``.env`` is loaded with
  python-dotenv). Nothing is hardcoded.
* Every LLM answer is requested as JSON and validated with a Pydantic schema.
* Any failure (no key, network error, timeout, bad JSON, schema mismatch) is
  returned as a failed ``LLMResult`` so callers can use their rule-based fallback.
  The LLM never invents results: when it fails, nothing is substituted.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional, Type, TypeVar

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Used only when GROQ_API_KEY is set but GROQ_MODEL is missing or still a placeholder.
# Check https://console.groq.com/docs/models for currently supported model IDs.
DEFAULT_MODEL = "llama-3.3-70b-versatile"
DEFAULT_TIMEOUT_SECONDS = 20.0
_PLACEHOLDER_KEYS = {"", "your_groq_api_key", "changeme", "none"}
_PLACEHOLDER_MODELS = {"", "your_supported_groq_model", "changeme", "none"}


@dataclass
class LLMResult:
    """Outcome of one LLM call."""

    ok: bool
    data: Optional[BaseModel] = None
    error: str = ""

    @property
    def status(self) -> str:
        """Short status string stored in the investigation result."""
        return "used" if self.ok else f"failed: {self.error}"


class LLMClient:
    """Thin wrapper around the Groq SDK that returns validated Pydantic objects."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: Any = None,
        enabled: bool = True,
    ) -> None:
        load_dotenv()
        key = (api_key if api_key is not None else os.getenv("GROQ_API_KEY", "")).strip()
        mdl = (model if model is not None else os.getenv("GROQ_MODEL", "")).strip()
        self.api_key = "" if key.lower() in _PLACEHOLDER_KEYS else key
        self.model = DEFAULT_MODEL if mdl.lower() in _PLACEHOLDER_MODELS else mdl
        self.timeout = timeout
        self.enabled = enabled
        self._client = client
        self._init_error = ""
        if self._client is None and self.api_key and self.enabled:
            self._client = self._build_groq_client()

    def _build_groq_client(self) -> Any:
        """Create the Groq SDK client lazily; failures put us in DEMO mode."""
        try:
            from groq import Groq  # imported here so DEMO mode never needs the SDK

            return Groq(api_key=self.api_key, timeout=self.timeout, max_retries=1)
        except Exception as exc:  # pragma: no cover - depends on local install
            self._init_error = f"Groq SDK unavailable: {exc}"
            logger.warning(self._init_error)
            return None

    @property
    def is_available(self) -> bool:
        """True when an LLM call can be attempted (otherwise DEMO mode)."""
        return bool(self.enabled and self._client is not None)

    @property
    def mode_label(self) -> str:
        """Human-readable mode for the UI and reports."""
        return f"LLM enabled ({self.model})" if self.is_available else "DEMO mode (rule-based)"

    def generate_structured(
        self, system_prompt: str, payload: dict[str, Any], schema: Type[T]
    ) -> LLMResult:
        """Ask the model for JSON matching ``schema`` and validate it.

        Never raises. Returns ``LLMResult(ok=False, error=...)`` on any problem.
        """
        if not self.is_available:
            reason = self._init_error or "LLM not configured (DEMO mode)"
            return LLMResult(ok=False, error=reason)

        schema_hint = json.dumps(schema.model_json_schema())
        system = (
            f"{system_prompt}\n\nRespond with ONE JSON object only (no markdown, no prose) "
            f"that matches this JSON schema:\n{schema_hint}"
        )
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(payload, default=str)},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                timeout=self.timeout,
            )
            content = response.choices[0].message.content
        except Exception as exc:  # network error, timeout, auth error, rate limit...
            logger.warning("LLM request failed: %s", exc)
            return LLMResult(ok=False, error=f"API error ({type(exc).__name__})")

        try:
            parsed = schema.model_validate(json.loads(content))
        except (json.JSONDecodeError, TypeError):
            return LLMResult(ok=False, error="response was not valid JSON")
        except ValidationError as exc:
            return LLMResult(ok=False, error=f"response failed schema validation ({exc.error_count()} issues)")
        return LLMResult(ok=True, data=parsed)


def get_llm_client(enabled: bool = True) -> LLMClient:
    """Build an LLMClient from environment variables."""
    return LLMClient(enabled=enabled)
