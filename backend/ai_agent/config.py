"""Configuration module for the AuthScope Gemini AI Brain and Agent.

Manages environment variables, execution bounds, model parameters, and secret
redaction for the Google GenAI integration. Never exposes raw API keys to the
frontend or application logs.
"""

from typing import Any, Dict, Optional
import os
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.config import settings


PLACEHOLDER_API_KEYS = {
    "",
    "your_gemini_api_key_here",
    "your_google_api_key_here",
    "placeholder_key",
    "changeme",
    "none",
    "null",
}


def _clean_api_key(raw_key: Optional[str]) -> Optional[str]:
    """Normalizes and filters out placeholder or empty API keys."""
    if not raw_key:
        return None
    cleaned = raw_key.strip()
    if cleaned.lower() in PLACEHOLDER_API_KEYS:
        return None
    return cleaned


class GeminiAgentConfig(BaseModel):
    """Validated configuration for the Gemini AI Brain and bounded agent loop."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    api_key: Optional[str] = Field(
        default=None,
        description="Google Gemini API key (read from GEMINI_API_KEY; never exposed to frontend).",
        repr=False,
    )
    model: str = Field(
        default="gemini-2.5-flash",
        min_length=1,
        description="Configurable Gemini model identifier (GEMINI_MODEL).",
    )
    max_iterations: int = Field(
        default=8,
        ge=1,
        le=50,
        description="Maximum reasoning iterations per assessment loop (AGENT_MAX_ITERATIONS).",
    )
    max_tool_calls: int = Field(
        default=15,
        ge=1,
        le=100,
        description="Maximum total tool executions per assessment loop (AGENT_MAX_TOOL_CALLS).",
    )
    temperature: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="Sampling temperature for deterministic security reasoning (AGENT_TEMPERATURE).",
    )
    max_output_tokens: int = Field(
        default=2048,
        ge=128,
        le=8192,
        description="Maximum output tokens per Gemini call to keep token usage low.",
    )
    timeout: float = Field(
        default=30.0,
        gt=0.0,
        le=300.0,
        description="Network timeout in seconds for Gemini API requests.",
    )
    max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum retry attempts on transient rate limits or timeouts.",
    )
    retry_delay: float = Field(
        default=1.0,
        ge=0.0,
        le=60.0,
        description="Initial exponential backoff delay in seconds between retries.",
    )

    @field_validator("api_key", mode="before")
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        return _clean_api_key(v)

    @field_validator("model", mode="before")
    @classmethod
    def validate_model(cls, v: Any) -> str:
        if isinstance(v, str) and v.strip():
            return v.strip()
        return "gemini-2.5-flash"

    @property
    def is_configured(self) -> bool:
        """Returns True when a non-placeholder Gemini API key is present."""
        return bool(self.api_key)

    def to_safe_dict(self) -> Dict[str, Any]:
        """Returns a dictionary safe for logging or frontend status responses (never exposes API key)."""
        return {
            "configured": self.is_configured,
            "api_key": "[REDACTED]" if self.is_configured else None,
            "model": self.model,
            "max_iterations": self.max_iterations,
            "max_tool_calls": self.max_tool_calls,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
        }

    def __repr__(self) -> str:
        """Safe representation that never leaks the raw API key."""
        return (
            f"GeminiAgentConfig(model='{self.model}', "
            f"configured={self.is_configured}, "
            f"max_iterations={self.max_iterations}, "
            f"max_tool_calls={self.max_tool_calls}, "
            f"temperature={self.temperature})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @classmethod
    def from_env(
        cls,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_iterations: Optional[int] = None,
        max_tool_calls: Optional[int] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ) -> "GeminiAgentConfig":
        """Constructs a GeminiAgentConfig from explicit parameters, OS environment variables, or settings."""
        resolved_key = (
            _clean_api_key(api_key)
            or _clean_api_key(os.environ.get("GEMINI_API_KEY"))
            or _clean_api_key(getattr(settings, "gemini_api_key", None))
        )

        resolved_model = (
            (model.strip() if isinstance(model, str) and model.strip() else None)
            or os.environ.get("GEMINI_MODEL", "").strip()
            or getattr(settings, "gemini_model", "gemini-2.5-flash")
        )

        def _resolve_int(explicit: Optional[int], env_name: str, default_val: int) -> int:
            if explicit is not None:
                return int(explicit)
            env_raw = os.environ.get(env_name, "").strip()
            if env_raw:
                try:
                    return int(env_raw)
                except ValueError:
                    pass
            return int(default_val)

        def _resolve_float(explicit: Optional[float], env_name: str, default_val: float) -> float:
            if explicit is not None:
                return float(explicit)
            env_raw = os.environ.get(env_name, "").strip()
            if env_raw:
                try:
                    return float(env_raw)
                except ValueError:
                    pass
            return float(default_val)

        resolved_max_iter = _resolve_int(
            max_iterations,
            "AGENT_MAX_ITERATIONS",
            getattr(settings, "agent_max_iterations", 8),
        )
        resolved_max_tools = _resolve_int(
            max_tool_calls,
            "AGENT_MAX_TOOL_CALLS",
            getattr(settings, "agent_max_tool_calls", 15),
        )
        resolved_temp = _resolve_float(
            temperature,
            "AGENT_TEMPERATURE",
            getattr(settings, "agent_temperature", 0.2),
        )
        resolved_tokens = _resolve_int(
            max_output_tokens,
            "GEMINI_MAX_TOKENS",
            getattr(settings, "gemini_max_tokens", 2048),
        )
        resolved_timeout = _resolve_float(
            timeout,
            "GEMINI_TIMEOUT",
            getattr(settings, "gemini_timeout", 30.0),
        )
        resolved_retries = _resolve_int(
            max_retries,
            "GEMINI_MAX_RETRIES",
            3,
        )
        resolved_delay = _resolve_float(
            retry_delay,
            "GEMINI_RETRY_DELAY",
            1.0,
        )

        return cls(
            api_key=resolved_key,
            model=resolved_model,
            max_iterations=resolved_max_iter,
            max_tool_calls=resolved_max_tools,
            temperature=resolved_temp,
            max_output_tokens=resolved_tokens,
            timeout=resolved_timeout,
            max_retries=resolved_retries,
            retry_delay=resolved_delay,
        )

