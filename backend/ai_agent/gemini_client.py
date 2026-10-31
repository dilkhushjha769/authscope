"""Google Gemini Client Wrapper using the official `google-genai` SDK.

Provides synchronous and asynchronous interfaces for text completion, structured
Pydantic JSON generation, and function-calling tool proposals with exponential
backoff retry logic, strict timeout/rate-limit handling, and zero secret exposure.
"""

from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union
import asyncio
import json
import re
import time

import httpx
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types
from pydantic import BaseModel

from backend.ai_agent.config import GeminiAgentConfig
from backend.ai_agent.prompts import GEMINI_SYSTEM_INSTRUCTION
from backend.utils.helpers import AuthScopeException
from backend.utils.logger import get_logger

logger = get_logger(__name__)

TModel = TypeVar("TModel", bound=BaseModel)


# ==============================================================================
# Custom Typed Exceptions
# ==============================================================================


class GeminiClientException(AuthScopeException):
    """Base exception for all Google Gemini client operations."""
    pass


class GeminiConfigurationError(GeminiClientException):
    """Raised when GEMINI_API_KEY or client configuration is missing or invalid."""
    pass


class GeminiAuthenticationError(GeminiClientException):
    """Raised when authentication with Google Gemini API fails (HTTP 401/403)."""
    pass


class GeminiRateLimitError(GeminiClientException):
    """Raised when Gemini API rate limits or quotas are exceeded (HTTP 429)."""
    pass


class GeminiTimeoutError(GeminiClientException):
    """Raised when a Gemini API request times out."""
    pass


class GeminiAPIError(GeminiClientException):
    """Raised when non-recoverable Gemini API errors occur."""
    pass


class GeminiValidationError(GeminiClientException):
    """Raised when Gemini response is empty or violates the requested Pydantic schema."""
    pass


# ==============================================================================
# Official Google GenAI Client Wrapper
# ==============================================================================


class GeminiClient:
    """Official `google-genai` SDK client wrapper for AuthScope security reasoning."""

    def __init__(
        self,
        config: Optional[GeminiAgentConfig] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
        sdk_client: Optional[Any] = None,
    ) -> None:
        """Initializes the Gemini client.

        Args:
            config: Optional pre-built GeminiAgentConfig instance.
            api_key: Optional GEMINI_API_KEY override.
            model: Optional GEMINI_MODEL override (default 'gemini-2.5-flash').
            temperature: Optional sampling temperature override (default 0.2).
            max_output_tokens: Optional maximum output tokens override (default 2048).
            timeout: Optional timeout in seconds (default 30.0).
            max_retries: Optional retry count on transient errors (default 3).
            retry_delay: Optional initial backoff delay in seconds (default 1.0).
            sdk_client: Optional injected `google.genai.Client` or mock for testing.
        """
        if config is not None:
            base_cfg = config.model_copy(deep=True)
            if api_key is not None:
                base_cfg.api_key = api_key
            if model is not None:
                base_cfg.model = model
            if temperature is not None:
                base_cfg.temperature = temperature
            if max_output_tokens is not None:
                base_cfg.max_output_tokens = max_output_tokens
            if timeout is not None:
                base_cfg.timeout = timeout
            if max_retries is not None:
                base_cfg.max_retries = max_retries
            if retry_delay is not None:
                base_cfg.retry_delay = retry_delay
            self.config = base_cfg
        else:
            self.config = GeminiAgentConfig.from_env(
                api_key=api_key,
                model=model,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
                timeout=timeout,
                max_retries=max_retries,
                retry_delay=retry_delay,
            )

        self.model: str = self.config.model
        self.temperature: float = self.config.temperature
        self.max_output_tokens: int = self.config.max_output_tokens
        self.timeout: float = self.config.timeout
        self.max_retries: int = self.config.max_retries
        self.retry_delay: float = self.config.retry_delay

        self.total_calls: int = 0
        self.total_tokens_used: int = 0

        if sdk_client is not None:
            self._client: Optional[Any] = sdk_client
        elif self.config.api_key:
            try:
                http_options = genai_types.HttpOptions(
                    timeout=int(self.timeout * 1000)
                )
                self._client = genai.Client(
                    api_key=self.config.api_key,
                    http_options=http_options,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to initialize google.genai.Client; operating in fallback mode",
                    extra={"error_type": type(exc).__name__},
                )
                self._client = None
        else:
            self._client = None
            logger.info("GEMINI_API_KEY not configured; GeminiClient initialized in offline/fallback mode.")

    @property
    def is_configured(self) -> bool:
        """Returns True if an active SDK client or valid API key is present."""
        return self._client is not None

    @classmethod
    def for_qa(cls) -> "GeminiClient":
        """Constructs Gemini API #1 client for Text Generation & Bug Question-Answer."""
        return cls(config=GeminiAgentConfig.for_qa())

    @classmethod
    def for_code_analysis(cls) -> "GeminiClient":
        """Constructs Gemini API #2 client for Bug Impact, Remediation & Code Generation."""
        return cls(config=GeminiAgentConfig.for_code_analysis())

    @staticmethod
    def _strip_additional_properties(schema_obj: Any) -> Any:
        """Recursively removes 'additionalProperties' for Gemini Developer API compatibility."""
        if isinstance(schema_obj, dict):
            return {
                k: GeminiClient._strip_additional_properties(v)
                for k, v in schema_obj.items()
                if k != "additionalProperties"
            }
        if isinstance(schema_obj, list):
            return [GeminiClient._strip_additional_properties(i) for i in schema_obj]
        return schema_obj

    def __repr__(self) -> str:
        """Safe representation that never exposes the raw API key."""
        return (
            f"GeminiClient(model='{self.model}', "
            f"configured={self.is_configured}, "
            f"temperature={self.temperature}, "
            f"max_output_tokens={self.max_output_tokens}, "
            f"timeout={self.timeout})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    # --------------------------------------------------------------------------
    # Internal Error Classification & JSON Extraction
    # --------------------------------------------------------------------------

    @staticmethod
    def _extract_json_string(raw_text: str) -> str:
        """Strips optional markdown code fences to isolate a raw JSON payload."""
        text = (raw_text or "").strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            return match.group(1).strip()
        return text

    @staticmethod
    def _classify_exception(exc: Exception) -> Tuple[str, bool]:
        """Classifies an exception into ('auth' | 'rate_limit' | 'timeout' | 'api', is_retryable)."""
        if isinstance(exc, (GeminiClientException,)):
            return ("passthrough", False)

        # Timeout checks
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException)):
            return ("timeout", True)

        status_code: Optional[int] = getattr(exc, "code", None) or getattr(exc, "status_code", None)
        msg_lower = str(exc).lower()

        if isinstance(exc, genai_errors.APIError) or status_code is not None:
            if status_code in (401, 403) or "api_key_invalid" in msg_lower or "permission_denied" in msg_lower or "unauthenticated" in msg_lower:
                return ("auth", False)
            if status_code == 429 or "resource_exhausted" in msg_lower or "rate limit" in msg_lower or "quota" in msg_lower:
                return ("rate_limit", True)
            if status_code in (408, 504) or "deadline_exceeded" in msg_lower or "timed out" in msg_lower or "timeout" in msg_lower:
                return ("timeout", True)
            if isinstance(exc, genai_errors.ServerError) or (status_code and status_code >= 500):
                return ("api", True)
            return ("api", False)

        if "401" in msg_lower or "403" in msg_lower or "invalid api key" in msg_lower or "authentication" in msg_lower:
            return ("auth", False)
        if "429" in msg_lower or "rate limit" in msg_lower or "resource_exhausted" in msg_lower or "quota" in msg_lower:
            return ("rate_limit", True)
        if "timeout" in msg_lower or "timed out" in msg_lower:
            return ("timeout", True)

        return ("api", False)

    def _record_usage(self, response: Any) -> None:
        """Tracks call count and token usage metadata when present on response."""
        self.total_calls += 1
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            total = getattr(usage, "total_token_count", None)
            if isinstance(total, int) and total > 0:
                self.total_tokens_used += total

    @staticmethod
    def _extract_text_from_response(response: Any) -> str:
        """Extracts text safely from a google-genai GenerateContentResponse or mock."""
        if response is None:
            return ""
        direct_text = getattr(response, "text", None)
        if isinstance(direct_text, str) and direct_text.strip():
            return direct_text.strip()

        candidates = getattr(response, "candidates", None)
        if candidates and isinstance(candidates, list):
            parts_text: List[str] = []
            for cand in candidates:
                content = getattr(cand, "content", None)
                parts = getattr(content, "parts", None) if content else None
                if parts:
                    for part in parts:
                        pt = getattr(part, "text", None)
                        if isinstance(pt, str) and pt:
                            parts_text.append(pt)
            if parts_text:
                return "\n".join(parts_text).strip()

        return ""

    @staticmethod
    def _extract_function_calls(response: Any) -> List[Dict[str, Any]]:
        """Extracts structured function call proposals from a GenerateContentResponse."""
        calls: List[Dict[str, Any]] = []
        fn_calls = getattr(response, "function_calls", None)
        if fn_calls:
            for fc in fn_calls:
                name = getattr(fc, "name", None)
                args = getattr(fc, "args", None) or {}
                if isinstance(args, BaseModel):
                    args = args.model_dump()
                elif not isinstance(args, dict):
                    try:
                        args = dict(args)
                    except Exception:
                        args = {}
                if name:
                    calls.append({"name": str(name), "arguments": args})
            return calls

        candidates = getattr(response, "candidates", None)
        if candidates and isinstance(candidates, list):
            for cand in candidates:
                content = getattr(cand, "content", None)
                parts = getattr(content, "parts", None) if content else None
                if parts:
                    for part in parts:
                        fc = getattr(part, "function_call", None)
                        if fc is not None:
                            name = getattr(fc, "name", None)
                            args = getattr(fc, "args", None) or {}
                            if not isinstance(args, dict):
                                try:
                                    args = dict(args)
                                except Exception:
                                    args = {}
                            if name:
                                calls.append({"name": str(name), "arguments": args})
        return calls

    def _build_generate_config(
        self,
        system_instruction: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
        response_mime_type: Optional[str] = None,
        response_schema: Optional[Any] = None,
        tools: Optional[List[Any]] = None,
    ) -> genai_types.GenerateContentConfig:
        """Builds a google.genai.types.GenerateContentConfig with safe defaults."""
        eff_temp = temperature if temperature is not None else self.temperature
        eff_tokens = max_output_tokens if max_output_tokens is not None else self.max_output_tokens
        sys_inst = system_instruction or GEMINI_SYSTEM_INSTRUCTION

        cfg_kwargs: Dict[str, Any] = {
            "system_instruction": sys_inst,
            "temperature": eff_temp,
            "max_output_tokens": eff_tokens,
        }
        if response_mime_type is not None:
            cfg_kwargs["response_mime_type"] = response_mime_type
        if response_schema is not None:
            cfg_kwargs["response_schema"] = response_schema
        if tools is not None:
            cfg_kwargs["tools"] = tools

        return genai_types.GenerateContentConfig(**cfg_kwargs)

    # --------------------------------------------------------------------------
    # Synchronous Generation Methods
    # --------------------------------------------------------------------------

    def generate_text(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
    ) -> str:
        """Generates a text completion using Google Gemini with retry and error handling."""
        if self._client is None:
            raise GeminiConfigurationError(
                "Gemini API key is not configured. Set the GEMINI_API_KEY environment variable."
            )

        target_model = model or self.model
        gen_config = self._build_generate_config(
            system_instruction=system_instruction,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    "Dispatching Gemini generate_content request",
                    extra={
                        "model": target_model,
                        "attempt": attempt,
                        "max_output_tokens": gen_config.max_output_tokens,
                    },
                )
                response = self._client.models.generate_content(
                    model=target_model,
                    contents=prompt,
                    config=gen_config,
                )
                self._record_usage(response)
                text = self._extract_text_from_response(response)
                if not text:
                    raise GeminiValidationError("Gemini API returned an empty text response.")
                return text

            except Exception as exc:
                if isinstance(exc, GeminiValidationError):
                    raise
                category, is_retryable = self._classify_exception(exc)
                if category == "passthrough":
                    raise

                if category == "auth":
                    logger.error("Gemini API authentication failed. Verify GEMINI_API_KEY.")
                    raise GeminiAuthenticationError(
                        "Gemini API authentication failed. Verify GEMINI_API_KEY credentials."
                    ) from exc

                if is_retryable and attempt < self.max_retries:
                    backoff = self.retry_delay * (2 ** (attempt - 1))
                    logger.warning(
                        f"Transient Gemini {category} error on attempt {attempt}/{self.max_retries}; retrying",
                        extra={"attempt": attempt, "category": category},
                    )
                    if backoff > 0:
                        time.sleep(backoff)
                    continue

                if category == "rate_limit":
                    raise GeminiRateLimitError(
                        f"Gemini API rate limit exceeded after {attempt} attempt(s)."
                    ) from exc
                if category == "timeout":
                    raise GeminiTimeoutError(
                        f"Gemini API request timed out after {attempt} attempt(s)."
                    ) from exc
                raise GeminiAPIError(
                    f"Gemini API request failed: {type(exc).__name__}: {str(exc)}"
                ) from exc

        raise GeminiAPIError("Gemini API request exhausted all retry attempts.")

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Adapter method compatible with AuthScope FindingAnalyzer and RemediationEngine protocols."""
        return self.generate_text(
            prompt=user_prompt,
            system_instruction=system_prompt,
        )

    def generate_structured(
        self,
        prompt: str,
        response_schema: Type[TModel],
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
    ) -> TModel:
        """Generates a structured JSON response and validates it against a Pydantic model."""
        if self._client is None:
            raise GeminiConfigurationError(
                "Gemini API key is not configured. Set the GEMINI_API_KEY environment variable."
            )

        target_model = model or self.model
        gen_config = self._build_generate_config(
            system_instruction=system_instruction,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            response_mime_type="application/json",
            response_schema=response_schema,
        )

        for attempt in range(1, self.max_retries + 1):
            try:
                try:
                    response = self._client.models.generate_content(
                        model=target_model,
                        contents=prompt,
                        config=gen_config,
                    )
                except ValueError as val_exc:
                    if "additionalProperties" in str(val_exc) and hasattr(
                        response_schema, "model_json_schema"
                    ):
                        clean_schema = self._strip_additional_properties(
                            response_schema.model_json_schema()
                        )
                        fallback_config = self._build_generate_config(
                            system_instruction=system_instruction,
                            temperature=temperature,
                            max_output_tokens=max_output_tokens,
                            response_mime_type="application/json",
                            response_schema=clean_schema,
                        )
                        response = self._client.models.generate_content(
                            model=target_model,
                            contents=prompt,
                            config=fallback_config,
                        )
                    else:
                        raise
                self._record_usage(response)

                parsed_obj = getattr(response, "parsed", None)
                if isinstance(parsed_obj, response_schema):
                    return parsed_obj
                if isinstance(parsed_obj, dict):
                    return response_schema.model_validate(parsed_obj)

                raw_text = self._extract_text_from_response(response)
                if not raw_text:
                    raise GeminiValidationError("Gemini API returned empty structured response.")

                clean_json = self._extract_json_string(raw_text)
                try:
                    data = json.loads(clean_json)
                    return response_schema.model_validate(data)
                except Exception as parse_exc:
                    raise GeminiValidationError(
                        f"Gemini response failed schema validation for {response_schema.__name__}: {parse_exc}"
                    ) from parse_exc

            except Exception as exc:
                if isinstance(exc, GeminiValidationError):
                    raise
                category, is_retryable = self._classify_exception(exc)
                if category == "passthrough":
                    raise
                if category == "auth":
                    raise GeminiAuthenticationError(
                        "Gemini API authentication failed. Verify GEMINI_API_KEY credentials."
                    ) from exc
                if is_retryable and attempt < self.max_retries:
                    backoff = self.retry_delay * (2 ** (attempt - 1))
                    if backoff > 0:
                        time.sleep(backoff)
                    continue
                if category == "rate_limit":
                    raise GeminiRateLimitError(
                        f"Gemini API rate limit exceeded after {attempt} attempt(s)."
                    ) from exc
                if category == "timeout":
                    raise GeminiTimeoutError(
                        f"Gemini API request timed out after {attempt} attempt(s)."
                    ) from exc
                raise GeminiAPIError(
                    f"Gemini structured generation failed: {type(exc).__name__}: {str(exc)}"
                ) from exc

        raise GeminiAPIError("Gemini structured generation exhausted all retry attempts.")

    def generate_with_tools(
        self,
        prompt: str,
        tool_declarations: List[Dict[str, Any]],
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Requests a tool-call proposal or text completion from Gemini using declared tools.

        Returns a normalized dictionary:
        {
            "function_calls": [{"name": str, "arguments": dict}],
            "text": str
        }
        """
        if self._client is None:
            raise GeminiConfigurationError(
                "Gemini API key is not configured. Set the GEMINI_API_KEY environment variable."
            )

        target_model = model or self.model
        fn_decls: List[genai_types.FunctionDeclaration] = []
        for td in tool_declarations:
            fn_decls.append(
                genai_types.FunctionDeclaration(
                    name=td["name"],
                    description=td.get("description", ""),
                    parameters_json_schema=td.get("input_schema") or td.get("parameters"),
                )
            )
        sdk_tools = [genai_types.Tool(function_declarations=fn_decls)] if fn_decls else None

        gen_config = self._build_generate_config(
            system_instruction=system_instruction,
            temperature=temperature,
            tools=sdk_tools,
        )

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.models.generate_content(
                    model=target_model,
                    contents=prompt,
                    config=gen_config,
                )
                self._record_usage(response)
                fn_calls = self._extract_function_calls(response)
                text = self._extract_text_from_response(response)
                return {
                    "function_calls": fn_calls,
                    "text": text,
                }
            except Exception as exc:
                category, is_retryable = self._classify_exception(exc)
                if category == "passthrough":
                    raise
                if category == "auth":
                    raise GeminiAuthenticationError(
                        "Gemini API authentication failed. Verify GEMINI_API_KEY credentials."
                    ) from exc
                if is_retryable and attempt < self.max_retries:
                    backoff = self.retry_delay * (2 ** (attempt - 1))
                    if backoff > 0:
                        time.sleep(backoff)
                    continue
                if category == "rate_limit":
                    raise GeminiRateLimitError(
                        f"Gemini API rate limit exceeded after {attempt} attempt(s)."
                    ) from exc
                if category == "timeout":
                    raise GeminiTimeoutError(
                        f"Gemini API request timed out after {attempt} attempt(s)."
                    ) from exc
                raise GeminiAPIError(
                    f"Gemini tool generation failed: {type(exc).__name__}: {str(exc)}"
                ) from exc

        raise GeminiAPIError("Gemini tool generation exhausted all retry attempts.")

    # --------------------------------------------------------------------------
    # Asynchronous Generation Methods (FastAPI / Async Compatible)
    # --------------------------------------------------------------------------

    async def agenerate_text(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
    ) -> str:
        """Asynchronous wrapper for `generate_text`."""
        return await asyncio.to_thread(
            self.generate_text,
            prompt=prompt,
            system_instruction=system_instruction,
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

    async def agenerate_structured(
        self,
        prompt: str,
        response_schema: Type[TModel],
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
    ) -> TModel:
        """Asynchronous wrapper for `generate_structured`."""
        return await asyncio.to_thread(
            self.generate_structured,
            prompt=prompt,
            response_schema=response_schema,
            system_instruction=system_instruction,
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

    async def agenerate_with_tools(
        self,
        prompt: str,
        tool_declarations: List[Dict[str, Any]],
        system_instruction: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Asynchronous wrapper for `generate_with_tools`."""
        return await asyncio.to_thread(
            self.generate_with_tools,
            prompt=prompt,
            tool_declarations=tool_declarations,
            system_instruction=system_instruction,
            model=model,
            temperature=temperature,
        )
