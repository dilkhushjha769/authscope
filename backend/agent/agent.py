"""AuthScope AI Agent: Central Claude-Powered Orchestrator.

Coordinates Finding Analyzer, Severity Engine, Remediation Engine,
prompts, and Pydantic schemas under strict evidence-supported guardrails.

Architectural Guarantees:
1. Hard Scope & Safety: Zero arbitrary command execution or raw shell invocation.
2. Deterministic Severity: CVSS & risk metrics are strictly calculated by mathematical
   rules, never inflated or overridden by model speculation.
3. Anti-Upgrade Guardrail: Confirmation status is anchored to trusted validation metadata;
   unvalidated findings cannot be marked as CONFIRMED.
4. Defense-in-Depth Remediation: Generates actionable, server-side patches and retesting
   procedures tailored to the target application framework.
5. Error Resilience: Exponential backoff retries on transient errors and graceful fallback.
6. Secret Protection: Redacts secrets; never logs raw credentials or API keys.
"""

from typing import Any, Dict, List, Optional, Union
import json
import os
import re
import time

from anthropic import (
    Anthropic,
    APIConnectionError,
    APIError,
    APITimeoutError,
    AuthenticationError,
    InternalServerError,
    RateLimitError,
)

from backend.config import settings
from backend.utils.helpers import AuthScopeException
from backend.utils.logger import get_logger
from backend.agent.finding_analyzer import FindingAnalyzer
from backend.analysis.severity_engine import SeverityEngine, DeterministicSeverityResult
from backend.analysis.remediation import RemediationEngine, DetailedRemediationPlan
from backend.agent.prompts import (
    SYSTEM_ANALYSIS_PROMPT,
    SYSTEM_PROMPT,
    build_finding_analysis_prompt,
    wrap_untrusted_evidence,
)
from backend.agent.schemas import (
    AnalysisStatus,
    ConfirmationStatus,
    ConfidenceLevel,
    FindingAnalysis,
    FindingAnalysisInput,
    FindingAnalysisOutput,
    RemediationRecommendation,
    SecurityEvidence,
    SeverityAssessment,
    ValidationStatus,
)
from backend.agent.tools import AgentTools, TOOL_DEFINITIONS

logger = get_logger(__name__)


# ==============================================================================
# Agent Custom Exceptions
# ==============================================================================


class AgentException(AuthScopeException):
    """Base exception for AI agent operations."""
    pass


class AgentConfigurationError(AgentException):
    """Raised when required agent configuration or credentials are missing."""
    pass


class AgentAuthenticationError(AgentException):
    """Raised when authentication with the Anthropic API fails."""
    pass


class AgentAPIError(AgentException):
    """Raised when non-recoverable Anthropic API errors occur or retries are exhausted."""
    pass


class AgentValidationError(AgentException):
    """Raised when model output is malformed or violates schema validation."""
    pass


# ==============================================================================
# AI Client Adapter
# ==============================================================================


class _AgentAIClientAdapter:
    """Internal adapter bridging Anthropic Messages API to cognitive analyzer and remediation protocols."""

    def __init__(self, agent: "AuthScopeAgent"):
        self._agent = agent

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Dispatches completion request to the parent agent's Claude Messages API."""
        return self._agent.call_claude(system_prompt=system_prompt, user_prompt=user_prompt)


# ==============================================================================
# Central AI Agent Orchestrator
# ==============================================================================


class AuthScopeAgent:
    """Central Claude-powered AI Agent coordinating authorization finding analysis,
    deterministic severity calculation, and intelligent remediation generation.
    """

    def __init__(
        self,
        tools: Optional[AgentTools] = None,
        client: Optional[Any] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        temperature: float = 0.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        finding_analyzer: Optional[FindingAnalyzer] = None,
        severity_engine: Optional[SeverityEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
    ):
        """Initializes the central AuthScope AI Agent.

        Args:
            tools: Optional AgentTools instance for tool dispatching.
            client: Optional Anthropic client instance or mock for dependency injection.
            api_key: Optional Anthropic API key override.
            model: Optional model identifier override.
            max_tokens: Maximum tokens for Claude completions.
            timeout: Network timeout in seconds for API calls.
            temperature: Sampling temperature (default 0.0 for deterministic security analysis).
            max_retries: Maximum exponential backoff retries on transient errors.
            retry_delay: Initial backoff delay in seconds between retries.
            finding_analyzer: Optional FindingAnalyzer override.
            severity_engine: Optional SeverityEngine override.
            remediation_engine: Optional RemediationEngine override.
        """
        self.tools = tools
        self.temperature = temperature
        self.max_retries = max(1, max_retries)
        self.retry_delay = max(0.0, retry_delay)

        # 1. Resolve configuration from parameters, environment variables, or settings
        raw_key = (
            api_key
            or os.environ.get("ANTHROPIC_API_KEY")
            or getattr(settings, "anthropic_api_key", "")
        )
        if raw_key in ("your_anthropic_api_key_here", "placeholder_key"):
            self.api_key: Optional[str] = None
        else:
            self.api_key = raw_key if raw_key else None

        self.model: str = (
            model
            or os.environ.get("ANTHROPIC_MODEL")
            or getattr(settings, "anthropic_model", "claude-3-5-sonnet-20241022")
        )

        env_max_tokens = os.environ.get("ANTHROPIC_MAX_TOKENS")
        self.max_tokens: int = (
            max_tokens
            or (int(env_max_tokens) if env_max_tokens and env_max_tokens.isdigit() else None)
            or getattr(settings, "anthropic_max_tokens", 2048)
        )

        env_timeout = os.environ.get("ANTHROPIC_TIMEOUT")
        self.timeout: float = (
            timeout
            or (float(env_timeout) if env_timeout else None)
            or getattr(settings, "anthropic_timeout", 30.0)
        )

        # 2. Initialize Anthropic client (or use provided client / mock)
        if client is not None:
            self.client: Optional[Any] = client
        elif self.api_key:
            try:
                self.client = Anthropic(api_key=self.api_key, timeout=self.timeout)
            except Exception as exc:
                logger.warning(
                    "Failed to initialize Anthropic client transport; operating in deterministic fallback mode",
                    extra={"error": str(exc)},
                )
                self.client = None
        else:
            self.client = None
            logger.info("Anthropic API key not configured; agent will operate in deterministic fallback mode.")

        # 3. Setup internal AI client adapter
        self._ai_adapter: Optional[_AgentAIClientAdapter] = (
            _AgentAIClientAdapter(self) if self.client is not None else None
        )

        # 4. Initialize domain engines with dependency injection
        self.finding_analyzer: FindingAnalyzer = (
            finding_analyzer or FindingAnalyzer(ai_client=self._ai_adapter)
        )
        self.severity_engine: SeverityEngine = (
            severity_engine or SeverityEngine()
        )
        self.remediation_engine: RemediationEngine = (
            remediation_engine or RemediationEngine(ai_client=self._ai_adapter)
        )

        self._operational_warnings: List[str] = []

    def __repr__(self) -> str:
        """Safe representation without exposing secrets."""
        has_key = bool(self.api_key or self.client is not None)
        return (
            f"AuthScopeAgent(model='{self.model}', "
            f"configured={has_key}, "
            f"max_tokens={self.max_tokens}, "
            f"timeout={self.timeout})"
        )

    # --------------------------------------------------------------------------
    # Claude Messages API Communication
    # --------------------------------------------------------------------------

    def call_claude(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """Invokes Claude Messages API with exponential backoff retries and error handling.

        Args:
            system_prompt: System directive for the model.
            user_prompt: User prompt content.
            max_tokens: Optional override token limit.
            temperature: Optional override temperature.

        Returns:
            Cleaned text response from Claude.

        Raises:
            AgentConfigurationError: If API key / client is missing.
            AgentAuthenticationError: If authentication with Anthropic fails.
            AgentAPIError: If non-retryable API error occurs or retries are exhausted.
            AgentValidationError: If response is empty or unparsable.
        """
        if self.client is None:
            raise AgentConfigurationError(
                "Anthropic API key is not configured. Set ANTHROPIC_API_KEY environment variable."
            )

        eff_tokens = max_tokens or self.max_tokens
        eff_temp = temperature if temperature is not None else self.temperature
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(
                    "Dispatching Anthropic Messages API request",
                    extra={
                        "model": self.model,
                        "attempt": attempt,
                        "max_tokens": eff_tokens,
                    },
                )
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=eff_tokens,
                    temperature=eff_temp,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt}
                    ],
                    timeout=self.timeout,
                )

                content_text = ""
                for block in response.content:
                    if getattr(block, "type", None) == "text":
                        content_text += block.text
                    elif hasattr(block, "text"):
                        content_text += block.text
                    elif isinstance(block, dict) and block.get("type") == "text":
                        content_text += block.get("text", "")

                cleaned = content_text.strip()
                if not cleaned:
                    raise AgentValidationError("Anthropic API returned an empty response body.")

                return cleaned

            except AuthenticationError as exc:
                # Authentication failures are permanent; do NOT retry
                logger.error("Anthropic API authentication failed. Verify ANTHROPIC_API_KEY.")
                raise AgentAuthenticationError(
                    "Anthropic API authentication failed. Verify ANTHROPIC_API_KEY credentials."
                ) from exc

            except (RateLimitError, APITimeoutError, APIConnectionError, InternalServerError) as exc:
                last_error = exc
                err_name = type(exc).__name__
                logger.warning(
                    f"Transient Anthropic error on attempt {attempt}/{self.max_retries}: {err_name}",
                    extra={"attempt": attempt, "error_type": err_name},
                )
                if attempt < self.max_retries:
                    backoff = self.retry_delay * (2 ** (attempt - 1))
                    time.sleep(backoff)
                else:
                    logger.error(
                        f"Retries exhausted ({self.max_retries}) for Anthropic API error: {err_name}"
                    )
                    raise AgentAPIError(
                        f"Anthropic API request failed after {self.max_retries} attempts: {err_name}"
                    ) from exc

            except APIError as exc:
                logger.error(f"Anthropic API error: {type(exc).__name__}")
                raise AgentAPIError(f"Anthropic API returned error: {type(exc).__name__}") from exc

            except Exception as exc:
                if isinstance(exc, (AgentException, AgentValidationError)):
                    raise
                logger.error(f"Unexpected error during Claude API communication: {str(exc)}")
                raise AgentAPIError(f"Unexpected error during Claude call: {str(exc)}") from exc

        raise AgentAPIError(f"Claude API call failed: {str(last_error)}")

    # --------------------------------------------------------------------------
    # Helper: Markdown JSON Stripping
    # --------------------------------------------------------------------------

    @staticmethod
    def _extract_json_from_response(raw_text: str) -> str:
        """Extracts JSON substring from model response, stripping markdown fences."""
        text = raw_text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if match:
            return match.group(1).strip()
        return text

    # --------------------------------------------------------------------------
    # Complete 8-Step Finding Analysis Pipeline
    # --------------------------------------------------------------------------

    def analyze_finding(
        self,
        input_data: Union[FindingAnalysisInput, Dict[str, Any]],
        target_framework: str = "express",
        raise_on_error: bool = False,
    ) -> FindingAnalysisOutput:
        """Executes the complete 8-step finding analysis pipeline.

        Workflow:
        1. Validate incoming data using Pydantic.
        2. Pass validated evidence to Finding Analyzer.
        3. Use Claude to explain the vulnerability and technical root cause.
        4. Determine confirmation status using trusted validation metadata.
        5. Pass the resulting analysis to the deterministic Severity Engine.
        6. Generate remediation recommendations using the Remediation Engine.
        7. Validate the complete result against FindingAnalysisOutput.
        8. Return structured FindingAnalysisOutput to the calling backend component.

        Args:
            input_data: Structured FindingAnalysisInput model or equivalent dict.
            target_framework: Target framework for code remediation (e.g. 'express', 'fastapi', 'spring').
            raise_on_error: If True, re-raises any cognitive/API errors instead of falling back.

        Returns:
            Validated FindingAnalysisOutput model.
        """
        self._operational_warnings = []

        # ----------------------------------------------------------------------
        # STEP 1: Validate incoming data using Pydantic
        # ----------------------------------------------------------------------
        try:
            if isinstance(input_data, dict):
                if "raw_evidence" in input_data and "security_evidence" not in input_data:
                    validated_input = self.finding_analyzer._convert_legacy_evidence(input_data["raw_evidence"])
                else:
                    validated_input = FindingAnalysisInput.model_validate(input_data)
            elif isinstance(input_data, FindingAnalysisInput):
                validated_input = input_data
            else:
                raise AgentValidationError(
                    f"Unsupported input type '{type(input_data).__name__}'. Expected FindingAnalysisInput or dict."
                )
        except Exception as exc:
            logger.error("Failed Step 1 input schema validation", extra={"error": str(exc)})
            if raise_on_error:
                raise AgentValidationError(f"Input schema validation failed: {str(exc)}") from exc
            raise

        logger.info(
            "Agent analyzing finding",
            extra={
                "finding_id": validated_input.finding_id,
                "category": validated_input.vulnerability_category.value,
                "evidence_count": len(validated_input.security_evidence),
            },
        )

        # ----------------------------------------------------------------------
        # STEP 2, 3 & 4: Finding Analyzer with Claude & Trusted Metadata Gate
        # ----------------------------------------------------------------------
        try:
            analysis: FindingAnalysis = self.finding_analyzer.analyze(validated_input)
        except Exception as exc:
            logger.warning(
                "FindingAnalyzer raised an exception; using deterministic fallback",
                extra={"error": str(exc)},
            )
            if raise_on_error:
                raise
            self._operational_warnings.append(f"AI analysis fallback triggered: {str(exc)}")
            inspection = self.finding_analyzer.inspect_evidence(validated_input.security_evidence)
            vuln_context = self.finding_analyzer.determine_vulnerability_context(validated_input, inspection)
            conf_status = self.finding_analyzer.determine_confirmation_status(validated_input, inspection)
            conf_level = self.finding_analyzer.estimate_confidence(conf_status, inspection)
            impact = self.finding_analyzer.analyze_impact(validated_input, inspection, vuln_context)
            analysis = self.finding_analyzer._synthesize_structured_analysis(
                input_data=validated_input,
                inspection=inspection,
                vuln_context=vuln_context,
                confirmation_status=conf_status,
                confidence_level=conf_level,
                potential_impact=impact,
            )

        # STEP 4 Hard Enforcement: Confirmation status can NEVER be upgraded by AI
        all_validated = all(
            e.validation_status == ValidationStatus.VALIDATED
            for e in validated_input.security_evidence
        )
        if not all_validated and analysis.confirmation_status == ConfirmationStatus.CONFIRMED:
            logger.warning("Guardrail tripped: model set CONFIRMED without validated evidence; reverting.")
            analysis = analysis.model_copy(
                update={"confirmation_status": ConfirmationStatus.SUSPECTED}
            )

        # ----------------------------------------------------------------------
        # STEP 5: Pass resulting analysis to deterministic Severity Engine
        # ----------------------------------------------------------------------
        sev_result: DeterministicSeverityResult = self.severity_engine.evaluate_finding(
            input_data=validated_input,
            ai_rationale=analysis.vulnerability_explanation,
        )
        severity_assessment: SeverityAssessment = sev_result.to_severity_assessment()

        # ----------------------------------------------------------------------
        # STEP 6: Generate remediation recommendations using Remediation Engine
        # ----------------------------------------------------------------------
        try:
            remediation_plan: DetailedRemediationPlan = self.remediation_engine.generate_remediation(
                analysis=analysis,
                severity=severity_assessment,
                evidence=validated_input.security_evidence,
                resource=validated_input.affected_resource,
                target_framework=target_framework,
            )
            remediation_recommendation: RemediationRecommendation = (
                remediation_plan.to_remediation_recommendation()
            )
        except Exception as exc:
            logger.warning(
                "RemediationEngine raised an exception; generating deterministic fallback",
                extra={"error": str(exc)},
            )
            if raise_on_error:
                raise
            self._operational_warnings.append(f"Remediation fallback triggered: {str(exc)}")
            norm_fw = self.remediation_engine._normalize_framework(target_framework)
            plan = self.remediation_engine._generate_deterministic_remediation(
                analysis=analysis,
                norm_framework=norm_fw,
                endpoint=validated_input.affected_resource.endpoint,
            )
            remediation_recommendation = plan.to_remediation_recommendation()

        # ----------------------------------------------------------------------
        # STEP 7: Validate complete result against FindingAnalysisOutput
        # ----------------------------------------------------------------------
        combined_warnings = list(sev_result.missing_information)
        combined_warnings.extend(self._operational_warnings)
        if self.client is None:
            combined_warnings.append("Operating in deterministic fallback mode (ANTHROPIC_API_KEY not configured).")

        evidence_ids = [e.evidence_id for e in validated_input.security_evidence]

        output = FindingAnalysisOutput(
            analysis=analysis,
            severity_assessment=severity_assessment,
            remediation_recommendation=remediation_recommendation,
            evidence_references=evidence_ids,
            overall_status=AnalysisStatus.COMPLETED,
            warnings_or_limitations=combined_warnings,
        )

        # ----------------------------------------------------------------------
        # STEP 8: Return structured output to caller
        # ----------------------------------------------------------------------
        return output

    def analyze_finding_json(
        self,
        input_data: Union[FindingAnalysisInput, Dict[str, Any]],
        target_framework: str = "express",
        indent: int = 2,
    ) -> str:
        """Executes analysis and returns formatted JSON string."""
        output = self.analyze_finding(input_data=input_data, target_framework=target_framework)
        return output.model_dump_json(indent=indent)

    def analyze_finding_dict(
        self,
        input_data: Union[FindingAnalysisInput, Dict[str, Any]],
        target_framework: str = "express",
    ) -> Dict[str, Any]:
        """Executes analysis and returns a serializable dictionary."""
        output = self.analyze_finding(input_data=input_data, target_framework=target_framework)
        return output.model_dump()

    # --------------------------------------------------------------------------
    # Backward Compatibility
    # --------------------------------------------------------------------------

    def run_scan_loop(self, scan_objective: str) -> Dict[str, Any]:
        """Executes the agentic scanning and reasoning loop.

        Preserved for Phase 5 multi-turn conversational tool execution loop.
        """
        logger.info("Initializing Agent scan loop", extra={"objective": scan_objective})
        return {
            "status": "INITIALIZED",
            "message": "Agent loop scaffolded. Complete Anthropic loop scheduled for Phase 5.",
        }
