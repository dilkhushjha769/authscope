"""High-Level Gemini AI Brain & Autonomous Agent Facade for AuthScope.

Exposes `GeminiAuthScopeAgent` with dependency-injected `tool_executor`,
`memory_provider`, and `config`, plus `astream_assessment(request, cancel_token=None)`
returning an asynchronous stream of structured event dictionaries.
"""

from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Union

from backend.agent.finding_analyzer import FindingAnalyzer
from backend.agent.schemas import (
    AnalysisStatus,
    ConfirmationStatus,
    FindingAnalysis,
    FindingAnalysisInput,
    FindingAnalysisOutput,
    RemediationRecommendation,
    SeverityAssessment,
    ValidationStatus,
)
from backend.ai_agent.config import GeminiAgentConfig
from backend.ai_agent.gemini_client import GeminiClient
from backend.ai_agent.orchestrator import (
    AgentOrchestrator,
    AgentStreamEvent,
    ApprovedToolRegistry,
    AssessmentRunResult,
    DefaultMemoryBridge,
    FindingValidationStatus,
    MemoryProviderAdapter,
    MemoryProviderProtocol,
    MemorySystemInterface,
    MockMemoryProvider,
    ToolCallProposal,
    ToolExecutionResult,
    ToolExecutorProtocol,
    ToolValidationResult,
)
from backend.ai_agent.planner import (
    AssessmentPlan,
    AssessmentPlanner,
    AssessmentRequest,
)
from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.remediation import DetailedRemediationPlan, RemediationEngine
from backend.analysis.severity_engine import DeterministicSeverityResult, SeverityEngine
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class GeminiAuthScopeAgent:
    """Central Gemini-powered AI Brain for AuthScope.

    Respects all architectural boundaries:
    - Dependency injection for `tool_executor`, `memory_provider`, and `config`.
    - Never bypasses `ScopeGuard` or `RequestExecutor`.
    - Never executes arbitrary shell commands, dynamic code, or unapproved tools.
    - Enforces bounded iteration (`max_iterations`) and tool call (`max_tool_calls`) limits.
    - Requires independent security-engine evidence validation before confirming findings.
    - Clearly reports deterministic fallback mode when `GEMINI_API_KEY` is absent.
    """

    def __init__(
        self,
        tool_executor: Optional[Any] = None,
        memory_provider: Optional[Any] = None,
        config: Optional[Union[GeminiAgentConfig, Dict[str, Any]]] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_iterations: Optional[int] = None,
        max_tool_calls: Optional[int] = None,
        temperature: Optional[float] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
        gemini_client: Optional[GeminiClient] = None,
        sdk_client: Optional[Any] = None,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        tool_registry: Optional[Any] = None,
        planner: Optional[AssessmentPlanner] = None,
        memory: Optional[Any] = None,
        orchestrator: Optional[AgentOrchestrator] = None,
        evidence_validator: Optional[EvidenceValidator] = None,
        finding_analyzer: Optional[FindingAnalyzer] = None,
        severity_engine: Optional[SeverityEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
    ) -> None:
        # Handle case where a caller passes GeminiAgentConfig as the first positional arg
        if isinstance(tool_executor, GeminiAgentConfig) and config is None:
            config = tool_executor
            tool_executor = None

        if isinstance(config, GeminiAgentConfig):
            base_cfg = config.model_copy(deep=True)
            if api_key is not None:
                base_cfg.api_key = api_key
            if model is not None:
                base_cfg.model = model
            if max_iterations is not None:
                base_cfg.max_iterations = max_iterations
            if max_tool_calls is not None:
                base_cfg.max_tool_calls = max_tool_calls
            if temperature is not None:
                base_cfg.temperature = temperature
            if timeout is not None:
                base_cfg.timeout = timeout
            if max_retries is not None:
                base_cfg.max_retries = max_retries
            if retry_delay is not None:
                base_cfg.retry_delay = retry_delay
            self.config = base_cfg
        elif isinstance(config, dict):
            self.config = GeminiAgentConfig.from_env(
                api_key=api_key or config.get("api_key"),
                model=model or config.get("model"),
                max_iterations=max_iterations or config.get("max_iterations"),
                max_tool_calls=max_tool_calls or config.get("max_tool_calls"),
                temperature=temperature if temperature is not None else config.get("temperature"),
                timeout=timeout if timeout is not None else config.get("timeout"),
                max_retries=max_retries or config.get("max_retries"),
                retry_delay=retry_delay if retry_delay is not None else config.get("retry_delay"),
            )
        else:
            self.config = GeminiAgentConfig.from_env(
                api_key=api_key,
                model=model,
                max_iterations=max_iterations,
                max_tool_calls=max_tool_calls,
                temperature=temperature,
                timeout=timeout,
                max_retries=max_retries,
                retry_delay=retry_delay,
            )

        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor
        self.evidence_validator = evidence_validator or EvidenceValidator()

        resolved_memory = memory_provider if memory_provider is not None else memory
        self.memory_provider: Any = resolved_memory if resolved_memory is not None else DefaultMemoryBridge()
        self.memory_adapter = MemoryProviderAdapter(self.memory_provider)
        self.memory: Any = self.memory_adapter

        self.gemini_client = gemini_client or GeminiClient(
            config=self.config,
            sdk_client=sdk_client,
        )

        resolved_tools = tool_executor if tool_executor is not None else tool_registry
        if isinstance(resolved_tools, ApprovedToolRegistry):
            self.tool_registry = resolved_tools
            self.tool_executor: Any = resolved_tools
        else:
            self.tool_registry = ApprovedToolRegistry(
                scope_guard=self.scope_guard,
                executor=self.executor,
                evidence_validator=self.evidence_validator,
                memory=self.memory_adapter,
                external_tool_executor=resolved_tools,
            )
            self.tool_executor = resolved_tools if resolved_tools is not None else self.tool_registry

        self.planner = planner or AssessmentPlanner(
            scope_guard=self.scope_guard,
            gemini_client=self.gemini_client,
            config=self.config,
            approved_tools=self.tool_registry.approved_tool_names,
        )

        ai_adapter = self.gemini_client if self.gemini_client.is_configured else None
        self.finding_analyzer = finding_analyzer or FindingAnalyzer(ai_client=ai_adapter)
        self.severity_engine = severity_engine or SeverityEngine()
        self.remediation_engine = remediation_engine or RemediationEngine(ai_client=ai_adapter)

        self.orchestrator = orchestrator or AgentOrchestrator(
            config=self.config,
            gemini_client=self.gemini_client,
            scope_guard=self.scope_guard,
            tool_registry=self.tool_registry,
            planner=self.planner,
            memory=self.memory_adapter,
            evidence_validator=self.evidence_validator,
            severity_engine=self.severity_engine,
            remediation_engine=self.remediation_engine,
        )

    @property
    def is_configured(self) -> bool:
        """Returns True if Gemini client has a valid API key or injected SDK client."""
        return self.gemini_client.is_configured

    @property
    def fallback_mode(self) -> bool:
        """Returns True when operating in deterministic fallback mode (no Gemini API key)."""
        return not self.is_configured

    @property
    def mode(self) -> str:
        """Returns 'gemini' when configured with an API key, else 'deterministic_fallback'."""
        return "gemini" if self.is_configured else "deterministic_fallback"

    def get_status(self) -> Dict[str, Any]:
        """Returns a safe status dictionary without exposing any API keys."""
        status = self.config.to_safe_dict()
        status["configured"] = self.is_configured
        status["fallback_mode"] = self.fallback_mode
        status["mode"] = self.mode
        status["approved_tools"] = self.tool_registry.approved_tool_names
        status["total_calls"] = self.gemini_client.total_calls
        status["total_tokens_used"] = self.gemini_client.total_tokens_used
        return status

    def __repr__(self) -> str:
        """Safe representation that never leaks the raw API key."""
        return (
            f"GeminiAuthScopeAgent(model='{self.config.model}', "
            f"configured={self.is_configured}, "
            f"mode='{self.mode}', "
            f"max_iterations={self.config.max_iterations}, "
            f"max_tool_calls={self.config.max_tool_calls}, "
            f"temperature={self.config.temperature})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    # --------------------------------------------------------------------------
    # Planning & Tool Registry Operations
    # --------------------------------------------------------------------------

    def create_plan(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
    ) -> AssessmentPlan:
        """Validates request scope and generates a bounded assessment plan."""
        req = (
            request
            if isinstance(request, AssessmentRequest)
            else AssessmentRequest.model_validate(request)
        )
        knowledge = self.memory_adapter.search_knowledge(query=req.objective, limit=5)
        self.planner.approved_tools = self.tool_registry.approved_tool_names
        return self.planner.create_plan(request=req, security_knowledge=knowledge)

    async def acreate_plan(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
    ) -> AssessmentPlan:
        """Asynchronously validates request scope and generates a bounded assessment plan."""
        req = (
            request
            if isinstance(request, AssessmentRequest)
            else AssessmentRequest.model_validate(request)
        )
        await self.tool_registry.async_refresh_schemas()
        knowledge = await self.memory_adapter.asearch_knowledge(query=req.objective, limit=5)
        self.planner.approved_tools = self.tool_registry.approved_tool_names
        return await self.planner.acreate_plan(request=req, security_knowledge=knowledge)

    def validate_tool_proposal(
        self,
        proposal: Union[ToolCallProposal, Dict[str, Any]],
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
    ) -> ToolValidationResult:
        """Validates a proposed tool call against the approved registry and ScopeGuard."""
        prop = (
            proposal
            if isinstance(proposal, ToolCallProposal)
            else ToolCallProposal.model_validate(proposal)
        )
        return self.tool_registry.validate_proposal(
            proposal=prop,
            target_url=target_url,
            allowed_methods=allowed_methods,
        )

    def execute_tool_proposal(
        self,
        proposal: Union[ToolCallProposal, Dict[str, Any]],
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
    ) -> ToolExecutionResult:
        """Validates and executes an approved tool call through the registry."""
        prop = (
            proposal
            if isinstance(proposal, ToolCallProposal)
            else ToolCallProposal.model_validate(proposal)
        )
        return self.tool_registry.execute_tool(
            proposal=prop,
            target_url=target_url,
            allowed_methods=allowed_methods,
        )

    # --------------------------------------------------------------------------
    # Bounded Assessment Execution & Streaming (Section D & H)
    # --------------------------------------------------------------------------

    def run_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
        cancel_token: Optional[Any] = None,
    ) -> AssessmentRunResult:
        """Executes the bounded 12-step assessment loop synchronously."""
        return self.orchestrator.run_assessment(
            request=request,
            auto_validate_evidence=auto_validate_evidence,
            cancel_token=cancel_token,
        )

    async def arun_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
        cancel_token: Optional[Any] = None,
    ) -> AssessmentRunResult:
        """Executes the bounded 12-step assessment loop asynchronously."""
        return await self.orchestrator.arun_assessment(
            request=request,
            auto_validate_evidence=auto_validate_evidence,
            cancel_token=cancel_token,
        )

    def stream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
        cancel_token: Optional[Any] = None,
    ) -> Generator[AgentStreamEvent, None, AssessmentRunResult]:
        """Streams real-time structured event dictionaries during the bounded assessment loop."""
        return self.orchestrator.stream_assessment(
            request=request,
            auto_validate_evidence=auto_validate_evidence,
            cancel_token=cancel_token,
        )

    async def astream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        cancel_token: Optional[Any] = None,
    ) -> AsyncGenerator[AgentStreamEvent, None]:
        """Asynchronously streams structured event dictionaries for the assessment run.

        Example yielded dictionary:
        {
            "type": "agent_plan",
            "assessment_id": "...",
            "timestamp": "...",
            "message": "Authorization assessment plan created",
            "data": {}
        }
        """
        async for ev in self.orchestrator.astream_assessment(
            request=request,
            cancel_token=cancel_token,
        ):
            yield ev

    # --------------------------------------------------------------------------
    # Existing 8-Step Finding Analysis Pipeline Compatibility
    # --------------------------------------------------------------------------

    def analyze_finding(
        self,
        input_data: Union[FindingAnalysisInput, Dict[str, Any]],
        target_framework: str = "express",
    ) -> FindingAnalysisOutput:
        """Executes the 8-step FindingAnalysisOutput pipeline using Gemini + deterministic engines."""
        validated_input = (
            input_data
            if isinstance(input_data, FindingAnalysisInput)
            else FindingAnalysisInput.model_validate(input_data)
        )
        warnings: List[str] = []

        try:
            analysis: FindingAnalysis = self.finding_analyzer.analyze(validated_input)
        except Exception as exc:
            warnings.append(f"Gemini analysis fallback triggered: {str(exc)}")
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

        # Hard Anti-Upgrade Guardrail: Never allow CONFIRMED without all evidence VALIDATED
        all_validated = all(
            e.validation_status == ValidationStatus.VALIDATED
            for e in validated_input.security_evidence
        )
        if not all_validated and analysis.confirmation_status == ConfirmationStatus.CONFIRMED:
            analysis = analysis.model_copy(
                update={"confirmation_status": ConfirmationStatus.SUSPECTED}
            )

        sev_result: DeterministicSeverityResult = self.severity_engine.evaluate_finding(
            input_data=validated_input,
            ai_rationale=analysis.vulnerability_explanation,
        )
        severity_assessment: SeverityAssessment = sev_result.to_severity_assessment()

        try:
            rem_plan: DetailedRemediationPlan = self.remediation_engine.generate_remediation(
                analysis=analysis,
                severity=severity_assessment,
                evidence=validated_input.security_evidence,
                resource=validated_input.affected_resource,
                target_framework=target_framework,
            )
            remediation_recommendation: RemediationRecommendation = rem_plan.to_remediation_recommendation()
        except Exception as exc:
            warnings.append(f"Remediation fallback triggered: {str(exc)}")
            norm_fw = self.remediation_engine._normalize_framework(target_framework)
            fallback_plan = self.remediation_engine._generate_deterministic_remediation(
                analysis=analysis,
                norm_framework=norm_fw,
                endpoint=validated_input.affected_resource.endpoint,
            )
            remediation_recommendation = fallback_plan.to_remediation_recommendation()

        combined_warnings = list(sev_result.missing_information) + warnings
        if not self.is_configured:
            combined_warnings.append("Operating in deterministic fallback mode (GEMINI_API_KEY not configured).")

        return FindingAnalysisOutput(
            analysis=analysis,
            severity_assessment=severity_assessment,
            remediation_recommendation=remediation_recommendation,
            evidence_references=[e.evidence_id for e in validated_input.security_evidence],
            overall_status=AnalysisStatus.COMPLETED,
            warnings_or_limitations=combined_warnings,
        )


# Convenient alias
GeminiAgent = GeminiAuthScopeAgent
