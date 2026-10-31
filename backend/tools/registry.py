"""Approved Tool Registry for AuthScope Gemini and AI Agents.

Manages registered security tools, enforces strict Pydantic v2 input validation,
verifies ScopeGuard boundaries, records execution metadata, and emits
streaming events for real-time frontend observability.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type
import uuid

from pydantic import BaseModel, ValidationError

from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.tools.schemas import (
    AnalyzeResponseInput,
    AnalyzeResponseOutput,
    AnalyzeSourceCodeInput,
    AnalyzeSourceCodeOutput,
    CheckHttpMethodsInput,
    CheckAuthWeaknessesInput,
    CheckAuthWeaknessesOutput,
    CheckCorsInput,
    CheckCorsOutput,
    CheckHttpMethodsInput,
    CheckHttpMethodsOutput,
    CheckSecurityHeadersInput,
    CheckSecurityHeadersOutput,
    CheckSessionSecurityInput,
    CheckSessionSecurityOutput,
    CheckTransportSecurityInput,
    CheckTransportSecurityOutput,
    CompareEndpointAccessInput,
    CompareEndpointAccessOutput,
    DetectIdorInput,
    DetectIdorOutput,
    DiscoverEndpointsInput,
    DiscoverEndpointsOutput,
    PlanAttackChainsInput,
    PlanAttackChainsOutput,
    EvidenceValidatedEvent,
    ExplainFindingInput,
    ExplainFindingOutput,
    GenerateRemediationInput,
    GenerateRemediationOutput,
    GetAssessmentSummaryInput,
    GetAssessmentSummaryOutput,
    InspectEndpointInput,
    InspectEndpointOutput,
    RunMisconfigurationScanInput,
    RunMisconfigurationScanOutput,
    MapEndpointToCodeInput,
    MapEndpointToCodeOutput,
    ProbeAccessControlInput,
    ProbeAccessControlOutput,
    RetestFindingInput,
    RetestFindingOutput,
    SaveFindingInput,
    SaveFindingOutput,
    TestAccessControlInput,
    TestAccessControlOutput,
    TestBflaInput,
    TestBflaOutput,
    TestUnauthorizedModificationInput,
    TestUnauthorizedModificationOutput,
    ToolCategory,
    ToolCompletedEvent,
    ToolEventBase,
    ToolExecutionContext,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolFailedEvent,
    ToolStartedEvent,
    ValidateEvidenceInput,
    ValidateEvidenceOutput,
    ValidateTargetInput,
    ValidateTargetOutput,
)
from backend.tools.website_tools import WebsiteTools
from backend.tools.authorization_tools import AuthorizationTools
from backend.tools.source_tools import SourceTools
from backend.tools.report_tools import ReportTools
from backend.utils.helpers import (
    AuthScopeException,
    InvalidDataError,
    InvalidTargetURLError,
    ScopeViolationError,
    UnsupportedMethodError,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Exceptions
# ==============================================================================


class UnknownToolError(AuthScopeException):
    """Raised when an unregistered tool is requested."""
    pass


class ToolArgumentValidationError(AuthScopeException):
    """Raised when tool input arguments fail Pydantic validation."""
    pass


# ==============================================================================
# Tool Definition Contract
# ==============================================================================


@dataclass
class ToolDefinition:
    """Encapsulates a single approved tool."""
    name: str
    description: str
    category: ToolCategory
    input_model: Type[BaseModel]
    output_model: Type[BaseModel]
    handler: Callable[[Any, Optional[ToolExecutionContext]], Any]
    requires_scope_check: bool = False


# ==============================================================================
# Tool Registry
# ==============================================================================


class ToolRegistry:
    """Central registry of approved security tools for AI agents.

    Guarantees:
    - Explicit allowlist only. Unknown tools are rejected immediately.
    - Strict Pydantic argument parsing and validation prior to dispatch.
    - Automatic ScopeGuard and RequestExecutor integration.
    - Zero arbitrary function, command, or shell execution.
    - Emits structured lifecycle events for streaming to the dashboard.
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        session_manager: Optional[Any] = None,
        website_tools: Optional[WebsiteTools] = None,
        authorization_tools: Optional[AuthorizationTools] = None,
        source_tools: Optional[SourceTools] = None,
        report_tools: Optional[ReportTools] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor or RequestExecutor(scope_guard=self.scope_guard)
        self.session_manager = session_manager

        # Domain tool providers
        self.website_tools = website_tools or WebsiteTools(
            scope_guard=self.scope_guard,
            executor=self.executor
        )
        self.authorization_tools = authorization_tools or AuthorizationTools(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
            executor=self.executor
        )
        self.source_tools = source_tools or SourceTools()
        self.report_tools = report_tools or ReportTools()

        self._tools: Dict[str, ToolDefinition] = {}
        self._event_listeners: List[Callable[[ToolEventBase], None]] = []

        # Register standard approved tool suite
        self._register_default_tools()

    # --------------------------------------------------------------------------
    # Registration & Discovery
    # --------------------------------------------------------------------------

    def register_tool(self, tool: ToolDefinition) -> None:
        """Registers an approved tool definition."""
        if not tool.name or not tool.name.strip():
            raise InvalidDataError("Tool name cannot be empty.")
        self._tools[tool.name.strip()] = tool
        logger.debug("Registered tool: %s (%s)", tool.name, tool.category.value)

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Retrieves a registered tool definition by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered tools."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category.value,
                "input_schema": t.input_model.model_json_schema(),
                "output_schema": t.output_model.model_json_schema(),
                "requires_scope_check": t.requires_scope_check
            }
            for t in self._tools.values()
        ]

    def add_event_listener(self, listener: Callable[[ToolEventBase], None]) -> None:
        """Subscribes an event listener for streaming lifecycle notifications."""
        self._event_listeners.append(listener)

    def _emit_event(self, event: ToolEventBase) -> None:
        """Dispatches an event to all subscribed listeners safely."""
        for listener in self._event_listeners:
            try:
                listener(event)
            except Exception as e:
                logger.warning("Event listener error: %s", str(e))

    # --------------------------------------------------------------------------
    # Validation & Execution
    # --------------------------------------------------------------------------

    def validate_tool_call(
        self,
        name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[BaseModel]]:
        """Validates tool existence and argument types against its Pydantic schema."""
        tool = self.get_tool(name)
        if not tool:
            return False, f"Unknown tool: '{name}'. Tool is not in approved allowlist.", None

        try:
            parsed_args = tool.input_model.model_validate(arguments)
            return True, None, parsed_args
        except ValidationError as val_err:
            return False, f"Argument validation failed: {str(val_err)}", None

    def execute_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        context: Optional[ToolExecutionContext] = None
    ) -> ToolExecutionResult:
        """Executes an approved tool with validation, scope checks, and timing."""
        ctx = context or ToolExecutionContext()
        start_time = time.time()

        tool = self.get_tool(name)
        if not tool:
            duration_ms = (time.time() - start_time) * 1000.0
            error_msg = f"Unknown tool: '{name}'. Access denied."
            self._emit_event(
                ToolFailedEvent(
                    tool_name=name,
                    execution_id=ctx.request_id,
                    duration_ms=round(duration_ms, 2),
                    error=error_msg,
                    status=ToolExecutionStatus.PERMISSION_DENIED
                )
            )
            return ToolExecutionResult(
                tool_name=name,
                execution_id=ctx.request_id,
                status=ToolExecutionStatus.PERMISSION_DENIED,
                duration_ms=round(duration_ms, 2),
                error=error_msg
            )

        # Validate arguments against Pydantic schema
        is_valid, val_error, parsed_args = self.validate_tool_call(name, arguments)
        if not is_valid or parsed_args is None:
            duration_ms = (time.time() - start_time) * 1000.0
            self._emit_event(
                ToolFailedEvent(
                    tool_name=name,
                    execution_id=ctx.request_id,
                    duration_ms=round(duration_ms, 2),
                    error=val_error or "Invalid arguments.",
                    status=ToolExecutionStatus.VALIDATION_ERROR
                )
            )
            return ToolExecutionResult(
                tool_name=name,
                execution_id=ctx.request_id,
                status=ToolExecutionStatus.VALIDATION_ERROR,
                duration_ms=round(duration_ms, 2),
                error=val_error
            )

        # Emit Started Event
        self._emit_event(
            ToolStartedEvent(
                tool_name=name,
                execution_id=ctx.request_id,
                arguments=arguments
            )
        )

        try:
            # Execute the tool's handler
            raw_output = tool.handler(parsed_args, ctx)
            duration_ms = (time.time() - start_time) * 1000.0

            # Convert output to dict
            output_dict = raw_output.model_dump() if hasattr(raw_output, "model_dump") else dict(raw_output)

            # Emit Completed Event
            self._emit_event(
                ToolCompletedEvent(
                    tool_name=name,
                    execution_id=ctx.request_id,
                    duration_ms=round(duration_ms, 2),
                    summary=f"Tool '{name}' completed successfully."
                )
            )

            # Special hook for evidence validation events
            if name == "validate_evidence" and isinstance(output_dict, dict):
                self._emit_event(
                    EvidenceValidatedEvent(
                        tool_name=name,
                        execution_id=ctx.request_id,
                        finding_id=output_dict.get("finding_id", "unknown"),
                        validation_status=output_dict.get("validation_status", "UNKNOWN"),
                        is_confirmed=output_dict.get("is_valid", False)
                    )
                )

            return ToolExecutionResult(
                tool_name=name,
                execution_id=ctx.request_id,
                status=ToolExecutionStatus.SUCCESS,
                duration_ms=round(duration_ms, 2),
                data=output_dict
            )

        except (ScopeViolationError, InvalidTargetURLError, UnsupportedMethodError) as scope_err:
            duration_ms = (time.time() - start_time) * 1000.0
            error_msg = f"Scope violation: {str(scope_err)}"
            self._emit_event(
                ToolFailedEvent(
                    tool_name=name,
                    execution_id=ctx.request_id,
                    duration_ms=round(duration_ms, 2),
                    error=error_msg,
                    status=ToolExecutionStatus.SCOPE_VIOLATION
                )
            )
            return ToolExecutionResult(
                tool_name=name,
                execution_id=ctx.request_id,
                status=ToolExecutionStatus.SCOPE_VIOLATION,
                duration_ms=round(duration_ms, 2),
                error=error_msg
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000.0
            error_msg = f"Tool execution failed: {str(e)}"
            self._emit_event(
                ToolFailedEvent(
                    tool_name=name,
                    execution_id=ctx.request_id,
                    duration_ms=round(duration_ms, 2),
                    error=error_msg,
                    status=ToolExecutionStatus.FAILED
                )
            )
            return ToolExecutionResult(
                tool_name=name,
                execution_id=ctx.request_id,
                status=ToolExecutionStatus.FAILED,
                duration_ms=round(duration_ms, 2),
                error=error_msg
            )

    # --------------------------------------------------------------------------
    # AI Declarations Export (Anthropic / Gemini Format)
    # --------------------------------------------------------------------------

    def get_anthropic_declarations(self) -> List[Dict[str, Any]]:
        """Exports approved tools as Anthropic / Claude tool definitions."""
        declarations = []
        for tool in self._tools.values():
            declarations.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_model.model_json_schema()
            })
        return declarations

    def get_gemini_declarations(self) -> List[Dict[str, Any]]:
        """Exports approved tools as Gemini Function Declarations."""
        declarations = []
        for tool in self._tools.values():
            schema = tool.input_model.model_json_schema()
            # Gemini function declarations expect 'parameters'
            declarations.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": schema
            })
        return declarations

    def _handle_plan_attack_chains(
        self,
        payload: PlanAttackChainsInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> PlanAttackChainsOutput:
        """Plans only over persisted endpoints for the caller's active scan session."""
        assessment_id = context.session_id if context else None
        if not assessment_id:
            raise InvalidDataError("An active assessment session is required to plan attack chains.")
        session = self.report_tools.repository.get_scan_session(assessment_id)
        if session is None:
            raise InvalidDataError("The active assessment session was not found.")
        endpoints = self.report_tools.repository.list_discovered_endpoints(assessment_id)
        from backend.agent.attack_chain import AttackChainPlanner

        plan = AttackChainPlanner().plan(
            endpoints,
            max_steps=payload.max_steps,
            max_candidates=payload.max_candidates,
        )
        return PlanAttackChainsOutput(assessment_id=assessment_id, plan=plan)

    # --------------------------------------------------------------------------
    # Default Tool Registration
    # --------------------------------------------------------------------------

    def _register_default_tools(self) -> None:
        """Registers all built-in approved security tools."""
        # 1. Website Assessment Tools
        self.register_tool(
            ToolDefinition(
                name="validate_target",
                description="Verifies whether a given URL is strictly within the authorized target allowlist.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=ValidateTargetInput,
                output_model=ValidateTargetOutput,
                handler=lambda args, ctx: self.website_tools.validate_target(args, ctx),
                requires_scope_check=True
            )
        )
        # Compatibility alias for check_scope
        self.register_tool(
            ToolDefinition(
                name="check_scope",
                description="Alias for validate_target: checks if URL is within allowed target scope.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=ValidateTargetInput,
                output_model=ValidateTargetOutput,
                handler=lambda args, ctx: self.website_tools.validate_target(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="discover_endpoints",
                description="Discovers attack surface routes and endpoint metadata on authorized target.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=DiscoverEndpointsInput,
                output_model=DiscoverEndpointsOutput,
                handler=lambda args, ctx: self.website_tools.discover_endpoints(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="plan_attack_chains",
                description="Builds ranked, unverified authorization chain candidates from endpoints discovered in the active assessment. Does not authorize or execute requests.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=PlanAttackChainsInput,
                output_model=PlanAttackChainsOutput,
                handler=self._handle_plan_attack_chains,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="inspect_endpoint",
                description="Safely inspects an authorized endpoint using non-destructive GET/HEAD requests.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=InspectEndpointInput,
                output_model=InspectEndpointOutput,
                handler=lambda args, ctx: self.website_tools.inspect_endpoint(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="analyze_response",
                description="Analyzes response status, body, and headers to evaluate access behavior.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=AnalyzeResponseInput,
                output_model=AnalyzeResponseOutput,
                handler=lambda args, ctx: self.website_tools.analyze_response(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="check_http_methods",
                description="Determines permitted HTTP methods on an authorized URL adhering to read-only policy.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckHttpMethodsInput,
                output_model=CheckHttpMethodsOutput,
                handler=lambda args, ctx: self.website_tools.check_http_methods(args, ctx),
                requires_scope_check=True
            )
        )

        self.register_tool(
            ToolDefinition(
                name="check_authentication_weaknesses",
                description="Inspects endpoints for unauthenticated access, verbose error leaks, or auth inconsistencies.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckAuthWeaknessesInput,
                output_model=CheckAuthWeaknessesOutput,
                handler=lambda args, ctx: self.website_tools.check_authentication_weaknesses(args, ctx),
                requires_scope_check=True,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="check_session_security",
                description="Inspects cookie flags (HttpOnly, Secure, SameSite, lifetime) and session token leakage.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckSessionSecurityInput,
                output_model=CheckSessionSecurityOutput,
                handler=lambda args, ctx: self.website_tools.check_session_security(args, ctx),
                requires_scope_check=True,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="check_security_headers",
                description="Evaluates presence and adequacy of key HTTP security headers (CSP, HSTS, frame protection, etc.).",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckSecurityHeadersInput,
                output_model=CheckSecurityHeadersOutput,
                handler=lambda args, ctx: self.website_tools.check_security_headers(args, ctx),
                requires_scope_check=True,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="check_cors_misconfiguration",
                description="Evaluates Cross-Origin Resource Sharing headers for unsafe credentialed trust combinations.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckCorsInput,
                output_model=CheckCorsOutput,
                handler=lambda args, ctx: self.website_tools.check_cors_misconfiguration(args, ctx),
                requires_scope_check=True,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="check_transport_security",
                description="Evaluates HTTPS availability, HTTP-to-HTTPS redirect, HSTS, and mixed content references.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=CheckTransportSecurityInput,
                output_model=CheckTransportSecurityOutput,
                handler=lambda args, ctx: self.website_tools.check_transport_security(args, ctx),
                requires_scope_check=True,
            )
        )
        self.register_tool(
            ToolDefinition(
                name="run_security_misconfiguration_scan",
                description="Runs comprehensive Sprint 2 defensive security checks on an endpoint.",
                category=ToolCategory.WEBSITE_ASSESSMENT,
                input_model=RunMisconfigurationScanInput,
                output_model=RunMisconfigurationScanOutput,
                handler=lambda args, ctx: self.website_tools.run_security_misconfiguration_scan(args, ctx),
                requires_scope_check=True,
            )
        )

        # 2. Authorization Testing Tools
        self.register_tool(
            ToolDefinition(
                name="compare_endpoint_access",
                description="Executes multi-role authorization-differential testing on an endpoint.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=CompareEndpointAccessInput,
                output_model=CompareEndpointAccessOutput,
                handler=lambda args, ctx: self.authorization_tools.compare_endpoint_access(args, ctx),
                requires_scope_check=True
            )
        )
        # Compatibility alias for compare_access
        self.register_tool(
            ToolDefinition(
                name="compare_access",
                description="Alias for compare_endpoint_access: multi-role authorization probe.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=CompareEndpointAccessInput,
                output_model=CompareEndpointAccessOutput,
                handler=lambda args, ctx: self.authorization_tools.compare_endpoint_access(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="test_access_control",
                description="Tests access control on an endpoint for a single role.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=TestAccessControlInput,
                output_model=TestAccessControlOutput,
                handler=lambda args, ctx: self.authorization_tools.test_access_control(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="detect_idor",
                description="Verifies whether an attacker role can access another user's private resource (BOLA/IDOR).",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=DetectIdorInput,
                output_model=DetectIdorOutput,
                handler=lambda args, ctx: self.authorization_tools.detect_idor(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="test_bfla",
                description="Tests Broken Function Level Authorization against an administrative route across roles.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=TestBflaInput,
                output_model=TestBflaOutput,
                handler=lambda args, ctx: self.authorization_tools.test_bfla(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="compare_authorization",
                description="Canonical alias for compare_endpoint_access: multi-role authorization testing.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=CompareEndpointAccessInput,
                output_model=CompareEndpointAccessOutput,
                handler=lambda args, ctx: self.authorization_tools.compare_endpoint_access(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="test_four_role_access",
                description="Executes four-role authorization-differential testing across Anonymous, User A, User B, and Admin.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=CompareEndpointAccessInput,
                output_model=CompareEndpointAccessOutput,
                handler=lambda args, ctx: self.authorization_tools.compare_endpoint_access(args, ctx),
                requires_scope_check=True
            )
        )
        self.register_tool(
            ToolDefinition(
                name="test_unauthorized_modification",
                description="Tests whether an unauthorized role can modify another user's resource using safe non-destructive test fixtures.",
                category=ToolCategory.AUTHORIZATION_TESTING,
                input_model=TestUnauthorizedModificationInput,
                output_model=TestUnauthorizedModificationOutput,
                handler=lambda args, ctx: self.authorization_tools.test_unauthorized_modification(args, ctx),
                requires_scope_check=True
            )
        )

        # 3. Source Analysis Tools
        self.register_tool(
            ToolDefinition(
                name="map_endpoint_to_code",
                description="Correlates a runtime endpoint to its backend source code handler and line numbers.",
                category=ToolCategory.SOURCE_ANALYSIS,
                input_model=MapEndpointToCodeInput,
                output_model=MapEndpointToCodeOutput,
                handler=lambda args, ctx: self.source_tools.map_endpoint_to_code(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="analyze_source_code",
                description="Verifies a static source location against disk, validating snippet and line ranges.",
                category=ToolCategory.SOURCE_ANALYSIS,
                input_model=AnalyzeSourceCodeInput,
                output_model=AnalyzeSourceCodeOutput,
                handler=lambda args, ctx: self.source_tools.analyze_source_code(args, ctx)
            )
        )

        # 4. Reporting Tools
        self.register_tool(
            ToolDefinition(
                name="validate_evidence",
                description="Validates that a finding's evidence artifact is authentic, reproducible, and secret-free.",
                category=ToolCategory.REPORTING,
                input_model=ValidateEvidenceInput,
                output_model=ValidateEvidenceOutput,
                handler=lambda args, ctx: self.report_tools.validate_evidence(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="explain_finding",
                description="Generates finding narrative, technical impact statement, and root cause analysis.",
                category=ToolCategory.REPORTING,
                input_model=ExplainFindingInput,
                output_model=ExplainFindingOutput,
                handler=lambda args, ctx: self.report_tools.explain_finding(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="generate_remediation",
                description="Generates actionable server-side remediation guidance and recommended code patches.",
                category=ToolCategory.REPORTING,
                input_model=GenerateRemediationInput,
                output_model=GenerateRemediationOutput,
                handler=lambda args, ctx: self.report_tools.generate_remediation(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="get_assessment_summary",
                description="Retrieves aggregate metrics, severity breakdown, and confirmed finding counts.",
                category=ToolCategory.REPORTING,
                input_model=GetAssessmentSummaryInput,
                output_model=GetAssessmentSummaryOutput,
                handler=lambda args, ctx: self.report_tools.get_assessment_summary(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="save_finding",
                description="Persists a validated finding and its signed, sanitized evidence artifact to SQLite.",
                category=ToolCategory.REPORTING,
                input_model=SaveFindingInput,
                output_model=SaveFindingOutput,
                handler=lambda args, ctx: self.report_tools.save_finding(args, ctx)
            )
        )
        self.register_tool(
            ToolDefinition(
                name="retest_finding",
                description="Retests an existing finding across roles to verify whether remediation resolved the vulnerability.",
                category=ToolCategory.REPORTING,
                input_model=RetestFindingInput,
                output_model=RetestFindingOutput,
                handler=lambda args, ctx: self.report_tools.retest_finding(args, ctx)
            )
        )
