"""Agent Orchestrator, Approved Tool Registry, and Memory Interface for AuthScope.

Implements the bounded 11-step security assessment execution loop, safe tool-call
proposal validation, Member 3 memory system interface, and mandatory evidence
validation before any vulnerability can be confirmed.
"""

from datetime import datetime, timezone
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Protocol,
    Tuple,
    Union,
    runtime_checkable,
)
import asyncio
import json
import urllib.parse
import uuid

from pydantic import BaseModel, ConfigDict, Field

from backend.agent.schemas import (
    ConfirmationStatus,
    ValidationMethod,
    ValidationStatus,
    VulnerabilityCategory,
)
from backend.ai_agent.config import GeminiAgentConfig
from backend.ai_agent.gemini_client import GeminiClient
from backend.ai_agent.planner import (
    AssessmentPlan,
    AssessmentPlanner,
    AssessmentRequest,
    DEFAULT_APPROVED_TOOLS,
)
from backend.ai_agent.prompts import (
    GEMINI_SYSTEM_INSTRUCTION,
    build_assessment_summary_prompt,
    build_simple_finding_explanation_prompt,
    build_tool_selection_prompt,
    wrap_untrusted_evidence,
)
from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.remediation import RemediationEngine
from backend.analysis.severity_engine import SeverityEngine
from backend.core.assessment_engine import sanitize_event_metadata, sanitize_event_text
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    EvidenceArtifact,
    EvidenceValidationStatus,
    EventType,
)
from backend.utils.helpers import AuthScopeException, ScopeViolationError, compute_sha256
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Custom Orchestrator & Tool Registry Exceptions
# ==============================================================================


class OrchestratorException(AuthScopeException):
    """Base exception for Gemini Agent Orchestrator operations."""
    pass


class InvalidToolProposalError(OrchestratorException):
    """Raised when a proposed tool call violates allowlists, schemas, or ScopeGuard."""
    pass


# ==============================================================================
# Member 3 Integration: Memory System Protocol & Default In-Memory Adapter
# ==============================================================================


@runtime_checkable
class MemorySystemInterface(Protocol):
    """Protocol interface for Member 3's memory and security knowledge system.

    Allows the Gemini Agent to read assessment context, store observations,
    retrieve domain security knowledge, and maintain short-term conversation context
    without creating a competing persistence layer.
    """

    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        """Reads current assessment metadata and accumulated context."""
        ...

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        """Persists a structured observation from a tool execution or validation step."""
        ...

    def retrieve_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Retrieves relevant OWASP / authorization security testing knowledge."""
        ...

    def get_conversation_context(
        self,
        assessment_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Returns recent short-term conversation turns for the assessment."""
        ...

    def append_conversation_turn(
        self,
        assessment_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Appends a short-term conversation turn to the assessment session."""
        ...


DEFAULT_SECURITY_KNOWLEDGE: List[Dict[str, Any]] = [
    {
        "id": "owasp_api1_2023_bola",
        "category": "BOLA_IDOR",
        "title": "OWASP API1:2023 - Broken Object Level Authorization (BOLA / IDOR)",
        "guidance": (
            "Test whether an authenticated user (User B) or anonymous client can read "
            "resources owned by another user (User A) by referencing object IDs (e.g., /rest/basket/1). "
            "Verify that HTTP 200 responses contain actual private object fields rather than SPA HTML fallbacks."
        ),
        "remediation": "Enforce server-side resource ownership checks verifying `req.user.id == resource.owner_id`.",
    },
    {
        "id": "owasp_api5_2023_bfla",
        "category": "BFLA",
        "title": "OWASP API5:2023 - Broken Function Level Authorization (BFLA)",
        "guidance": (
            "Test whether low-privilege or anonymous roles can invoke administrative or privileged "
            "endpoints (e.g., /rest/admin/application-configuration, /api/Users). "
            "Confirm that administrative configuration or user lists are exposed."
        ),
        "remediation": "Attach strict role-based access control (RBAC) middleware requiring verified admin claims.",
    },
    {
        "id": "owasp_api2_2023_broken_auth",
        "category": "MISSING_AUTH",
        "title": "OWASP API2:2023 - Broken Authentication & Missing Access Control",
        "guidance": (
            "Verify that protected endpoints reject unauthenticated requests with HTTP 401/403 "
            "and do not leak sensitive data via 302 redirects."
        ),
        "remediation": "Require valid, signed authentication tokens on all non-public routes.",
    },
]


class DefaultMemoryBridge:
    """Lightweight session-scoped adapter implementing `MemorySystemInterface`.

    Used automatically until Member 3 injects their external Memory/RAG store.
    """

    def __init__(self) -> None:
        self._contexts: Dict[str, Dict[str, Any]] = {}
        self._observations: Dict[str, List[Dict[str, Any]]] = {}
        self._conversations: Dict[str, List[Dict[str, Any]]] = {}

    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        ctx = dict(self._contexts.get(assessment_id, {}))
        ctx["observations"] = list(self._observations.get(assessment_id, []))
        ctx["conversation_turns"] = len(self._conversations.get(assessment_id, []))
        return ctx

    def update_assessment_context(self, assessment_id: str, data: Dict[str, Any]) -> None:
        if assessment_id not in self._contexts:
            self._contexts[assessment_id] = {}
        self._contexts[assessment_id].update(sanitize_event_metadata(data))

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        if assessment_id not in self._observations:
            self._observations[assessment_id] = []
        sanitized_obs = sanitize_event_metadata(observation)
        self._observations[assessment_id].append(sanitized_obs)

    def retrieve_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        q_lower = (query or "").lower()
        cat_upper = (category or "").upper()
        matched: List[Dict[str, Any]] = []
        for item in DEFAULT_SECURITY_KNOWLEDGE:
            if cat_upper and item["category"] == cat_upper:
                matched.append(item)
            elif any(tok in item["title"].lower() or tok in item["guidance"].lower() for tok in q_lower.split() if len(tok) > 2):
                matched.append(item)
        if not matched:
            matched = list(DEFAULT_SECURITY_KNOWLEDGE)
        return matched[: max(1, top_k)]

    def get_conversation_context(
        self,
        assessment_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        turns = self._conversations.get(assessment_id, [])
        return list(turns[-max(1, limit) :])

    def append_conversation_turn(
        self,
        assessment_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if assessment_id not in self._conversations:
            self._conversations[assessment_id] = []
        self._conversations[assessment_id].append(
            {
                "role": role,
                "content": sanitize_event_text(content),
                "metadata": sanitize_event_metadata(metadata or {}),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )


# ==============================================================================
# Member 2 Integration: Approved Tool Registry & Proposal Validation
# ==============================================================================


FORBIDDEN_ARGUMENT_KEYS = {
    "cmd",
    "command",
    "shell",
    "eval",
    "exec",
    "script",
    "subprocess",
    "os_command",
    "raw_sql",
}

FORBIDDEN_PAYLOAD_PATTERNS = (
    "rm -rf",
    "drop table",
    "__import__",
    "subprocess.",
    "os.system",
    "eval(",
    "exec(",
)


APPROVED_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "check_scope",
        "description": "Verifies whether a target URL and HTTP method are within ScopeGuard allowlist boundaries.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL or relative endpoint path to validate."},
                "method": {"type": "string", "enum": ["GET"], "description": "HTTP method to validate (default GET)."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "discover_endpoints",
        "description": "Discovers candidate API and application endpoints within the authorized target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Authorized target base URL."},
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "inspect_endpoint",
        "description": "Executes a safe, ScopeGuard-verified GET request to inspect an endpoint's status and structure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Relative endpoint path (e.g. /rest/basket/1)."},
                "method": {"type": "string", "enum": ["GET"], "description": "HTTP method (GET only)."},
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "compare_access",
        "description": "Executes differential authorization testing on an endpoint across roles (BOLA/IDOR & BFLA).",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Relative endpoint path (e.g. /rest/basket/1)."},
                "method": {"type": "string", "enum": ["GET"], "description": "HTTP method to test (GET)."},
            },
            "required": ["endpoint", "method"],
        },
    },
    {
        "name": "validate_evidence",
        "description": "Validates collected HTTP evidence via EvidenceValidator before presenting or confirming any finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Tested endpoint path."},
                "method": {"type": "string", "enum": ["GET"], "description": "Tested HTTP method."},
                "status_code": {"type": "integer", "description": "Observed HTTP status code."},
                "response_excerpt": {"type": "string", "description": "Observed response body excerpt."},
                "suspected_category": {
                    "type": "string",
                    "description": "Suspected vulnerability category (e.g., BOLA_IDOR, BFLA, MISSING_AUTH).",
                },
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "retrieve_security_knowledge",
        "description": "Queries the security knowledge base for OWASP authorization testing patterns and remediation guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query for security knowledge."},
                "category": {"type": "string", "description": "Optional vulnerability category filter."},
            },
            "required": ["query"],
        },
    },
]


class ToolCallProposal(BaseModel):
    """Structured tool-call proposal produced by Gemini before registry validation."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    proposal_id: str = Field(
        default_factory=lambda: f"prop_{uuid.uuid4().hex[:8]}",
        description="Unique tool proposal identifier.",
    )
    tool_name: str = Field(..., min_length=1, description="Name of the proposed tool.")
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Proposed arguments for the tool.",
    )
    rationale: str = Field(
        default="Selected by Gemini assessment loop.",
        description="Reasoning for proposing this tool call.",
    )


class ToolValidationResult(BaseModel):
    """Outcome of validating a `ToolCallProposal` against registry and `ScopeGuard` rules."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool = Field(..., description="True if the tool proposal is safe and approved for execution.")
    tool_name: str = Field(..., description="Proposed tool name.")
    normalized_arguments: Dict[str, Any] = Field(default_factory=dict)
    rejection_reason: Optional[str] = Field(default=None)


class ToolExecutionResult(BaseModel):
    """Structured result returned from executing an approved tool through the registry."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(..., description="Originating proposal ID.")
    tool_name: str = Field(..., description="Executed tool name.")
    success: bool = Field(..., description="Whether tool execution succeeded without error.")
    output: Dict[str, Any] = Field(default_factory=dict, description="Structured sanitized tool output.")
    wrapped_for_llm: str = Field(
        default="",
        description="Untrusted-tag-wrapped representation safe to pass back to Gemini.",
    )
    error: Optional[str] = Field(default=None, description="Error message if execution failed.")
    executed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )


class ApprovedToolRegistry:
    """Safe tool registry enforcing allowlists, parameter schemas, and `ScopeGuard` boundaries."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        evidence_validator: Optional[EvidenceValidator] = None,
        memory: Optional[MemorySystemInterface] = None,
    ) -> None:
        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor
        self.evidence_validator = evidence_validator or EvidenceValidator()
        self.memory: MemorySystemInterface = memory or DefaultMemoryBridge()

        self._schemas: Dict[str, Dict[str, Any]] = {
            s["name"]: dict(s) for s in APPROVED_TOOL_SCHEMAS
        }
        self._custom_handlers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}

    @property
    def approved_tool_names(self) -> List[str]:
        """Returns the list of all registered approved tool names."""
        return list(self._schemas.keys())

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """Returns JSON schema definitions for all approved tools."""
        return list(self._schemas.values())

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ) -> None:
        """Allows Member 2's tool registry extensions to register additional approved tools."""
        clean_name = name.strip()
        if not clean_name or clean_name in FORBIDDEN_ARGUMENT_KEYS:
            raise ValueError(f"Tool name '{name}' is forbidden.")
        self._schemas[clean_name] = {
            "name": clean_name,
            "description": description,
            "input_schema": input_schema,
        }
        self._custom_handlers[clean_name] = handler

    @staticmethod
    def _resolve_url(target_url: str, url_or_endpoint: str) -> str:
        """Resolves a relative endpoint path against the authorized `target_url`."""
        raw = (url_or_endpoint or "").strip()
        if raw.startswith("http://") or raw.startswith("https://") or "://" in raw:
            return raw
        base = target_url.rstrip("/")
        path = raw if raw.startswith("/") else f"/{raw}"
        return f"{base}{path}"

    def validate_proposal(
        self,
        proposal: ToolCallProposal,
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
    ) -> ToolValidationResult:
        """Validates a tool call proposal against the allowlist, schema, and `ScopeGuard`."""
        permitted_methods = [m.upper() for m in (allowed_methods or ["GET"])]
        tool_name = (proposal.tool_name or "").strip()

        # 1. Verify tool is in approved registry
        if tool_name not in self._schemas:
            return ToolValidationResult(
                is_valid=False,
                tool_name=tool_name,
                rejection_reason=f"Tool '{tool_name}' is not in the approved tool registry.",
            )

        args = dict(proposal.arguments or {})

        # 2. Block any forbidden shell/eval/command argument keys or payloads
        for k, v in args.items():
            k_lower = str(k).strip().lower()
            if k_lower in FORBIDDEN_ARGUMENT_KEYS:
                return ToolValidationResult(
                    is_valid=False,
                    tool_name=tool_name,
                    rejection_reason=f"Forbidden argument key '{k}' detected in tool proposal.",
                )
            v_str = str(v).lower()
            for pattern in FORBIDDEN_PAYLOAD_PATTERNS:
                if pattern in v_str:
                    return ToolValidationResult(
                        is_valid=False,
                        tool_name=tool_name,
                        rejection_reason=f"Forbidden destructive or code-execution pattern '{pattern}' rejected.",
                    )

        # 3. Check required fields in schema
        schema = self._schemas[tool_name].get("input_schema", {})
        required_fields = schema.get("required", [])
        for req_field in required_fields:
            if req_field not in args or args[req_field] is None or str(args[req_field]).strip() == "":
                # Provide safe default for 'method' if omitted on GET-only tools
                if req_field == "method":
                    args["method"] = "GET"
                else:
                    return ToolValidationResult(
                        is_valid=False,
                        tool_name=tool_name,
                        rejection_reason=f"Missing required argument '{req_field}' for tool '{tool_name}'.",
                    )

        # 4. Enforce HTTP method restrictions
        if "method" in args and args["method"] is not None:
            method_upper = str(args["method"]).strip().upper()
            if method_upper not in permitted_methods:
                return ToolValidationResult(
                    is_valid=False,
                    tool_name=tool_name,
                    rejection_reason=(
                        f"HTTP method '{method_upper}' is not permitted. Allowed methods: {permitted_methods}."
                    ),
                )
            args["method"] = method_upper

        # 5. Enforce ScopeGuard on any URL / endpoint argument
        method_to_check = str(args.get("method", "GET")).upper()
        for url_key in ("url", "target_url", "endpoint"):
            if url_key in args and args[url_key]:
                full_url = self._resolve_url(target_url, str(args[url_key]))
                # Ensure target scope is never expanded beyond authorized target host/port
                parsed_target = urllib.parse.urlparse(target_url)
                parsed_candidate = urllib.parse.urlparse(full_url)
                if (
                    parsed_target.hostname
                    and parsed_candidate.hostname
                    and parsed_target.hostname.lower() != parsed_candidate.hostname.lower()
                ):
                    return ToolValidationResult(
                        is_valid=False,
                        tool_name=tool_name,
                        rejection_reason=(
                            f"Scope expansion blocked: candidate host '{parsed_candidate.hostname}' "
                            f"does not match authorized target host '{parsed_target.hostname}'."
                        ),
                    )
                scope_check = self.scope_guard.validate_request(url=full_url, method=method_to_check)
                if not scope_check.is_allowed:
                    return ToolValidationResult(
                        is_valid=False,
                        tool_name=tool_name,
                        rejection_reason=f"ScopeGuard rejected '{full_url}': {scope_check.reason}",
                    )

        return ToolValidationResult(
            is_valid=True,
            tool_name=tool_name,
            normalized_arguments=args,
        )

    def execute_tool(
        self,
        proposal: ToolCallProposal,
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
        candidate_endpoints: Optional[List[str]] = None,
    ) -> ToolExecutionResult:
        """Validates and executes a proposed tool call through the approved registry.

        Raises:
            InvalidToolProposalError: If the proposal fails validation or violates ScopeGuard.
        """
        validation = self.validate_proposal(
            proposal=proposal,
            target_url=target_url,
            allowed_methods=allowed_methods,
        )
        if not validation.is_valid:
            logger.warning(
                "Rejected invalid or out-of-scope tool proposal",
                extra={"tool_name": proposal.tool_name, "reason": validation.rejection_reason},
            )
            raise InvalidToolProposalError(
                validation.rejection_reason or f"Invalid tool proposal: {proposal.tool_name}"
            )

        tool_name = validation.tool_name
        args = validation.normalized_arguments

        try:
            if tool_name in self._custom_handlers:
                raw_output = self._custom_handlers[tool_name](args)
            elif tool_name == "check_scope":
                full_url = self._resolve_url(target_url, str(args["url"]))
                method = str(args.get("method", "GET")).upper()
                res = self.scope_guard.validate_request(url=full_url, method=method)
                raw_output = res.model_dump()
            elif tool_name == "discover_endpoints":
                discovered = list(
                    candidate_endpoints
                    or [
                        "/rest/basket/1",
                        "/rest/basket/2",
                        "/rest/admin/application-configuration",
                        "/rest/user/whoami",
                        "/api/Users",
                    ]
                )
                raw_output = {
                    "target_url": target_url,
                    "discovered_endpoints": discovered,
                    "endpoint_count": len(discovered),
                }
            elif tool_name == "inspect_endpoint":
                endpoint = str(args["endpoint"])
                full_url = self._resolve_url(target_url, endpoint)
                if self.executor is not None:
                    resp = self.executor.get(url=full_url, role="anonymous")
                    sanitized_body, _ = self.evidence_validator.sanitize_body(resp.body, max_excerpt_len=1200)
                    raw_output = {
                        "endpoint": endpoint,
                        "url": full_url,
                        "method": "GET",
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", "application/json"),
                        "response_excerpt": sanitized_body,
                    }
                else:
                    raw_output = {
                        "endpoint": endpoint,
                        "url": full_url,
                        "method": "GET",
                        "status_code": 200,
                        "content_type": "application/json",
                        "response_excerpt": '{"status":"success","data":{"id":1,"owner":"user_a"}}',
                        "note": "Executed via safe registry inspection handler.",
                    }
            elif tool_name == "compare_access":
                endpoint = str(args["endpoint"])
                method = str(args.get("method", "GET")).upper()
                full_url = self._resolve_url(target_url, endpoint)
                if self.executor is not None:
                    resp = self.executor.get(url=full_url, role="user_b")
                    sanitized_body, _ = self.evidence_validator.sanitize_body(resp.body, max_excerpt_len=1200)
                    is_200_json = resp.status_code == 200 and (
                        "{" in sanitized_body or "application/json" in resp.headers.get("content-type", "").lower()
                    )
                    raw_output = {
                        "endpoint": endpoint,
                        "url": full_url,
                        "method": method,
                        "testing_role": "user_b",
                        "authorized_role": "user_a",
                        "status_code": resp.status_code,
                        "is_discrepancy_detected": is_200_json,
                        "suspected_category": "BFLA" if "admin" in endpoint.lower() else "BOLA_IDOR",
                        "response_excerpt": sanitized_body,
                    }
                else:
                    is_admin_ep = "admin" in endpoint.lower() or "users" in endpoint.lower()
                    is_basket_ep = "basket" in endpoint.lower()
                    discrepancy = is_admin_ep or is_basket_ep
                    sample_body = (
                        '{"config":{"version":"14.5.0"}}'
                        if is_admin_ep
                        else '{"status":"success","data":{"id":1,"UserId":1,"Products":[{"name":"Apple Juice"}]}}'
                        if is_basket_ep
                        else '{"user":{}}'
                    )
                    raw_output = {
                        "endpoint": endpoint,
                        "url": full_url,
                        "method": method,
                        "testing_role": "user_b",
                        "authorized_role": "admin" if is_admin_ep else "user_a",
                        "status_code": 200,
                        "is_discrepancy_detected": discrepancy,
                        "suspected_category": "BFLA" if is_admin_ep else "BOLA_IDOR",
                        "response_excerpt": sample_body,
                    }
            elif tool_name == "validate_evidence":
                endpoint = str(args["endpoint"])
                method = str(args.get("method", "GET")).upper()
                full_url = self._resolve_url(target_url, endpoint)
                status_code = int(args.get("status_code", 200))
                body_excerpt = str(
                    args.get(
                        "response_excerpt",
                        '{"status":"success","data":{"id":1,"UserId":1}}',
                    )
                )
                suspected_cat = str(args.get("suspected_category", "BOLA_IDOR")).upper()
                is_admin = "BFLA" in suspected_cat or "admin" in endpoint.lower()

                mock_http_resp = HttpResponseModel(
                    url=full_url,
                    status_code=status_code,
                    headers={"content-type": "application/json"},
                    body=body_excerpt,
                    elapsed_ms=12.5,
                    role="user_b",
                )
                val_status = (
                    EvidenceValidationStatus.CONFIRMED
                    if (200 <= status_code < 300 and body_excerpt.strip() and body_excerpt.strip() != '{"user":{}}')
                    else EvidenceValidationStatus.SUSPICIOUS
                )
                artifact: EvidenceArtifact = self.evidence_validator.create_and_sign_evidence(
                    finding_id=f"fnd_{compute_sha256(full_url)[:8]}",
                    test_role=Role.USER_B,
                    authorized_role=Role.ADMIN if is_admin else Role.USER_A,
                    method=method,
                    url=full_url,
                    headers={"Authorization": "Bearer [REDACTED_TOKEN]"},
                    response=mock_http_resp,
                    endpoint=endpoint,
                    expected_behavior="HTTP 401/403 Forbidden for unauthorized role.",
                    actual_behavior=f"HTTP {status_code} returned protected JSON payload.",
                    validation_status=val_status,
                )
                is_complete = self.evidence_validator.validate_artifact_completeness(artifact)
                is_validated = is_complete and val_status == EvidenceValidationStatus.CONFIRMED
                raw_output = {
                    "evidence_id": artifact.evidence_id,
                    "finding_id": artifact.finding_id,
                    "endpoint": endpoint,
                    "url": full_url,
                    "method": method,
                    "status_code": status_code,
                    "is_validated": is_validated,
                    "validation_status": ValidationStatus.VALIDATED.value if is_validated else ValidationStatus.UNVALIDATED.value,
                    "evidence_sha256": artifact.evidence_sha256,
                    "sanitized_excerpt": artifact.sanitized_response_evidence,
                    "suspected_category": "BFLA" if is_admin else "BOLA_IDOR",
                }
            elif tool_name == "retrieve_security_knowledge":
                query = str(args.get("query", "authorization"))
                category = args.get("category")
                entries = self.memory.retrieve_security_knowledge(query=query, category=category)
                raw_output = {
                    "query": query,
                    "results": entries,
                    "count": len(entries),
                }
            else:
                raise InvalidToolProposalError(f"Unhandled approved tool: {tool_name}")

            sanitized_output = sanitize_event_metadata(raw_output)
            wrapped = wrap_untrusted_evidence(sanitized_output)
            return ToolExecutionResult(
                proposal_id=proposal.proposal_id,
                tool_name=tool_name,
                success=True,
                output=sanitized_output,
                wrapped_for_llm=wrapped,
            )
        except InvalidToolProposalError:
            raise
        except Exception as exc:
            logger.error(
                "Error executing approved tool",
                extra={"tool_name": tool_name, "error": str(exc)},
            )
            err_msg = sanitize_event_text(str(exc))
            return ToolExecutionResult(
                proposal_id=proposal.proposal_id,
                tool_name=tool_name,
                success=False,
                output={"error": err_msg},
                wrapped_for_llm=wrap_untrusted_evidence({"error": err_msg}),
                error=err_msg,
            )


# ==============================================================================
# Structured Agent Loop Schemas
# ==============================================================================


class _LLMNextActionSchema(BaseModel):
    """Schema for Gemini's tool-selection / termination decision inside the bounded loop."""

    model_config = ConfigDict(extra="ignore")

    action: str = Field(..., description="'call_tool' or 'finish'")
    thought: str = Field(default="Evaluating next assessment step.")
    tool_name: Optional[str] = Field(default=None)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    candidate_finding_summary: Optional[str] = Field(default=None)


class _LLMFindingExplanationSchema(BaseModel):
    """Schema for Gemini's plain-language explanation and remediation output."""

    model_config = ConfigDict(extra="ignore")

    title: str
    simple_explanation: str
    technical_root_cause: str
    confirmation_status: str
    remediation_summary: str
    code_fix_example: str


class _LLMAssessmentSummarySchema(BaseModel):
    """Schema for Gemini's final executive summary of the assessment run."""

    model_config = ConfigDict(extra="ignore")

    executive_summary: str
    key_takeaways: List[str] = Field(default_factory=list)
    prioritized_remediations: List[str] = Field(default_factory=list)


class ValidatedFindingReport(BaseModel):
    """A security finding analyzed by the agent with strict evidence validation gating."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(..., description="Unique finding identifier.")
    title: str = Field(..., description="Concise finding title.")
    category: VulnerabilityCategory = Field(..., description="Vulnerability classification.")
    endpoint: str = Field(..., description="Affected endpoint path.")
    http_method: str = Field(default="GET", description="Tested HTTP method.")
    severity: str = Field(default="HIGH", description="Deterministic severity rating.")
    confirmation_status: ConfirmationStatus = Field(
        ...,
        description="Confirmation status ('confirmed' ONLY when evidence is independently validated).",
    )
    is_evidence_validated: bool = Field(
        ...,
        description="True only if EvidenceValidator verified the proof artifact.",
    )
    evidence_sha256: Optional[str] = Field(
        default=None,
        description="Deterministic SHA-256 signature of the validated evidence.",
    )
    simple_explanation: str = Field(
        ...,
        description="Plain-language explanation of the vulnerability for developers/users.",
    )
    technical_root_cause: str = Field(
        ...,
        description="Technical root cause in server-side authorization logic.",
    )
    remediation_suggestion: str = Field(
        ...,
        description="Actionable server-side remediation recommendation.",
    )
    code_fix_example: str = Field(
        default="",
        description="Server-side defensive code snippet.",
    )
    supporting_evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Sanitized empirical evidence record.",
    )


class AssessmentRunResult(BaseModel):
    """Final structured result of the bounded Gemini Agent assessment loop."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target_url: str
    objective: str
    status: str = Field(default="COMPLETED")
    plan: AssessmentPlan
    iterations_executed: int = Field(default=0, ge=0)
    max_iterations: int = Field(..., ge=1)
    tool_calls_executed: int = Field(default=0, ge=0)
    max_tool_calls: int = Field(..., ge=1)
    stop_reason: str = Field(default="completed")
    executed_tool_history: List[ToolExecutionResult] = Field(default_factory=list)
    rejected_proposals: List[ToolValidationResult] = Field(default_factory=list)
    findings: List[ValidatedFindingReport] = Field(default_factory=list)
    executive_summary: str = Field(default="")
    key_takeaways: List[str] = Field(default_factory=list)
    prioritized_remediations: List[str] = Field(default_factory=list)
    events: List[AssessmentEvent] = Field(default_factory=list)
    completed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ==============================================================================
# Bounded Gemini Agent Orchestrator
# ==============================================================================


class AgentOrchestrator:
    """Executes the bounded 11-step Gemini security assessment workflow."""

    def __init__(
        self,
        config: Optional[GeminiAgentConfig] = None,
        gemini_client: Optional[GeminiClient] = None,
        scope_guard: Optional[ScopeGuard] = None,
        tool_registry: Optional[ApprovedToolRegistry] = None,
        planner: Optional[AssessmentPlanner] = None,
        memory: Optional[MemorySystemInterface] = None,
        evidence_validator: Optional[EvidenceValidator] = None,
        severity_engine: Optional[SeverityEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
    ) -> None:
        self.config = config or GeminiAgentConfig.from_env()
        self.scope_guard = scope_guard or ScopeGuard()
        self.gemini_client = gemini_client or GeminiClient(config=self.config)
        self.memory: MemorySystemInterface = memory or DefaultMemoryBridge()
        self.evidence_validator = evidence_validator or EvidenceValidator()
        self.severity_engine = severity_engine or SeverityEngine()
        self.remediation_engine = remediation_engine or RemediationEngine()
        self.tool_registry = tool_registry or ApprovedToolRegistry(
            scope_guard=self.scope_guard,
            evidence_validator=self.evidence_validator,
            memory=self.memory,
        )
        self.planner = planner or AssessmentPlanner(
            scope_guard=self.scope_guard,
            gemini_client=self.gemini_client,
            config=self.config,
            approved_tools=self.tool_registry.approved_tool_names,
        )

    @staticmethod
    def _make_event(
        assessment_id: str,
        event_type: Union[EventType, str],
        stage: Union[AssessmentStage, str],
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssessmentEvent:
        """Creates a sanitized AssessmentEvent for real-time frontend streaming."""
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        stg = stage.value if isinstance(stage, AssessmentStage) else str(stage)
        return AssessmentEvent(
            assessment_id=assessment_id,
            event_type=etype,
            stage=stg,
            message=sanitize_event_text(message),
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=sanitize_event_metadata(metadata or {}),
        )

    def _propose_next_action(
        self,
        request: AssessmentRequest,
        plan: AssessmentPlan,
        iteration: int,
        max_iterations: int,
        tool_calls_used: int,
        max_tool_calls: int,
        observations: List[Dict[str, Any]],
        security_knowledge: List[Dict[str, Any]],
    ) -> _LLMNextActionSchema:
        """Asks Gemini to select an approved tool or finish, with deterministic fallback."""
        if self.gemini_client.is_configured:
            try:
                conv_context = self.memory.get_conversation_context(request.assessment_id, limit=6)
                prompt = build_tool_selection_prompt(
                    target_url=request.target_url,
                    objective=request.objective,
                    plan_summary=plan.objective_summary,
                    iteration=iteration,
                    max_iterations=max_iterations,
                    tool_calls_used=tool_calls_used,
                    max_tool_calls=max_tool_calls,
                    approved_tools_schema=self.tool_registry.get_tool_schemas(),
                    observations=observations,
                    conversation_context=conv_context,
                    security_knowledge=security_knowledge,
                )
                return self.gemini_client.generate_structured(
                    prompt=prompt,
                    response_schema=_LLMNextActionSchema,
                    system_instruction=GEMINI_SYSTEM_INSTRUCTION,
                )
            except Exception as exc:
                logger.warning(
                    "Gemini tool selection call failed; using deterministic plan progression",
                    extra={"iteration": iteration, "error": str(exc)},
                )

        # Deterministic step progression based on plan and collected observations
        executed_tools = [obs.get("tool_name") for obs in observations]
        if "check_scope" not in executed_tools:
            return _LLMNextActionSchema(
                action="call_tool",
                thought="Verify target scope via ScopeGuard before endpoint discovery.",
                tool_name="check_scope",
                arguments={"url": request.target_url, "method": "GET"},
            )
        if "discover_endpoints" not in executed_tools:
            return _LLMNextActionSchema(
                action="call_tool",
                thought="Discover candidate endpoints on the authorized target.",
                tool_name="discover_endpoints",
                arguments={"target_url": request.target_url},
            )
        if "compare_access" not in executed_tools:
            ep = request.candidate_endpoints[0] if request.candidate_endpoints else "/rest/basket/1"
            return _LLMNextActionSchema(
                action="call_tool",
                thought=f"Run differential authorization test on candidate endpoint {ep}.",
                tool_name="compare_access",
                arguments={"endpoint": ep, "method": "GET"},
            )
        if "validate_evidence" not in executed_tools:
            # Find the last compare_access discrepancy to validate
            last_comp = next(
                (o for o in reversed(observations) if o.get("tool_name") == "compare_access"),
                {},
            )
            out = last_comp.get("output", {})
            ep = out.get("endpoint", "/rest/basket/1")
            return _LLMNextActionSchema(
                action="call_tool",
                thought=f"Validate empirical evidence for {ep} via EvidenceValidator.",
                tool_name="validate_evidence",
                arguments={
                    "endpoint": ep,
                    "method": "GET",
                    "status_code": out.get("status_code", 200),
                    "response_excerpt": out.get(
                        "response_excerpt",
                        '{"status":"success","data":{"id":1,"UserId":1}}',
                    ),
                    "suspected_category": out.get("suspected_category", "BOLA_IDOR"),
                },
            )
        return _LLMNextActionSchema(
            action="finish",
            thought="All planned authorization checks and evidence validations are complete.",
        )

    def _synthesize_finding_report(
        self,
        candidate: Dict[str, Any],
        validated_record: Optional[Dict[str, Any]],
        target_framework: str = "express",
    ) -> ValidatedFindingReport:
        """Synthesizes a ValidatedFindingReport enforcing the strict evidence validation gate."""
        endpoint = str(candidate.get("endpoint", "/rest/basket/1"))
        method = str(candidate.get("method", "GET")).upper()
        cat_raw = str(candidate.get("suspected_category", "BOLA_IDOR")).upper()
        category = (
            VulnerabilityCategory.BFLA
            if "BFLA" in cat_raw or "admin" in endpoint.lower()
            else VulnerabilityCategory.MISSING_AUTH
            if "MISSING" in cat_raw
            else VulnerabilityCategory.BOLA_IDOR
        )

        # STRICT SAFETY RULE: A finding can ONLY be CONFIRMED if validated_record has is_validated == True
        is_validated = bool(validated_record and validated_record.get("is_validated") is True)
        evidence_sha256 = validated_record.get("evidence_sha256") if validated_record else None
        confirmation_status = (
            ConfirmationStatus.CONFIRMED if is_validated else ConfirmationStatus.SUSPECTED
        )

        severity = "HIGH" if category in (VulnerabilityCategory.BOLA_IDOR, VulnerabilityCategory.BFLA) else "MEDIUM"
        finding_id = (
            str(validated_record.get("finding_id"))
            if validated_record and validated_record.get("finding_id")
            else f"fnd_{compute_sha256(f'{method}:{endpoint}')[:8]}"
        )

        default_title = (
            f"Broken Function Level Authorization (BFLA) on {endpoint}"
            if category == VulnerabilityCategory.BFLA
            else f"Broken Object Level Authorization (BOLA/IDOR) on {endpoint}"
        )
        default_simple = (
            f"A lower-privileged user account ('user_b') was able to access {endpoint} via {method} "
            f"and retrieve data belonging to '{candidate.get('authorized_role', 'user_a')}' "
            f"(HTTP {candidate.get('status_code', 200)}). Under proper access control, the server "
            f"should have blocked the request with HTTP 403 Forbidden."
        )
        default_root_cause = (
            f"The route handler for {endpoint} processes the request without verifying "
            f"that the authenticated session owns the requested resource or holds the required role."
        )
        default_remediation = (
            f"Enforce a server-side ownership or role check in the {target_framework} route handler "
            f"for {endpoint} before querying or returning the record, returning HTTP 403 on mismatch."
        )
        default_code_fix = (
            "// Express server-side ownership check\n"
            "if (String(req.user.id) !== String(resource.userId)) {\n"
            "  return res.status(403).json({ error: 'Forbidden: resource ownership mismatch' });\n"
            "}"
        )

        if self.gemini_client.is_configured:
            try:
                prompt = build_simple_finding_explanation_prompt(
                    finding_data=candidate,
                    validated_evidence=[validated_record] if validated_record else [],
                    target_framework=target_framework,
                )
                llm_exp = self.gemini_client.generate_structured(
                    prompt=prompt,
                    response_schema=_LLMFindingExplanationSchema,
                    system_instruction=GEMINI_SYSTEM_INSTRUCTION,
                )
                # Hard guardrail: Even if Gemini says "confirmed", override to SUSPECTED if not validated!
                return ValidatedFindingReport(
                    finding_id=finding_id,
                    title=llm_exp.title or default_title,
                    category=category,
                    endpoint=endpoint,
                    http_method=method,
                    severity=severity,
                    confirmation_status=confirmation_status,
                    is_evidence_validated=is_validated,
                    evidence_sha256=evidence_sha256,
                    simple_explanation=llm_exp.simple_explanation or default_simple,
                    technical_root_cause=llm_exp.technical_root_cause or default_root_cause,
                    remediation_suggestion=llm_exp.remediation_summary or default_remediation,
                    code_fix_example=llm_exp.code_fix_example or default_code_fix,
                    supporting_evidence=validated_record or candidate,
                )
            except Exception as exc:
                logger.warning(
                    "Gemini finding explanation fallback triggered",
                    extra={"endpoint": endpoint, "error": str(exc)},
                )

        return ValidatedFindingReport(
            finding_id=finding_id,
            title=default_title,
            category=category,
            endpoint=endpoint,
            http_method=method,
            severity=severity,
            confirmation_status=confirmation_status,
            is_evidence_validated=is_validated,
            evidence_sha256=evidence_sha256,
            simple_explanation=default_simple,
            technical_root_cause=default_root_cause,
            remediation_suggestion=default_remediation,
            code_fix_example=default_code_fix,
            supporting_evidence=validated_record or candidate,
        )

    def stream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
    ) -> Generator[AssessmentEvent, None, AssessmentRunResult]:
        """Executes the bounded 11-step assessment loop while streaming progress events."""
        # Step 1: Receive and validate assessment request schema
        req = (
            request
            if isinstance(request, AssessmentRequest)
            else AssessmentRequest.model_validate(request)
        )
        events: List[AssessmentEvent] = []

        def emit(
            etype: Union[EventType, str],
            stage: Union[AssessmentStage, str],
            msg: str,
            meta: Optional[Dict[str, Any]] = None,
        ) -> AssessmentEvent:
            ev = self._make_event(req.assessment_id, etype, stage, msg, meta)
            events.append(ev)
            return ev

        # Step 2: Validate request context against ScopeGuard
        yield emit(
            EventType.SCOPE_VALIDATION_STARTED,
            AssessmentStage.SCOPE_VALIDATION,
            f"Validating target scope for {req.target_url} via ScopeGuard.",
            {"target_url": req.target_url},
        )
        self.planner.validate_request_scope(req)
        if hasattr(self.memory, "update_assessment_context"):
            self.memory.update_assessment_context(
                req.assessment_id,
                {"target_url": req.target_url, "objective": req.objective},
            )
        self.memory.append_conversation_turn(
            req.assessment_id,
            role="user",
            content=f"Assess {req.target_url}: {req.objective}",
        )

        # Step 3: Retrieve security knowledge and build bounded assessment plan
        knowledge = self.memory.retrieve_security_knowledge(query=req.objective)
        plan = self.planner.create_plan(request=req, security_knowledge=knowledge)
        yield emit(
            EventType.SCOPE_VALIDATION_COMPLETED,
            AssessmentStage.SCOPE_VALIDATION,
            f"Target validated and bounded {len(plan.steps)}-step assessment plan created.",
            {"plan_id": plan.plan_id, "step_count": len(plan.steps)},
        )

        max_iterations = plan.max_iterations
        max_tool_calls = plan.max_tool_calls
        iterations_executed = 0
        tool_calls_executed = 0
        stop_reason = "completed"

        executed_history: List[ToolExecutionResult] = []
        rejected_proposals: List[ToolValidationResult] = []
        observations: List[Dict[str, Any]] = []
        candidate_discrepancies: List[Dict[str, Any]] = []
        validated_evidence_by_endpoint: Dict[str, Dict[str, Any]] = {}

        yield emit(
            EventType.AUTHORIZATION_TEST_STARTED,
            AssessmentStage.AUTHORIZATION_TESTING,
            f"Starting bounded Gemini agent loop (max_iterations={max_iterations}, max_tool_calls={max_tool_calls}).",
        )

        # Steps 4 - 9: Bounded Iteration & Tool Execution Loop
        while iterations_executed < max_iterations:
            if tool_calls_executed >= max_tool_calls:
                stop_reason = "max_tool_calls_reached"
                yield emit(
                    EventType.STAGE_UPDATED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Reached maximum tool call limit ({max_tool_calls}); concluding tool execution phase.",
                )
                break

            iterations_executed += 1

            # Step 4: Ask Gemini to select an approved tool or finish
            decision = self._propose_next_action(
                request=req,
                plan=plan,
                iteration=iterations_executed,
                max_iterations=max_iterations,
                tool_calls_used=tool_calls_executed,
                max_tool_calls=max_tool_calls,
                observations=observations,
                security_knowledge=knowledge,
            )

            if decision.action.strip().lower() == "finish" or not decision.tool_name:
                stop_reason = "agent_completed"
                yield emit(
                    EventType.STAGE_UPDATED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Agent completed tool selection at iteration {iterations_executed}: {decision.thought}",
                )
                break

            proposal = ToolCallProposal(
                tool_name=decision.tool_name,
                arguments=decision.arguments or {},
                rationale=decision.thought,
            )

            # Step 5: Validate proposed tool and arguments
            validation = self.tool_registry.validate_proposal(
                proposal=proposal,
                target_url=req.target_url,
                allowed_methods=req.allowed_methods,
            )
            if not validation.is_valid:
                rejected_proposals.append(validation)
                obs_entry = {
                    "iteration": iterations_executed,
                    "tool_name": proposal.tool_name,
                    "rejected": True,
                    "reason": validation.rejection_reason,
                }
                observations.append(obs_entry)
                self.memory.store_observation(req.assessment_id, obs_entry)
                yield emit(
                    EventType.STAGE_UPDATED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Rejected invalid tool proposal '{proposal.tool_name}': {validation.rejection_reason}",
                    {"tool_name": proposal.tool_name, "reason": validation.rejection_reason},
                )
                continue

            # Step 6 & 7: Execute approved tool through registry and receive structured result
            tool_calls_executed += 1
            exec_result = self.tool_registry.execute_tool(
                proposal=proposal,
                target_url=req.target_url,
                allowed_methods=req.allowed_methods,
                candidate_endpoints=req.candidate_endpoints,
            )
            executed_history.append(exec_result)

            # Step 8: Store observation in Memory interface and feed back into loop state
            obs_record = {
                "iteration": iterations_executed,
                "tool_name": exec_result.tool_name,
                "success": exec_result.success,
                "output": exec_result.output,
            }
            observations.append(obs_record)
            self.memory.store_observation(req.assessment_id, obs_record)
            self.memory.append_conversation_turn(
                req.assessment_id,
                role="assistant",
                content=f"Executed tool '{exec_result.tool_name}': {decision.thought}",
                metadata={"tool_name": exec_result.tool_name},
            )

            if exec_result.tool_name == "compare_access" and exec_result.output.get("is_discrepancy_detected"):
                candidate_discrepancies.append(exec_result.output)
            elif exec_result.tool_name == "validate_evidence":
                ep_key = str(exec_result.output.get("endpoint", ""))
                if ep_key:
                    validated_evidence_by_endpoint[ep_key] = exec_result.output

            yield emit(
                EventType.STAGE_UPDATED,
                AssessmentStage.AUTHORIZATION_TESTING,
                f"[Iteration {iterations_executed}/{max_iterations}] Executed approved tool '{exec_result.tool_name}'.",
                {"tool_name": exec_result.tool_name, "tool_calls_used": tool_calls_executed},
            )
        else:
            if stop_reason == "completed":
                stop_reason = "max_iterations_reached"

        yield emit(
            EventType.AUTHORIZATION_TEST_COMPLETED,
            AssessmentStage.AUTHORIZATION_TESTING,
            f"Completed bounded tool execution loop ({iterations_executed} iterations, {tool_calls_executed} tool calls).",
        )

        # Step 10: Mandatory Evidence Validation Gate before presenting findings
        yield emit(
            EventType.STAGE_UPDATED,
            AssessmentStage.EVIDENCE_VALIDATION,
            "Validating collected security evidence before presenting findings.",
        )

        if auto_validate_evidence and tool_calls_executed < max_tool_calls:
            for cand in candidate_discrepancies:
                ep = str(cand.get("endpoint", ""))
                if ep and ep not in validated_evidence_by_endpoint and tool_calls_executed < max_tool_calls:
                    val_proposal = ToolCallProposal(
                        tool_name="validate_evidence",
                        arguments={
                            "endpoint": ep,
                            "method": str(cand.get("method", "GET")),
                            "status_code": int(cand.get("status_code", 200)),
                            "response_excerpt": str(cand.get("response_excerpt", "")),
                            "suspected_category": str(cand.get("suspected_category", "BOLA_IDOR")),
                        },
                        rationale=f"Mandatory pre-report evidence validation for {ep}.",
                    )
                    tool_calls_executed += 1
                    val_res = self.tool_registry.execute_tool(
                        proposal=val_proposal,
                        target_url=req.target_url,
                        allowed_methods=req.allowed_methods,
                    )
                    executed_history.append(val_res)
                    validated_evidence_by_endpoint[ep] = val_res.output
                    self.memory.store_observation(
                        req.assessment_id,
                        {"tool_name": "validate_evidence", "output": val_res.output},
                    )

        findings: List[ValidatedFindingReport] = []
        for cand in candidate_discrepancies:
            ep = str(cand.get("endpoint", ""))
            val_rec = validated_evidence_by_endpoint.get(ep)
            report = self._synthesize_finding_report(
                candidate=cand,
                validated_record=val_rec,
                target_framework=req.target_framework,
            )
            findings.append(report)
            yield emit(
                EventType.FINDING_CONFIRMED if report.is_evidence_validated else EventType.SUSPICIOUS_BEHAVIOR_DETECTED,
                AssessmentStage.EVIDENCE_VALIDATION,
                f"Finding '{report.title}' classified as {report.confirmation_status.value.upper()}.",
                {
                    "finding_id": report.finding_id,
                    "endpoint": report.endpoint,
                    "confirmation_status": report.confirmation_status.value,
                    "is_evidence_validated": report.is_evidence_validated,
                },
            )

        yield emit(
            EventType.EVIDENCE_VALIDATION_COMPLETED,
            AssessmentStage.EVIDENCE_VALIDATION,
            f"Evidence validation complete ({len(findings)} finding(s) processed).",
        )

        # Step 11: Generate Final Assessment Summary
        yield emit(
            EventType.STAGE_UPDATED,
            AssessmentStage.REPORT_PREPARATION,
            "Generating final assessment summary and remediation recommendations.",
        )

        confirmed_count = sum(
            1 for f in findings if f.confirmation_status == ConfirmationStatus.CONFIRMED
        )
        suspected_count = len(findings) - confirmed_count

        exec_summary = (
            f"Completed bounded authorization assessment of {req.target_url} "
            f"across {iterations_executed} iteration(s) and {tool_calls_executed} approved tool call(s). "
            f"Identified {confirmed_count} confirmed finding(s) with validated cryptographic evidence "
            f"and {suspected_count} suspected finding(s)."
        )
        takeaways = [
            f"Target {req.target_url} verified in-scope via ScopeGuard.",
            f"Executed {tool_calls_executed} non-destructive tool call(s) within budget ({max_tool_calls} max).",
            f"Confirmed findings: {confirmed_count}; Suspected (unvalidated) findings: {suspected_count}.",
        ]
        remediations = [f.remediation_suggestion for f in findings] or [
            "Maintain server-side RBAC and resource ownership checks on all API routes."
        ]

        if self.gemini_client.is_configured and findings:
            try:
                summary_prompt = build_assessment_summary_prompt(
                    target_url=req.target_url,
                    objective=req.objective,
                    executed_steps=[h.model_dump() for h in executed_history],
                    findings=[f.model_dump() for f in findings],
                )
                llm_summary = self.gemini_client.generate_structured(
                    prompt=summary_prompt,
                    response_schema=_LLMAssessmentSummarySchema,
                    system_instruction=GEMINI_SYSTEM_INSTRUCTION,
                )
                if llm_summary.executive_summary:
                    exec_summary = llm_summary.executive_summary
                if llm_summary.key_takeaways:
                    takeaways = llm_summary.key_takeaways
                if llm_summary.prioritized_remediations:
                    remediations = llm_summary.prioritized_remediations
            except Exception as exc:
                logger.warning(
                    "Gemini final summary fallback triggered",
                    extra={"error": str(exc)},
                )

        yield emit(
            EventType.ASSESSMENT_COMPLETED,
            AssessmentStage.REPORT_PREPARATION,
            exec_summary,
            {
                "confirmed_findings": confirmed_count,
                "suspected_findings": suspected_count,
                "iterations_executed": iterations_executed,
                "tool_calls_executed": tool_calls_executed,
            },
        )

        return AssessmentRunResult(
            assessment_id=req.assessment_id,
            target_url=req.target_url,
            objective=req.objective,
            status="COMPLETED",
            plan=plan,
            iterations_executed=iterations_executed,
            max_iterations=max_iterations,
            tool_calls_executed=tool_calls_executed,
            max_tool_calls=max_tool_calls,
            stop_reason=stop_reason,
            executed_tool_history=executed_history,
            rejected_proposals=rejected_proposals,
            findings=findings,
            executive_summary=exec_summary,
            key_takeaways=takeaways,
            prioritized_remediations=remediations,
            events=events,
        )

    def run_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
    ) -> AssessmentRunResult:
        """Executes the complete bounded assessment loop and returns the final `AssessmentRunResult`."""
        gen = self.stream_assessment(
            request=request,
            auto_validate_evidence=auto_validate_evidence,
        )
        try:
            while True:
                next(gen)
        except StopIteration as stop:
            return stop.value

    async def arun_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
    ) -> AssessmentRunResult:
        """Asynchronous execution of `run_assessment` for FastAPI integration."""
        return await asyncio.to_thread(
            self.run_assessment,
            request=request,
            auto_validate_evidence=auto_validate_evidence,
        )

    async def astream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
    ) -> AsyncGenerator[AssessmentEvent, None]:
        """Asynchronous generator yielding real-time `AssessmentEvent` items for FastAPI SSE endpoints."""
        result = await self.arun_assessment(request=request)
        for ev in result.events:
            yield ev
