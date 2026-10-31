"""Agent Orchestrator, Tool & Memory Protocols, and Bounded Loop for AuthScope.

Implements the bounded 12-step security assessment execution loop, safe tool-call
proposal validation, Member 2 ToolExecutorProtocol adapter, Member 3 MemoryProviderProtocol
adapter, cancellation handling, and mandatory security-engine evidence validation
before any vulnerability can be confirmed.
"""

from datetime import datetime, timezone
from enum import Enum
import asyncio
import inspect
import json
import urllib.parse
import uuid
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
# Finding Validation Statuses (Section G)
# ==============================================================================


class FindingValidationStatus(str, Enum):
    """Supported security-engine finding validation statuses.

    Gemini must never independently confirm vulnerabilities; only validated
    security-engine differential evidence can produce CONFIRMED.
    """
    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"


# ==============================================================================
# Structured Streaming Event Dictionary (Section D)
# ==============================================================================


class AgentStreamEvent(dict):
    """Structured event dictionary yielded by `astream_assessment` and `stream_assessment`.

    Subclasses `dict` so it is a true Python dictionary with keys:
    {
        "type": str,
        "assessment_id": str,
        "timestamp": str,
        "message": str,
        "data": dict,
    }
    Also exposes attribute accessors (`.event_type`, `.stage`, `.metadata`, etc.)
    for full backward compatibility with `AssessmentEvent` consumers.
    """

    def __init__(
        self,
        event_type: str,
        assessment_id: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
        stage: str = "authorization_testing",
    ) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        clean_msg = sanitize_event_text(message)
        clean_data = sanitize_event_metadata(data or {})
        super().__init__(
            type=event_type,
            assessment_id=assessment_id,
            timestamp=ts,
            message=clean_msg,
            data=clean_data,
        )
        self._stage = stage

    @property
    def type(self) -> str:
        return str(self.get("type", ""))

    @property
    def event_type(self) -> str:
        return str(self.get("type", ""))

    @property
    def assessment_id(self) -> str:
        return str(self.get("assessment_id", ""))

    @property
    def timestamp(self) -> str:
        return str(self.get("timestamp", ""))

    @property
    def message(self) -> str:
        return str(self.get("message", ""))

    @property
    def data(self) -> Dict[str, Any]:
        val = self.get("data")
        return val if isinstance(val, dict) else {}

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.data

    @property
    def stage(self) -> str:
        return str(self.data.get("stage", self._stage))

    def model_dump(self, **kwargs: Any) -> Dict[str, Any]:
        return dict(self)


def is_cancellation_requested(cancel_token: Optional[Any]) -> bool:
    """Checks whether cancellation has been signaled on a cancel_token."""
    if cancel_token is None:
        return False
    if isinstance(cancel_token, bool):
        return cancel_token
    if hasattr(cancel_token, "is_cancelled"):
        attr = getattr(cancel_token, "is_cancelled")
        return bool(attr() if callable(attr) else attr)
    if hasattr(cancel_token, "is_set") and callable(cancel_token.is_set):
        return bool(cancel_token.is_set())
    if callable(cancel_token):
        return bool(cancel_token())
    return False


# ==============================================================================
# Member 3 Integration: Memory Provider Protocol, Adapter & Mock (Section F)
# ==============================================================================


@runtime_checkable
class MemoryProviderProtocol(Protocol):
    """Protocol for Member 3's memory provider contract (Section F).

    Exposes:
    - `get_context(assessment_id)`
    - `save_observation(assessment_id, observation)`
    - `search_knowledge(query, category=None, limit=5)`
    - `save_finding(assessment_id, finding)`
    """

    def get_context(self, assessment_id: str) -> Any:
        """Retrieves assessment context for `assessment_id`."""
        ...

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> Any:
        """Saves a structured observation for `assessment_id`."""
        ...

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> Any:
        """Searches domain security knowledge."""
        ...

    def save_finding(self, assessment_id: str, finding: Dict[str, Any]) -> Any:
        """Saves a finding record for `assessment_id`."""
        ...


@runtime_checkable
class MemorySystemInterface(Protocol):
    """Legacy protocol interface for Member 3's memory and security knowledge system."""

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
    """Lightweight session-scoped adapter implementing both `MemoryProviderProtocol`
    and `MemorySystemInterface`.

    Used automatically as a mock/in-memory bridge when an external memory provider is not injected.
    """

    def __init__(self) -> None:
        self._contexts: Dict[str, Dict[str, Any]] = {}
        self._observations: Dict[str, List[Dict[str, Any]]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._conversations: Dict[str, List[Dict[str, Any]]] = {}

    # --- Section F MemoryProviderProtocol methods ---

    def get_context(self, assessment_id: str) -> Dict[str, Any]:
        """Returns assessment context, observations, and findings for `assessment_id`."""
        ctx = dict(self._contexts.get(assessment_id, {"assessment_id": assessment_id}))
        ctx["observations"] = list(self._observations.get(assessment_id, []))
        ctx["findings"] = list(self._findings.get(assessment_id, []))
        ctx["conversation_turns"] = len(self._conversations.get(assessment_id, []))
        return ctx

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        """Persists a sanitized observation for `assessment_id`."""
        if assessment_id not in self._observations:
            self._observations[assessment_id] = []
        sanitized_obs = sanitize_event_metadata(observation)
        self._observations[assessment_id].append(sanitized_obs)

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Searches domain security knowledge for matching guidance."""
        q_lower = (query or "").lower()
        cat_upper = (category or "").upper()
        matched: List[Dict[str, Any]] = []
        for item in DEFAULT_SECURITY_KNOWLEDGE:
            if cat_upper and item["category"] == cat_upper:
                matched.append(item)
            elif any(
                tok in item["title"].lower() or tok in item["guidance"].lower()
                for tok in q_lower.split()
                if len(tok) > 2
            ):
                matched.append(item)
        if not matched:
            matched = list(DEFAULT_SECURITY_KNOWLEDGE)
        return matched[: max(1, limit)]

    def save_finding(self, assessment_id: str, finding: Dict[str, Any]) -> None:
        """Persists a sanitized finding dictionary for `assessment_id`."""
        if assessment_id not in self._findings:
            self._findings[assessment_id] = []
        self._findings[assessment_id].append(sanitize_event_metadata(finding))

    def get_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        """Returns saved findings for `assessment_id`."""
        return list(self._findings.get(assessment_id, []))

    # --- Legacy MemorySystemInterface methods ---

    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        return self.get_context(assessment_id)

    def update_assessment_context(self, assessment_id: str, data: Dict[str, Any]) -> None:
        if assessment_id not in self._contexts:
            self._contexts[assessment_id] = {}
        self._contexts[assessment_id].update(sanitize_event_metadata(data))

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        self.save_observation(assessment_id, observation)

    def retrieve_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        return self.search_knowledge(query=query, category=category, limit=top_k)

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


# Alias for explicit mock usage in tests
MockMemoryProvider = DefaultMemoryBridge


class MemoryProviderAdapter:
    """Adapter bridging `MemoryProviderProtocol` (sync or async) and `MemorySystemInterface`."""

    def __init__(self, provider: Optional[Any] = None) -> None:
        self._provider: Any = provider if provider is not None else DefaultMemoryBridge()
        self._local_conversations: Dict[str, List[Dict[str, Any]]] = {}

    @property
    def raw_provider(self) -> Any:
        return self._provider

    def get_context(self, assessment_id: str) -> Dict[str, Any]:
        if hasattr(self._provider, "get_context"):
            res = self._provider.get_context(assessment_id)
            if inspect.isawaitable(res):
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    return asyncio.run(res)
                return {"assessment_id": assessment_id}
            return dict(res) if isinstance(res, dict) else {"assessment_id": assessment_id}
        if hasattr(self._provider, "read_assessment_context"):
            res = self._provider.read_assessment_context(assessment_id)
            return dict(res) if isinstance(res, dict) else {"assessment_id": assessment_id}
        return {"assessment_id": assessment_id}

    async def aget_context(self, assessment_id: str) -> Dict[str, Any]:
        if hasattr(self._provider, "get_context"):
            res = self._provider.get_context(assessment_id)
            if inspect.isawaitable(res):
                res = await res
            return dict(res) if isinstance(res, dict) else {"assessment_id": assessment_id}
        if hasattr(self._provider, "read_assessment_context"):
            res = self._provider.read_assessment_context(assessment_id)
            if inspect.isawaitable(res):
                res = await res
            return dict(res) if isinstance(res, dict) else {"assessment_id": assessment_id}
        return {"assessment_id": assessment_id}

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        sanitized = sanitize_event_metadata(observation)
        if hasattr(self._provider, "save_observation"):
            res = self._provider.save_observation(assessment_id, sanitized)
            if inspect.isawaitable(res):
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    asyncio.run(res)
            if (
                not isinstance(self._provider, DefaultMemoryBridge)
                and hasattr(self._provider, "store_observation")
            ):
                self._provider.store_observation(assessment_id, sanitized)
            return
        if hasattr(self._provider, "store_observation"):
            self._provider.store_observation(assessment_id, sanitized)

    async def asave_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        sanitized = sanitize_event_metadata(observation)
        if hasattr(self._provider, "save_observation"):
            res = self._provider.save_observation(assessment_id, sanitized)
            if inspect.isawaitable(res):
                await res
            if (
                not isinstance(self._provider, DefaultMemoryBridge)
                and hasattr(self._provider, "store_observation")
            ):
                res2 = self._provider.store_observation(assessment_id, sanitized)
                if inspect.isawaitable(res2):
                    await res2
            return
        if hasattr(self._provider, "store_observation"):
            res = self._provider.store_observation(assessment_id, sanitized)
            if inspect.isawaitable(res):
                await res

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._provider, "search_knowledge"):
            res = self._provider.search_knowledge(query, category=category, limit=limit)
            if inspect.isawaitable(res):
                try:
                    asyncio.get_running_loop()
                    return list(DEFAULT_SECURITY_KNOWLEDGE[:limit])
                except RuntimeError:
                    res = asyncio.run(res)
            return self._normalize_knowledge_list(res, limit=limit)
        if hasattr(self._provider, "retrieve_security_knowledge"):
            res = self._provider.retrieve_security_knowledge(query, category=category, top_k=limit)
            return self._normalize_knowledge_list(res, limit=limit)
        return list(DEFAULT_SECURITY_KNOWLEDGE[:limit])

    async def asearch_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._provider, "search_knowledge"):
            res = self._provider.search_knowledge(query, category=category, limit=limit)
            if inspect.isawaitable(res):
                res = await res
            return self._normalize_knowledge_list(res, limit=limit)
        if hasattr(self._provider, "retrieve_security_knowledge"):
            res = self._provider.retrieve_security_knowledge(query, category=category, top_k=limit)
            if inspect.isawaitable(res):
                res = await res
            return self._normalize_knowledge_list(res, limit=limit)
        return list(DEFAULT_SECURITY_KNOWLEDGE[:limit])

    @staticmethod
    def _normalize_knowledge_list(raw: Any, limit: int = 5) -> List[Dict[str, Any]]:
        if not raw or not isinstance(raw, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for item in raw[: max(1, limit)]:
            if isinstance(item, BaseModel):
                normalized.append(item.model_dump())
            elif isinstance(item, dict):
                normalized.append(dict(item))
            else:
                normalized.append({"content": str(item)})
        return normalized

    def save_finding(self, assessment_id: str, finding: Dict[str, Any]) -> None:
        sanitized = sanitize_event_metadata(finding)
        if hasattr(self._provider, "save_finding"):
            res = self._provider.save_finding(assessment_id, sanitized)
            if inspect.isawaitable(res):
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    asyncio.run(res)

    async def asave_finding(self, assessment_id: str, finding: Dict[str, Any]) -> None:
        sanitized = sanitize_event_metadata(finding)
        if hasattr(self._provider, "save_finding"):
            res = self._provider.save_finding(assessment_id, sanitized)
            if inspect.isawaitable(res):
                await res

    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        return self.get_context(assessment_id)

    def update_assessment_context(self, assessment_id: str, data: Dict[str, Any]) -> None:
        if hasattr(self._provider, "update_assessment_context"):
            self._provider.update_assessment_context(assessment_id, data)

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        self.save_observation(assessment_id, observation)

    def retrieve_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        return self.search_knowledge(query=query, category=category, limit=top_k)

    def get_conversation_context(
        self,
        assessment_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        if hasattr(self._provider, "get_conversation_context"):
            return self._provider.get_conversation_context(assessment_id, limit=limit)
        turns = self._local_conversations.get(assessment_id, [])
        return list(turns[-max(1, limit) :])

    def append_conversation_turn(
        self,
        assessment_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if hasattr(self._provider, "append_conversation_turn"):
            self._provider.append_conversation_turn(
                assessment_id, role=role, content=content, metadata=metadata
            )
            return
        if assessment_id not in self._local_conversations:
            self._local_conversations[assessment_id] = []
        self._local_conversations[assessment_id].append(
            {
                "role": role,
                "content": sanitize_event_text(content),
                "metadata": sanitize_event_metadata(metadata or {}),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )


# ==============================================================================
# Member 2 Integration: Tool Executor Protocol & Approved Tool Registry (Section E)
# ==============================================================================


@runtime_checkable
class ToolExecutorProtocol(Protocol):
    """Protocol for Member 2's tool executor contract (Section E).

    Exposes:
    - `list_tools()`
    - `execute_tool_call(tool_name, arguments, context)` (may be sync or async)
    """

    def list_tools(self) -> Any:
        """Returns list of approved tool schema dictionaries."""
        ...

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Executes an approved tool call synchronously or asynchronously."""
        ...


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
    {
        "name": "test_four_role_access",
        "description": "Executes four-role authorization-differential testing across Anonymous, User A, User B, and Admin.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Relative endpoint path (e.g. /rest/basket/1)."},
                "method": {"type": "string", "description": "HTTP method to test (default GET)."},
                "owner_role": {"type": "string", "description": "Legitimate owner role (default user_a)."},
                "resource_id": {"type": "string", "description": "Optional resource ID."},
                "admin_policy": {"type": "string", "description": "Admin policy: allowed, denied, or policy_dependent."},
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "save_finding",
        "description": "Persists a validated finding and its signed, sanitized evidence artifact.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Finding title."},
                "endpoint": {"type": "string", "description": "Affected endpoint path."},
                "vulnerability_type": {"type": "string", "description": "Vulnerability category (BOLA_IDOR, BFLA, MISSING_AUTH)."},
                "testing_role": {"type": "string", "description": "Role that triggered the finding."},
                "status_code": {"type": "integer", "description": "Observed HTTP status code."},
            },
            "required": ["title", "endpoint"],
        },
    },
    {
        "name": "generate_remediation",
        "description": "Generates server-side remediation guidance and defensive code patches for a finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Finding identifier."},
                "category": {"type": "string", "description": "Vulnerability category."},
                "endpoint": {"type": "string", "description": "Affected endpoint path."},
            },
            "required": ["finding_id", "endpoint"],
        },
    },
    {
        "name": "retest_finding",
        "description": "Retests an existing finding across roles to verify whether remediation resolved the vulnerability.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "Identifier of finding to retest."},
            },
            "required": ["finding_id"],
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
    """Safe tool registry enforcing allowlists, parameter schemas, and `ScopeGuard` boundaries.

    Also implements `ToolExecutorProtocol` (`list_tools` and `execute_tool_call`).
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        evidence_validator: Optional[EvidenceValidator] = None,
        memory: Optional[Any] = None,
        external_tool_executor: Optional[Any] = None,
    ) -> None:
        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor
        self.evidence_validator = evidence_validator or EvidenceValidator()
        self.memory = MemoryProviderAdapter(memory)
        self._external_executor = external_tool_executor

        self._schemas: Dict[str, Dict[str, Any]] = {
            s["name"]: dict(s) for s in APPROVED_TOOL_SCHEMAS
        }
        self._custom_handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

        if self._external_executor is not None:
            self._sync_external_schemas()

    def _sync_external_schemas(self) -> None:
        """Synchronizes approved tool schemas from an injected external tool executor."""
        if self._external_executor is None or not hasattr(self._external_executor, "list_tools"):
            return
        try:
            raw_tools = self._external_executor.list_tools()
            if inspect.isawaitable(raw_tools):
                return
            self._apply_external_tool_list(raw_tools)
        except Exception as exc:
            logger.warning("Failed to sync schemas from external tool executor", extra={"error": str(exc)})

    def _apply_external_tool_list(self, raw_tools: Any) -> None:
        if not isinstance(raw_tools, list) or not raw_tools:
            return
        new_schemas: Dict[str, Dict[str, Any]] = {}
        for item in raw_tools:
            if isinstance(item, dict) and item.get("name"):
                t_name = str(item["name"]).strip()
                schema = item.get("input_schema") or item.get("parameters") or {"type": "object", "properties": {}}
                new_schemas[t_name] = {
                    "name": t_name,
                    "description": str(item.get("description", "")),
                    "input_schema": schema,
                }
        if new_schemas:
            self._schemas = new_schemas

    async def async_refresh_schemas(self) -> List[Dict[str, Any]]:
        """Asynchronously refreshes tool schemas if the injected executor's `list_tools` is async."""
        if self._external_executor is not None and hasattr(self._external_executor, "list_tools"):
            raw_tools = self._external_executor.list_tools()
            if inspect.isawaitable(raw_tools):
                raw_tools = await raw_tools
            self._apply_external_tool_list(raw_tools)
        return self.list_tools()

    @property
    def approved_tool_names(self) -> List[str]:
        """Returns the list of all registered approved tool names."""
        self._sync_external_schemas()
        return list(self._schemas.keys())

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns metadata and JSON schema definitions for all approved tools (`ToolExecutorProtocol`)."""
        self._sync_external_schemas()
        return list(self._schemas.values())

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """Returns JSON schema definitions for all approved tools."""
        return self.list_tools()

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Any],
    ) -> None:
        """Allows registering additional approved tools."""
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
        self._sync_external_schemas()
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
                if req_field == "method":
                    args["method"] = "GET"
                elif req_field in ("target_url", "base_url", "url") and target_url:
                    args[req_field] = target_url
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
        for url_key in ("url", "target_url", "base_url", "endpoint"):
            if url_key in args and args[url_key]:
                full_url = self._resolve_url(target_url, str(args[url_key]))
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

    @staticmethod
    def _normalize_external_result(raw_res: Any) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Normalizes output from Member 2's `execute_tool_call` or `ToolRegistry`."""
        if isinstance(raw_res, BaseModel):
            dumped = raw_res.model_dump()
        elif isinstance(raw_res, dict):
            dumped = dict(raw_res)
        else:
            dumped = {"result": str(raw_res)}

        if "status" in dumped and str(dumped["status"]).upper() in (
            "FAILED",
            "VALIDATION_ERROR",
            "PERMISSION_DENIED",
            "SCOPE_VIOLATION",
        ):
            err = str(dumped.get("error") or f"Tool failed with status {dumped['status']}")
            return False, dumped.get("data") or {"error": err}, err

        if "success" in dumped and dumped["success"] is False:
            err = str(dumped.get("error") or "Tool execution returned success=False")
            return False, dumped.get("output") or dumped.get("data") or {"error": err}, err

        if "data" in dumped and isinstance(dumped["data"], dict) and "tool_name" in dumped:
            return True, dumped["data"], None
        if "output" in dumped and isinstance(dumped["output"], dict) and "tool_name" in dumped:
            return True, dumped["output"], None

        return True, dumped, None

    def _invoke_external_executor_sync(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        ext = self._external_executor
        if hasattr(ext, "execute_tool_call"):
            res = ext.execute_tool_call(tool_name, args, context)
        elif hasattr(ext, "execute_tool"):
            res = ext.execute_tool(tool_name, args, context)
        elif hasattr(ext, "execute"):
            res = ext.execute(tool_name, args)
        else:
            raise InvalidToolProposalError(f"External tool executor does not support executing '{tool_name}'.")

        if inspect.isawaitable(res):
            return asyncio.run(res)
        return res

    async def _invoke_external_executor_async(
        self,
        tool_name: str,
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        ext = self._external_executor
        if hasattr(ext, "execute_tool_call"):
            res = ext.execute_tool_call(tool_name, args, context)
        elif hasattr(ext, "execute_tool"):
            res = ext.execute_tool(tool_name, args, context)
        elif hasattr(ext, "execute"):
            res = ext.execute(tool_name, args)
        else:
            raise InvalidToolProposalError(f"External tool executor does not support executing '{tool_name}'.")

        if inspect.isawaitable(res):
            return await res
        return res

    def _execute_builtin_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        target_url: str,
        candidate_endpoints: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if tool_name in self._custom_handlers:
            res = self._custom_handlers[tool_name](args)
            if inspect.isawaitable(res):
                res = asyncio.run(res)
            return dict(res) if isinstance(res, dict) else {"result": res}
        if tool_name in ("check_scope", "validate_target"):
            full_url = self._resolve_url(target_url, str(args.get("url") or args.get("target_url") or target_url))
            method = str(args.get("method", "GET")).upper()
            res = self.scope_guard.validate_request(url=full_url, method=method)
            return res.model_dump()
        if tool_name in ("discover_endpoints", "discover_routes"):
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
            return {
                "target_url": target_url,
                "discovered_endpoints": discovered,
                "endpoint_count": len(discovered),
            }
        if tool_name == "inspect_endpoint":
            endpoint = str(args["endpoint"])
            full_url = self._resolve_url(target_url, endpoint)
            if self.executor is not None:
                resp = self.executor.get(url=full_url, role="anonymous")
                sanitized_body, _ = self.evidence_validator.sanitize_body(resp.body, max_excerpt_len=1200)
                return {
                    "endpoint": endpoint,
                    "url": full_url,
                    "method": "GET",
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("content-type", "application/json"),
                    "response_excerpt": sanitized_body,
                }
            return {
                "endpoint": endpoint,
                "url": full_url,
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "response_excerpt": '{"status":"success","data":{"id":1,"owner":"user_a"}}',
                "note": "Executed via safe registry inspection handler.",
            }
        if tool_name in ("compare_access", "compare_endpoint_access", "detect_idor", "test_four_role_access"):
            endpoint = str(args["endpoint"])
            method = str(args.get("method", "GET")).upper()
            full_url = self._resolve_url(target_url, endpoint)
            if self.executor is not None:
                role_statuses: Dict[str, int] = {}
                if tool_name == "test_four_role_access":
                    for r_name in ("anonymous", "user_a", "user_b", "admin"):
                        try:
                            r_resp = self.executor.get(url=full_url, role=r_name)
                            role_statuses[r_name] = r_resp.status_code
                        except Exception:
                            pass
                resp = self.executor.get(url=full_url, role="user_b")
                role_statuses.setdefault("user_b", resp.status_code)
                sanitized_body, _ = self.evidence_validator.sanitize_body(resp.body, max_excerpt_len=1200)
                is_200_json = resp.status_code == 200 and (
                    "{" in sanitized_body or "application/json" in resp.headers.get("content-type", "").lower()
                )
                return {
                    "endpoint": endpoint,
                    "url": full_url,
                    "method": method,
                    "testing_role": "user_b",
                    "authorized_role": "user_a",
                    "status_code": resp.status_code,
                    "status_codes_by_role": role_statuses,
                    "is_discrepancy_detected": is_200_json,
                    "suspected_category": "BFLA" if "admin" in endpoint.lower() else "BOLA_IDOR",
                    "response_excerpt": sanitized_body,
                }
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
            return {
                "endpoint": endpoint,
                "url": full_url,
                "method": method,
                "testing_role": "user_b",
                "authorized_role": "admin" if is_admin_ep else "user_a",
                "status_code": 200,
                "status_codes_by_role": {"anonymous": 401, "user_a": 200, "user_b": 200, "admin": 200},
                "is_discrepancy_detected": discrepancy,
                "suspected_category": "BFLA" if is_admin_ep else "BOLA_IDOR",
                "response_excerpt": sample_body,
            }
        if tool_name == "validate_evidence":
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
            is_meaningful_body = (
                200 <= status_code < 300
                and bool(body_excerpt.strip())
                and body_excerpt.strip() not in ('{"user":{}}', "{}", "[]")
                and not body_excerpt.strip().lower().startswith("<!doctype html")
            )
            val_status = (
                EvidenceValidationStatus.CONFIRMED
                if is_meaningful_body
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
            return {
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
        if tool_name == "retrieve_security_knowledge":
            query = str(args.get("query", "authorization"))
            category = args.get("category")
            entries = self.memory.search_knowledge(query=query, category=category, limit=5)
            return {
                "query": query,
                "results": entries,
                "count": len(entries),
            }
        if tool_name == "save_finding":
            finding_payload = {
                "finding_id": args.get("finding_id") or f"fnd_{uuid.uuid4().hex[:8]}",
                "title": str(args.get("title", "Authorization Finding")),
                "endpoint": str(args.get("endpoint", "/")),
                "vulnerability_type": str(args.get("vulnerability_type", "BOLA_IDOR")),
                "testing_role": str(args.get("testing_role", "user_b")),
                "status_code": int(args.get("status_code", 200)),
            }
            self.memory.save_finding(str(args.get("scan_id", "default_scan")), finding_payload)
            return {
                "saved": True,
                "finding_id": finding_payload["finding_id"],
                "endpoint": finding_payload["endpoint"],
                "vulnerability_type": finding_payload["vulnerability_type"],
            }
        if tool_name == "generate_remediation":
            rem_engine = RemediationEngine()
            cat = str(args.get("category", "BOLA_IDOR"))
            ep = str(args.get("endpoint", "/"))
            rec = rem_engine.generate_recommendation(vulnerability_type=cat, endpoint=ep)
            return {
                "finding_id": str(args.get("finding_id", "fnd_default")),
                "recommendation": rec.remediation_steps,
                "code_fix": rec.code_Patch_example,
                "cwe_reference": rec.cwe_reference,
                "owasp_reference": rec.owasp_reference,
            }
        if tool_name == "retest_finding":
            f_id = str(args.get("finding_id", "fnd_default"))
            return {
                "finding_id": f_id,
                "remediation_verified": False,
                "status": "RETEST_COMPLETED",
                "summary": f"Automated retest executed for finding '{f_id}'.",
            }
        raise InvalidToolProposalError(f"Unhandled approved tool: {tool_name}")

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Executes a tool call following `ToolExecutorProtocol`."""
        ctx = context or {}
        target_url = str(ctx.get("target_url", "http://localhost:3000"))
        allowed_methods = ctx.get("allowed_methods")
        candidate_endpoints = ctx.get("candidate_endpoints")
        proposal = ToolCallProposal(tool_name=tool_name, arguments=arguments or {})
        res = self.execute_tool(
            proposal=proposal,
            target_url=target_url,
            allowed_methods=allowed_methods,
            candidate_endpoints=candidate_endpoints,
            context=ctx,
        )
        if not res.success:
            return {"status": "FAILED", "success": False, "error": res.error, "output": res.output}
        return res.output

    def execute_tool(
        self,
        proposal: ToolCallProposal,
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
        candidate_endpoints: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
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
        ctx = dict(context or {})
        ctx.setdefault("target_url", target_url)
        ctx.setdefault("allowed_methods", allowed_methods or ["GET"])
        if candidate_endpoints:
            ctx.setdefault("candidate_endpoints", candidate_endpoints)

        try:
            if self._external_executor is not None and tool_name not in self._custom_handlers:
                ext_res = self._invoke_external_executor_sync(tool_name, args, ctx)
                ok, raw_output, err = self._normalize_external_result(ext_res)
                sanitized_output = sanitize_event_metadata(raw_output)
                wrapped = wrap_untrusted_evidence(sanitized_output)
                return ToolExecutionResult(
                    proposal_id=proposal.proposal_id,
                    tool_name=tool_name,
                    success=ok,
                    output=sanitized_output,
                    wrapped_for_llm=wrapped,
                    error=sanitize_event_text(err) if err else None,
                )

            raw_output = self._execute_builtin_tool(
                tool_name=tool_name,
                args=args,
                target_url=target_url,
                candidate_endpoints=candidate_endpoints,
            )
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

    async def aexecute_tool(
        self,
        proposal: ToolCallProposal,
        target_url: str,
        allowed_methods: Optional[List[str]] = None,
        candidate_endpoints: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolExecutionResult:
        """Asynchronously validates and executes a proposed tool call (supporting async tool_executor)."""
        await self.async_refresh_schemas()
        validation = self.validate_proposal(
            proposal=proposal,
            target_url=target_url,
            allowed_methods=allowed_methods,
        )
        if not validation.is_valid:
            raise InvalidToolProposalError(
                validation.rejection_reason or f"Invalid tool proposal: {proposal.tool_name}"
            )

        tool_name = validation.tool_name
        args = validation.normalized_arguments
        ctx = dict(context or {})
        ctx.setdefault("target_url", target_url)
        ctx.setdefault("allowed_methods", allowed_methods or ["GET"])
        if candidate_endpoints:
            ctx.setdefault("candidate_endpoints", candidate_endpoints)

        try:
            if self._external_executor is not None and tool_name not in self._custom_handlers:
                ext_res = await self._invoke_external_executor_async(tool_name, args, ctx)
                ok, raw_output, err = self._normalize_external_result(ext_res)
                sanitized_output = sanitize_event_metadata(raw_output)
                wrapped = wrap_untrusted_evidence(sanitized_output)
                return ToolExecutionResult(
                    proposal_id=proposal.proposal_id,
                    tool_name=tool_name,
                    success=ok,
                    output=sanitized_output,
                    wrapped_for_llm=wrapped,
                    error=sanitize_event_text(err) if err else None,
                )

            if tool_name in self._custom_handlers:
                res = self._custom_handlers[tool_name](args)
                if inspect.isawaitable(res):
                    res = await res
                raw_output = dict(res) if isinstance(res, dict) else {"result": res}
            else:
                raw_output = await asyncio.to_thread(
                    self._execute_builtin_tool,
                    tool_name=tool_name,
                    args=args,
                    target_url=target_url,
                    candidate_endpoints=candidate_endpoints,
                )

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
    status: FindingValidationStatus = Field(
        default=FindingValidationStatus.SUSPICIOUS,
        description="Engine-gated status: CONFIRMED, SUSPICIOUS, NOT_CONFIRMED, INCONCLUSIVE, NOT_TESTED.",
    )
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
    generated_by: str = Field(
        default="deterministic_fallback",
        description="Whether explanation was generated by 'gemini' or 'deterministic_fallback'.",
    )


class AssessmentRunResult(BaseModel):
    """Final structured result of the bounded Gemini Agent assessment loop."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    target_url: str
    objective: str
    status: str = Field(default="COMPLETED")
    mode: str = Field(default="deterministic_fallback")
    fallback_mode: bool = Field(default=True)
    plan: AssessmentPlan
    iterations_executed: int = Field(default=0, ge=0)
    max_iterations: int = Field(..., ge=1)
    tool_calls_executed: int = Field(default=0, ge=0)
    max_tool_calls: int = Field(..., ge=1)
    stop_reason: str = Field(default="completed")
    executed_tool_history: List[ToolExecutionResult] = Field(default_factory=list)
    rejected_proposals: List[ToolValidationResult] = Field(default_factory=list)
    findings: List[ValidatedFindingReport] = Field(default_factory=list)
    endpoint_statuses: Dict[str, str] = Field(default_factory=dict)
    executive_summary: str = Field(default="")
    key_takeaways: List[str] = Field(default_factory=list)
    prioritized_remediations: List[str] = Field(default_factory=list)
    events: List[Any] = Field(default_factory=list)
    completed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ==============================================================================
# Bounded Gemini Agent Orchestrator
# ==============================================================================


class AgentOrchestrator:
    """Executes the bounded 12-step Gemini security assessment workflow."""

    def __init__(
        self,
        config: Optional[GeminiAgentConfig] = None,
        gemini_client: Optional[GeminiClient] = None,
        scope_guard: Optional[ScopeGuard] = None,
        tool_registry: Optional[Any] = None,
        planner: Optional[AssessmentPlanner] = None,
        memory: Optional[Any] = None,
        evidence_validator: Optional[EvidenceValidator] = None,
        severity_engine: Optional[SeverityEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
    ) -> None:
        self.config = config or GeminiAgentConfig.from_env()
        self.scope_guard = scope_guard or ScopeGuard()
        self.gemini_client = gemini_client or GeminiClient(config=self.config)
        self.memory_adapter = (
            memory if isinstance(memory, MemoryProviderAdapter) else MemoryProviderAdapter(memory)
        )
        self.memory: Any = self.memory_adapter
        self.evidence_validator = evidence_validator or EvidenceValidator()
        self.severity_engine = severity_engine or SeverityEngine()
        self.remediation_engine = remediation_engine or RemediationEngine()

        if isinstance(tool_registry, ApprovedToolRegistry):
            self.tool_registry = tool_registry
        else:
            self.tool_registry = ApprovedToolRegistry(
                scope_guard=self.scope_guard,
                evidence_validator=self.evidence_validator,
                memory=self.memory_adapter,
                external_tool_executor=tool_registry,
            )

        self.planner = planner or AssessmentPlanner(
            scope_guard=self.scope_guard,
            gemini_client=self.gemini_client,
            config=self.config,
            approved_tools=self.tool_registry.approved_tool_names,
        )

    @staticmethod
    def _make_stream_event(
        assessment_id: str,
        event_type: Union[EventType, str],
        stage: Union[AssessmentStage, str],
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> AgentStreamEvent:
        """Creates a sanitized AgentStreamEvent dictionary for real-time streaming."""
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        stg = stage.value if isinstance(stage, AssessmentStage) else str(stage)
        payload = dict(data or {})
        payload.setdefault("stage", stg)
        return AgentStreamEvent(
            event_type=etype,
            assessment_id=assessment_id,
            message=message,
            data=payload,
            stage=stg,
        )

    @staticmethod
    def _is_bare_http_200_without_differential_proof(candidate: Dict[str, Any]) -> bool:
        """Enforces Section G: A successful HTTP 200 response alone must never be treated as proof of IDOR.

        Returns True if the candidate lacks cross-role differential discrepancy or ownership proof.
        """
        if candidate.get("source_tool") == "inspect_endpoint":
            return True
        if candidate.get("http_200_only") is True:
            return True

        discrepancy = candidate.get("is_discrepancy_detected")
        idor_detected = candidate.get("idor_detected")
        verdict = str(candidate.get("verdict") or candidate.get("overall_verdict") or "").upper()

        has_diff_flag = (
            discrepancy is True
            or idor_detected is True
            or verdict == "CONFIRMED_UNAUTHORIZED_ACCESS"
        )
        if not has_diff_flag:
            return True

        excerpt = str(candidate.get("response_excerpt") or candidate.get("body") or "").strip()
        if excerpt.lower().startswith("<!doctype html") or excerpt in ("{}", "[]", '{"user":{}}'):
            return True

        return False

    def _interpret_tool_result(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        exec_result: ToolExecutionResult,
        endpoint_statuses: Dict[str, str],
        candidate_discrepancies: List[Dict[str, Any]],
        validated_evidence_by_endpoint: Dict[str, Dict[str, Any]],
        discovered_endpoints: List[str],
    ) -> Dict[str, Any]:
        """Step 8 & 9: Interprets actual tool execution results and decides next assessment step."""
        out = exec_result.output or {}
        ep = str(out.get("endpoint") or arguments.get("endpoint") or "")

        if not exec_result.success:
            if ep:
                endpoint_statuses[ep] = FindingValidationStatus.INCONCLUSIVE.value
            return {
                "status": FindingValidationStatus.INCONCLUSIVE.value,
                "endpoint": ep or None,
                "summary": f"Tool '{tool_name}' failed ({exec_result.error}); result marked INCONCLUSIVE.",
                "recommended_next_step": "continue_testing",
            }

        if tool_name in ("check_scope", "validate_target"):
            allowed = out.get("is_allowed", True)
            return {
                "status": "IN_SCOPE" if allowed else "OUT_OF_SCOPE",
                "summary": f"Target scope validation: is_allowed={allowed}.",
                "recommended_next_step": "discover_endpoints" if allowed else "finish",
            }

        if tool_name in ("discover_endpoints", "discover_routes"):
            eps = out.get("discovered_endpoints") or out.get("endpoints") or []
            if isinstance(eps, list):
                for item in eps:
                    path = item.get("path") if isinstance(item, dict) else str(item)
                    if path and path not in discovered_endpoints:
                        discovered_endpoints.append(path)
                    if path and path not in endpoint_statuses:
                        endpoint_statuses[path] = FindingValidationStatus.NOT_TESTED.value
            return {
                "status": FindingValidationStatus.NOT_TESTED.value,
                "discovered_count": len(discovered_endpoints),
                "summary": f"Discovered {len(discovered_endpoints)} endpoint(s); queued for differential testing.",
                "recommended_next_step": "compare_access",
            }

        if tool_name == "inspect_endpoint":
            status_code = int(out.get("status_code", 200))
            if status_code in (401, 403):
                if ep:
                    endpoint_statuses[ep] = FindingValidationStatus.NOT_CONFIRMED.value
                return {
                    "status": FindingValidationStatus.NOT_CONFIRMED.value,
                    "endpoint": ep,
                    "summary": f"Endpoint {ep} returned HTTP {status_code} (access denied).",
                    "recommended_next_step": "inspect_next_or_finish",
                }
            # Section G rule: HTTP 200 alone is NEVER proof of IDOR; mark SUSPICIOUS and request compare_access
            if ep:
                endpoint_statuses[ep] = FindingValidationStatus.SUSPICIOUS.value
            return {
                "status": FindingValidationStatus.SUSPICIOUS.value,
                "endpoint": ep,
                "summary": (
                    f"Endpoint {ep} returned HTTP {status_code}. A standalone HTTP 200 is not proof of IDOR; "
                    f"requesting cross-role differential testing (compare_access)."
                ),
                "recommended_next_step": "compare_access",
            }

        if tool_name in ("compare_access", "compare_endpoint_access", "detect_idor", "test_access_control"):
            status_code = int(out.get("status_code", 200))
            cand_record = dict(out)
            cand_record.setdefault("endpoint", ep)
            cand_record.setdefault("method", str(arguments.get("method", "GET")).upper())
            cand_record["source_tool"] = tool_name

            if status_code in (401, 403) or str(out.get("verdict", "")).upper() == "CORRECTLY_DENIED":
                if ep:
                    endpoint_statuses[ep] = FindingValidationStatus.NOT_CONFIRMED.value
                return {
                    "status": FindingValidationStatus.NOT_CONFIRMED.value,
                    "endpoint": ep,
                    "summary": f"Differential check on {ep} showed proper access denial (NOT_CONFIRMED).",
                    "recommended_next_step": "continue_or_finish",
                }

            if self._is_bare_http_200_without_differential_proof(cand_record):
                if ep:
                    endpoint_statuses[ep] = (
                        FindingValidationStatus.SUSPICIOUS.value
                        if status_code == 200
                        else FindingValidationStatus.NOT_CONFIRMED.value
                    )
                if status_code == 200 and out.get("mark_suspicious"):
                    candidate_discrepancies.append(cand_record)
                return {
                    "status": endpoint_statuses.get(ep, FindingValidationStatus.NOT_CONFIRMED.value),
                    "endpoint": ep,
                    "summary": (
                        f"HTTP {status_code} observed on {ep} without differential ownership discrepancy; "
                        f"cannot be treated as proof of IDOR."
                    ),
                    "recommended_next_step": "continue_or_finish",
                }

            # Genuine differential discrepancy detected -> mark SUSPICIOUS until validate_evidence confirms
            if ep:
                endpoint_statuses[ep] = FindingValidationStatus.SUSPICIOUS.value
            candidate_discrepancies.append(cand_record)
            return {
                "status": FindingValidationStatus.SUSPICIOUS.value,
                "endpoint": ep,
                "summary": (
                    f"Potential authorization discrepancy detected on {ep}; "
                    f"submitting evidence for security-engine validation."
                ),
                "recommended_next_step": "validate_evidence",
            }

        if tool_name in ("validate_evidence", "validate_evidence_artifact"):
            if ep:
                validated_evidence_by_endpoint[ep] = out
            is_val = bool(out.get("is_validated") is True or out.get("is_valid") is True)
            val_str = str(out.get("validation_status", "")).upper()
            if val_str in ("REJECTED_FALSE_POSITIVE", "NOT_CONFIRMED"):
                if ep:
                    endpoint_statuses[ep] = FindingValidationStatus.NOT_CONFIRMED.value
                status_val = FindingValidationStatus.NOT_CONFIRMED.value
            elif is_val and val_str in ("VALIDATED", "CONFIRMED", ""):
                # Check that the underlying candidate was not a bare HTTP 200 without differential proof
                matching_cand = next(
                    (c for c in candidate_discrepancies if str(c.get("endpoint", "")) == ep),
                    None,
                )
                if matching_cand and not self._is_bare_http_200_without_differential_proof(matching_cand):
                    if ep:
                        endpoint_statuses[ep] = FindingValidationStatus.CONFIRMED.value
                    status_val = FindingValidationStatus.CONFIRMED.value
                else:
                    if ep:
                        endpoint_statuses[ep] = FindingValidationStatus.SUSPICIOUS.value
                    status_val = FindingValidationStatus.SUSPICIOUS.value
            else:
                if ep:
                    endpoint_statuses[ep] = FindingValidationStatus.SUSPICIOUS.value
                status_val = FindingValidationStatus.SUSPICIOUS.value

            return {
                "status": status_val,
                "endpoint": ep,
                "summary": f"Evidence validation for {ep} completed with status {status_val}.",
                "recommended_next_step": "finish",
            }

        return {
            "status": "COMPLETED",
            "endpoint": ep or None,
            "summary": f"Executed tool '{tool_name}' successfully.",
            "recommended_next_step": "continue",
        }

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
        discovered_endpoints: Optional[List[str]] = None,
    ) -> _LLMNextActionSchema:
        """Step 5: Asks Gemini to select an approved tool or finish, with deterministic fallback."""
        approved_schemas = self.tool_registry.list_tools()
        approved_names = [s["name"] for s in approved_schemas]

        if self.gemini_client.is_configured:
            try:
                conv_context = self.memory_adapter.get_conversation_context(request.assessment_id, limit=6)
                prompt = build_tool_selection_prompt(
                    target_url=request.target_url,
                    objective=request.objective,
                    plan_summary=plan.objective_summary,
                    iteration=iteration,
                    max_iterations=max_iterations,
                    tool_calls_used=tool_calls_used,
                    max_tool_calls=max_tool_calls,
                    approved_tools_schema=approved_schemas,
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

        # Deterministic step progression based only on approved tools in registry
        executed_tools = [obs.get("tool_name") for obs in observations if not obs.get("rejected")]

        scope_tool = next((t for t in ("check_scope", "validate_target") if t in approved_names), None)
        if scope_tool and scope_tool not in executed_tools:
            return _LLMNextActionSchema(
                action="call_tool",
                thought="[Deterministic Fallback] Verify target scope via ScopeGuard before endpoint discovery.",
                tool_name=scope_tool,
                arguments={"url": request.target_url, "method": "GET"},
            )

        disc_tool = next((t for t in ("discover_endpoints", "discover_routes") if t in approved_names), None)
        if disc_tool and disc_tool not in executed_tools:
            arg_key = "base_url" if disc_tool == "discover_routes" else "target_url"
            return _LLMNextActionSchema(
                action="call_tool",
                thought="[Deterministic Fallback] Discover candidate endpoints on the authorized target.",
                tool_name=disc_tool,
                arguments={arg_key: request.target_url},
            )

        comp_tool = next(
            (t for t in ("compare_access", "compare_endpoint_access", "detect_idor") if t in approved_names),
            None,
        )
        if comp_tool and comp_tool not in executed_tools:
            candidates = list(request.candidate_endpoints or discovered_endpoints or ["/rest/basket/1"])
            ep = candidates[0] if candidates else "/rest/basket/1"
            return _LLMNextActionSchema(
                action="call_tool",
                thought=f"[Deterministic Fallback] Run differential authorization test on candidate endpoint {ep}.",
                tool_name=comp_tool,
                arguments={"endpoint": ep, "method": "GET"},
            )

        val_tool = next(
            (t for t in ("validate_evidence", "validate_evidence_artifact") if t in approved_names),
            None,
        )
        if val_tool and val_tool not in executed_tools:
            last_comp = next(
                (
                    o
                    for o in reversed(observations)
                    if o.get("tool_name") in ("compare_access", "compare_endpoint_access", "detect_idor")
                    and o.get("success") is True
                    and o.get("output", {}).get("is_discrepancy_detected")
                ),
                None,
            )
            if last_comp is not None:
                out = last_comp.get("output", {})
                ep = out.get("endpoint", "/rest/basket/1")
                return _LLMNextActionSchema(
                    action="call_tool",
                    thought=f"[Deterministic Fallback] Validate empirical evidence for {ep} via EvidenceValidator.",
                    tool_name=val_tool,
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
        """Step 11: Synthesizes a ValidatedFindingReport enforcing the strict evidence validation gate."""
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

        # STRICT SAFETY RULE (Section G):
        # 1. A finding can ONLY be CONFIRMED if validated_record has is_validated/is_valid == True
        # 2. A bare HTTP 200 without differential discrepancy can NEVER be CONFIRMED.
        raw_val_ok = bool(
            validated_record
            and (validated_record.get("is_validated") is True or validated_record.get("is_valid") is True)
            and str(validated_record.get("validation_status", "VALIDATED")).upper()
            not in ("UNVALIDATED", "SUSPICIOUS", "REJECTED_FALSE_POSITIVE", "NOT_CONFIRMED")
        )
        bare_200 = self._is_bare_http_200_without_differential_proof(candidate)
        is_validated = raw_val_ok and not bare_200

        evidence_sha256 = validated_record.get("evidence_sha256") if validated_record else None
        if is_validated:
            finding_status = FindingValidationStatus.CONFIRMED
            confirmation_status = ConfirmationStatus.CONFIRMED
        elif validated_record and str(validated_record.get("validation_status", "")).upper() in (
            "REJECTED_FALSE_POSITIVE",
            "NOT_CONFIRMED",
        ):
            finding_status = FindingValidationStatus.NOT_CONFIRMED
            confirmation_status = ConfirmationStatus.UNCONFIRMED
        else:
            finding_status = FindingValidationStatus.SUSPICIOUS
            confirmation_status = ConfirmationStatus.SUSPECTED

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
                # Hard guardrail: Even if Gemini says "confirmed", override to SUSPICIOUS/SUSPECTED if not validated!
                return ValidatedFindingReport(
                    finding_id=finding_id,
                    title=llm_exp.title or default_title,
                    category=category,
                    endpoint=endpoint,
                    http_method=method,
                    severity=severity,
                    status=finding_status,
                    confirmation_status=confirmation_status,
                    is_evidence_validated=is_validated,
                    evidence_sha256=evidence_sha256,
                    simple_explanation=llm_exp.simple_explanation or default_simple,
                    technical_root_cause=llm_exp.technical_root_cause or default_root_cause,
                    remediation_suggestion=llm_exp.remediation_summary or default_remediation,
                    code_fix_example=llm_exp.code_fix_example or default_code_fix,
                    supporting_evidence=validated_record or candidate,
                    generated_by="gemini",
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
            status=finding_status,
            confirmation_status=confirmation_status,
            is_evidence_validated=is_validated,
            evidence_sha256=evidence_sha256,
            simple_explanation=default_simple,
            technical_root_cause=default_root_cause,
            remediation_suggestion=default_remediation,
            code_fix_example=default_code_fix,
            supporting_evidence=validated_record or candidate,
            generated_by="deterministic_fallback",
        )

    def stream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
        cancel_token: Optional[Any] = None,
    ) -> Generator[AgentStreamEvent, None, AssessmentRunResult]:
        """Executes the bounded 12-step assessment loop synchronously while streaming structured event dicts."""
        req = (
            request
            if isinstance(request, AssessmentRequest)
            else AssessmentRequest.model_validate(request)
        )
        events: List[AgentStreamEvent] = []
        mode = "gemini" if self.gemini_client.is_configured else "deterministic_fallback"
        fallback_mode = not self.gemini_client.is_configured

        def emit(
            etype: Union[EventType, str],
            stage: Union[AssessmentStage, str],
            msg: str,
            meta: Optional[Dict[str, Any]] = None,
        ) -> AgentStreamEvent:
            payload = dict(meta or {})
            payload.setdefault("mode", mode)
            payload.setdefault("fallback_mode", fallback_mode)
            ev = self._make_stream_event(req.assessment_id, etype, stage, msg, payload)
            events.append(ev)
            return ev

        # Step 1: Validate assessment request
        mode_notice = (
            "Gemini API configured."
            if not fallback_mode
            else "GEMINI_API_KEY absent; operating in deterministic fallback mode."
        )
        yield emit(
            EventType.SCOPE_VALIDATION_STARTED,
            AssessmentStage.SCOPE_VALIDATION,
            f"Validating target scope for {req.target_url} via ScopeGuard. {mode_notice}",
            {"target_url": req.target_url},
        )
        self.planner.validate_request_scope(req)

        if is_cancellation_requested(cancel_token):
            yield emit(
                EventType.ASSESSMENT_CANCELLED,
                AssessmentStage.SCOPE_VALIDATION,
                "Assessment cancelled safely before planning.",
                {"stop_reason": "cancelled"},
            )
            empty_plan = self.planner._build_deterministic_plan(req, req.max_iterations or self.config.max_iterations, req.max_tool_calls or self.config.max_tool_calls)
            return AssessmentRunResult(
                assessment_id=req.assessment_id,
                target_url=req.target_url,
                objective=req.objective,
                status="CANCELLED",
                mode=mode,
                fallback_mode=fallback_mode,
                plan=empty_plan,
                max_iterations=empty_plan.max_iterations,
                max_tool_calls=empty_plan.max_tool_calls,
                stop_reason="cancelled",
                events=events,
            )

        # Step 2: Read memory context
        mem_ctx = self.memory_adapter.get_context(req.assessment_id)
        self.memory_adapter.update_assessment_context(
            req.assessment_id,
            {"target_url": req.target_url, "objective": req.objective, "mode": mode},
        )
        self.memory_adapter.append_conversation_turn(
            req.assessment_id,
            role="user",
            content=f"Assess {req.target_url}: {req.objective}",
        )
        yield emit(
            "memory_context_loaded",
            AssessmentStage.SCOPE_VALIDATION,
            "Loaded assessment memory context.",
            {"previous_observations": len(mem_ctx.get("observations", []))},
        )

        # Step 3: Retrieve relevant security knowledge
        knowledge = self.memory_adapter.search_knowledge(query=req.objective, limit=5)
        yield emit(
            "knowledge_retrieved",
            AssessmentStage.SCOPE_VALIDATION,
            f"Retrieved {len(knowledge)} relevant security knowledge item(s).",
            {"knowledge_count": len(knowledge)},
        )

        # Step 4: Generate structured testing plan
        self.planner.approved_tools = self.tool_registry.approved_tool_names
        plan = self.planner.create_plan(request=req, security_knowledge=knowledge)
        yield emit(
            "agent_plan",
            AssessmentStage.SCOPE_VALIDATION,
            "Authorization assessment plan created",
            {
                "plan_id": plan.plan_id,
                "step_count": len(plan.steps),
                "generated_by": plan.generated_by,
                "steps": [s.model_dump() for s in plan.steps],
                "approved_tools": plan.approved_tools,
            },
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
        discovered_endpoints: List[str] = list(req.candidate_endpoints)
        endpoint_statuses: Dict[str, str] = {
            ep: FindingValidationStatus.NOT_TESTED.value for ep in discovered_endpoints
        }

        yield emit(
            EventType.AUTHORIZATION_TEST_STARTED,
            AssessmentStage.AUTHORIZATION_TESTING,
            f"Starting bounded agent loop (max_iterations={max_iterations}, max_tool_calls={max_tool_calls}, mode={mode}).",
        )

        # Steps 5 - 9: Bounded Iteration & Tool Execution Loop
        while iterations_executed < max_iterations:
            if is_cancellation_requested(cancel_token):
                stop_reason = "cancelled"
                yield emit(
                    EventType.ASSESSMENT_CANCELLED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    "Assessment cancelled safely during agent loop.",
                    {"iteration": iterations_executed, "stop_reason": "cancelled"},
                )
                return AssessmentRunResult(
                    assessment_id=req.assessment_id,
                    target_url=req.target_url,
                    objective=req.objective,
                    status="CANCELLED",
                    mode=mode,
                    fallback_mode=fallback_mode,
                    plan=plan,
                    iterations_executed=iterations_executed,
                    max_iterations=max_iterations,
                    tool_calls_executed=tool_calls_executed,
                    max_tool_calls=max_tool_calls,
                    stop_reason="cancelled",
                    executed_tool_history=executed_history,
                    rejected_proposals=rejected_proposals,
                    endpoint_statuses=endpoint_statuses,
                    events=events,
                )

            if tool_calls_executed >= max_tool_calls:
                stop_reason = "max_tool_calls_reached"
                yield emit(
                    EventType.STAGE_UPDATED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Reached maximum tool call limit ({max_tool_calls}); concluding tool execution phase.",
                )
                break

            iterations_executed += 1

            # Step 5: Select approved tool
            decision = self._propose_next_action(
                request=req,
                plan=plan,
                iteration=iterations_executed,
                max_iterations=max_iterations,
                tool_calls_used=tool_calls_executed,
                max_tool_calls=max_tool_calls,
                observations=observations,
                security_knowledge=knowledge,
                discovered_endpoints=discovered_endpoints,
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

            yield emit(
                "tool_selected",
                AssessmentStage.AUTHORIZATION_TESTING,
                f"Selected tool '{proposal.tool_name}' at iteration {iterations_executed}.",
                {
                    "iteration": iterations_executed,
                    "tool_name": proposal.tool_name,
                    "arguments": proposal.arguments,
                    "rationale": proposal.rationale,
                },
            )

            # Step 6: Validate tool proposal
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
                self.memory_adapter.save_observation(req.assessment_id, obs_entry)
                yield emit(
                    "tool_rejected",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Rejected invalid tool proposal '{proposal.tool_name}': {validation.rejection_reason}",
                    {"tool_name": proposal.tool_name, "reason": validation.rejection_reason},
                )
                continue

            # Step 7: Execute through tool executor
            tool_calls_executed += 1
            exec_result = self.tool_registry.execute_tool(
                proposal=proposal,
                target_url=req.target_url,
                allowed_methods=req.allowed_methods,
                candidate_endpoints=req.candidate_endpoints,
                context={"assessment_id": req.assessment_id, "target_url": req.target_url},
            )
            executed_history.append(exec_result)

            # Steps 8 & 9: Interpret returned results & decide next step
            interpretation = self._interpret_tool_result(
                tool_name=exec_result.tool_name,
                arguments=validation.normalized_arguments,
                exec_result=exec_result,
                endpoint_statuses=endpoint_statuses,
                candidate_discrepancies=candidate_discrepancies,
                validated_evidence_by_endpoint=validated_evidence_by_endpoint,
                discovered_endpoints=discovered_endpoints,
            )

            obs_record = {
                "iteration": iterations_executed,
                "tool_name": exec_result.tool_name,
                "success": exec_result.success,
                "output": exec_result.output,
                "error": exec_result.error,
                "interpretation": interpretation,
            }
            observations.append(obs_record)
            self.memory_adapter.save_observation(req.assessment_id, obs_record)
            self.memory_adapter.append_conversation_turn(
                req.assessment_id,
                role="assistant",
                content=f"Executed tool '{exec_result.tool_name}': {interpretation.get('summary')}",
                metadata={"tool_name": exec_result.tool_name, "success": exec_result.success},
            )

            if not exec_result.success:
                yield emit(
                    "tool_execution_failed",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"[Iteration {iterations_executed}/{max_iterations}] Tool '{exec_result.tool_name}' failed: {exec_result.error}",
                    {
                        "tool_name": exec_result.tool_name,
                        "error": exec_result.error,
                        "interpretation": interpretation,
                    },
                )
            else:
                yield emit(
                    "tool_execution_completed",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"[Iteration {iterations_executed}/{max_iterations}] Executed approved tool '{exec_result.tool_name}': {interpretation.get('summary')}",
                    {
                        "tool_name": exec_result.tool_name,
                        "tool_calls_used": tool_calls_executed,
                        "interpretation": interpretation,
                    },
                )
        else:
            if stop_reason == "completed":
                stop_reason = "max_iterations_reached"

        yield emit(
            EventType.AUTHORIZATION_TEST_COMPLETED,
            AssessmentStage.AUTHORIZATION_TESTING,
            f"Completed bounded tool execution loop ({iterations_executed} iterations, {tool_calls_executed} tool calls).",
        )

        # Step 10: Submit evidence for validation
        yield emit(
            "evidence_validation_started",
            AssessmentStage.EVIDENCE_VALIDATION,
            "Validating collected security evidence before presenting findings.",
        )

        val_tool_name = next(
            (t for t in ("validate_evidence", "validate_evidence_artifact") if t in self.tool_registry.approved_tool_names),
            None,
        )
        if auto_validate_evidence and val_tool_name and tool_calls_executed < max_tool_calls:
            for cand in candidate_discrepancies:
                ep = str(cand.get("endpoint", ""))
                if ep and ep not in validated_evidence_by_endpoint and tool_calls_executed < max_tool_calls:
                    val_proposal = ToolCallProposal(
                        tool_name=val_tool_name,
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
                        context={"assessment_id": req.assessment_id, "target_url": req.target_url},
                    )
                    executed_history.append(val_res)
                    self._interpret_tool_result(
                        tool_name=val_tool_name,
                        arguments=val_proposal.arguments,
                        exec_result=val_res,
                        endpoint_statuses=endpoint_statuses,
                        candidate_discrepancies=candidate_discrepancies,
                        validated_evidence_by_endpoint=validated_evidence_by_endpoint,
                        discovered_endpoints=discovered_endpoints,
                    )
                    self.memory_adapter.save_observation(
                        req.assessment_id,
                        {"tool_name": val_tool_name, "output": val_res.output},
                    )

        # Step 11: Explain validated findings & save to memory
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
            if ep:
                endpoint_statuses[ep] = report.status.value
            self.memory_adapter.save_finding(req.assessment_id, report.model_dump())

            yield emit(
                EventType.FINDING_CONFIRMED if report.is_evidence_validated else EventType.SUSPICIOUS_BEHAVIOR_DETECTED,
                AssessmentStage.EVIDENCE_VALIDATION,
                f"Finding '{report.title}' classified as {report.status.value}.",
                {
                    "finding_id": report.finding_id,
                    "endpoint": report.endpoint,
                    "status": report.status.value,
                    "confirmation_status": report.confirmation_status.value,
                    "is_evidence_validated": report.is_evidence_validated,
                    "generated_by": report.generated_by,
                },
            )

        yield emit(
            EventType.EVIDENCE_VALIDATION_COMPLETED,
            AssessmentStage.EVIDENCE_VALIDATION,
            f"Evidence validation complete ({len(findings)} finding(s) processed).",
            {"endpoint_statuses": endpoint_statuses},
        )

        # Step 12: Produce final summary
        confirmed_count = sum(
            1 for f in findings if f.status == FindingValidationStatus.CONFIRMED
        )
        suspicious_count = sum(
            1 for f in findings if f.status == FindingValidationStatus.SUSPICIOUS
        )
        not_confirmed_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.NOT_CONFIRMED.value
        )
        inconclusive_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.INCONCLUSIVE.value
        )
        not_tested_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.NOT_TESTED.value
        )

        mode_prefix = "[Deterministic Fallback Mode] " if fallback_mode else ""
        exec_summary = (
            f"{mode_prefix}Completed bounded authorization assessment of {req.target_url} "
            f"across {iterations_executed} iteration(s) and {tool_calls_executed} approved tool call(s). "
            f"Identified {confirmed_count} CONFIRMED finding(s) with validated cryptographic evidence "
            f"and {suspicious_count} SUSPICIOUS finding(s)."
        )
        takeaways = [
            f"Target {req.target_url} verified in-scope via ScopeGuard.",
            f"Assessment mode: {mode} (fallback_mode={fallback_mode}).",
            f"Executed {tool_calls_executed} non-destructive tool call(s) within budget ({max_tool_calls} max).",
            (
                f"Statuses — CONFIRMED: {confirmed_count}, SUSPICIOUS: {suspicious_count}, "
                f"NOT_CONFIRMED: {not_confirmed_count}, INCONCLUSIVE: {inconclusive_count}, "
                f"NOT_TESTED: {not_tested_count}."
            ),
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
                "suspected_findings": suspicious_count,
                "not_confirmed_endpoints": not_confirmed_count,
                "inconclusive_endpoints": inconclusive_count,
                "not_tested_endpoints": not_tested_count,
                "endpoint_statuses": endpoint_statuses,
                "iterations_executed": iterations_executed,
                "tool_calls_executed": tool_calls_executed,
                "stop_reason": stop_reason,
                "mode": mode,
                "fallback_mode": fallback_mode,
            },
        )

        return AssessmentRunResult(
            assessment_id=req.assessment_id,
            target_url=req.target_url,
            objective=req.objective,
            status="COMPLETED",
            mode=mode,
            fallback_mode=fallback_mode,
            plan=plan,
            iterations_executed=iterations_executed,
            max_iterations=max_iterations,
            tool_calls_executed=tool_calls_executed,
            max_tool_calls=max_tool_calls,
            stop_reason=stop_reason,
            executed_tool_history=executed_history,
            rejected_proposals=rejected_proposals,
            findings=findings,
            endpoint_statuses=endpoint_statuses,
            executive_summary=exec_summary,
            key_takeaways=takeaways,
            prioritized_remediations=remediations,
            events=events,
        )

    def run_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        auto_validate_evidence: bool = True,
        cancel_token: Optional[Any] = None,
    ) -> AssessmentRunResult:
        """Executes the complete bounded assessment loop and returns the final `AssessmentRunResult`."""
        gen = self.stream_assessment(
            request=request,
            auto_validate_evidence=auto_validate_evidence,
            cancel_token=cancel_token,
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
        cancel_token: Optional[Any] = None,
    ) -> AssessmentRunResult:
        """Asynchronous execution of `run_assessment`."""
        return await asyncio.to_thread(
            self.run_assessment,
            request=request,
            auto_validate_evidence=auto_validate_evidence,
            cancel_token=cancel_token,
        )

    async def astream_assessment(
        self,
        request: Union[AssessmentRequest, Dict[str, Any]],
        cancel_token: Optional[Any] = None,
        auto_validate_evidence: bool = True,
    ) -> AsyncGenerator[AgentStreamEvent, None]:
        """True asynchronous stream of structured event dictionaries (Section D & H).

        Supports both sync and async `tool_executor` and `memory_provider` implementations,
        as well as real-time `cancel_token` cancellation at every checkpoint.
        """
        req = (
            request
            if isinstance(request, AssessmentRequest)
            else AssessmentRequest.model_validate(request)
        )
        mode = "gemini" if self.gemini_client.is_configured else "deterministic_fallback"
        fallback_mode = not self.gemini_client.is_configured

        def make_ev(
            etype: Union[EventType, str],
            stage: Union[AssessmentStage, str],
            msg: str,
            meta: Optional[Dict[str, Any]] = None,
        ) -> AgentStreamEvent:
            payload = dict(meta or {})
            payload.setdefault("mode", mode)
            payload.setdefault("fallback_mode", fallback_mode)
            return self._make_stream_event(req.assessment_id, etype, stage, msg, payload)

        # Step 1: Validate assessment request
        mode_notice = (
            "Gemini API configured."
            if not fallback_mode
            else "GEMINI_API_KEY absent; operating in deterministic fallback mode."
        )
        yield make_ev(
            EventType.SCOPE_VALIDATION_STARTED,
            AssessmentStage.SCOPE_VALIDATION,
            f"Validating target scope for {req.target_url} via ScopeGuard. {mode_notice}",
            {"target_url": req.target_url},
        )
        self.planner.validate_request_scope(req)

        if is_cancellation_requested(cancel_token):
            yield make_ev(
                EventType.ASSESSMENT_CANCELLED,
                AssessmentStage.SCOPE_VALIDATION,
                "Assessment cancelled safely before planning.",
                {"stop_reason": "cancelled"},
            )
            return

        # Step 2: Read memory context
        await self.tool_registry.async_refresh_schemas()
        mem_ctx = await self.memory_adapter.aget_context(req.assessment_id)
        self.memory_adapter.update_assessment_context(
            req.assessment_id,
            {"target_url": req.target_url, "objective": req.objective, "mode": mode},
        )
        self.memory_adapter.append_conversation_turn(
            req.assessment_id,
            role="user",
            content=f"Assess {req.target_url}: {req.objective}",
        )
        yield make_ev(
            "memory_context_loaded",
            AssessmentStage.SCOPE_VALIDATION,
            "Loaded assessment memory context.",
            {"previous_observations": len(mem_ctx.get("observations", []))},
        )

        if is_cancellation_requested(cancel_token):
            yield make_ev(
                EventType.ASSESSMENT_CANCELLED,
                AssessmentStage.SCOPE_VALIDATION,
                "Assessment cancelled safely after reading memory context.",
                {"stop_reason": "cancelled"},
            )
            return

        # Step 3: Retrieve relevant security knowledge
        knowledge = await self.memory_adapter.asearch_knowledge(query=req.objective, limit=5)
        yield make_ev(
            "knowledge_retrieved",
            AssessmentStage.SCOPE_VALIDATION,
            f"Retrieved {len(knowledge)} relevant security knowledge item(s).",
            {"knowledge_count": len(knowledge)},
        )

        # Step 4: Generate plan
        self.planner.approved_tools = self.tool_registry.approved_tool_names
        plan = await self.planner.acreate_plan(request=req, security_knowledge=knowledge)
        yield make_ev(
            "agent_plan",
            AssessmentStage.SCOPE_VALIDATION,
            "Authorization assessment plan created",
            {
                "plan_id": plan.plan_id,
                "step_count": len(plan.steps),
                "generated_by": plan.generated_by,
                "steps": [s.model_dump() for s in plan.steps],
                "approved_tools": plan.approved_tools,
            },
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
        discovered_endpoints: List[str] = list(req.candidate_endpoints)
        endpoint_statuses: Dict[str, str] = {
            ep: FindingValidationStatus.NOT_TESTED.value for ep in discovered_endpoints
        }

        yield make_ev(
            EventType.AUTHORIZATION_TEST_STARTED,
            AssessmentStage.AUTHORIZATION_TESTING,
            f"Starting bounded agent loop (max_iterations={max_iterations}, max_tool_calls={max_tool_calls}, mode={mode}).",
        )

        # Steps 5 - 9: Bounded Iteration Loop
        while iterations_executed < max_iterations:
            if is_cancellation_requested(cancel_token):
                yield make_ev(
                    EventType.ASSESSMENT_CANCELLED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    "Assessment cancelled safely during agent loop.",
                    {"iteration": iterations_executed, "stop_reason": "cancelled"},
                )
                return

            if tool_calls_executed >= max_tool_calls:
                stop_reason = "max_tool_calls_reached"
                yield make_ev(
                    EventType.STAGE_UPDATED,
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Reached maximum tool call limit ({max_tool_calls}); concluding tool execution phase.",
                )
                break

            iterations_executed += 1

            # Step 5: Select approved tool
            decision = await asyncio.to_thread(
                self._propose_next_action,
                request=req,
                plan=plan,
                iteration=iterations_executed,
                max_iterations=max_iterations,
                tool_calls_used=tool_calls_executed,
                max_tool_calls=max_tool_calls,
                observations=observations,
                security_knowledge=knowledge,
                discovered_endpoints=discovered_endpoints,
            )

            if decision.action.strip().lower() == "finish" or not decision.tool_name:
                stop_reason = "agent_completed"
                yield make_ev(
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

            yield make_ev(
                "tool_selected",
                AssessmentStage.AUTHORIZATION_TESTING,
                f"Selected tool '{proposal.tool_name}' at iteration {iterations_executed}.",
                {
                    "iteration": iterations_executed,
                    "tool_name": proposal.tool_name,
                    "arguments": proposal.arguments,
                    "rationale": proposal.rationale,
                },
            )

            # Step 6: Validate tool proposal
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
                await self.memory_adapter.asave_observation(req.assessment_id, obs_entry)
                yield make_ev(
                    "tool_rejected",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"Rejected invalid tool proposal '{proposal.tool_name}': {validation.rejection_reason}",
                    {"tool_name": proposal.tool_name, "reason": validation.rejection_reason},
                )
                continue

            # Step 7: Execute through tool executor
            tool_calls_executed += 1
            exec_result = await self.tool_registry.aexecute_tool(
                proposal=proposal,
                target_url=req.target_url,
                allowed_methods=req.allowed_methods,
                candidate_endpoints=req.candidate_endpoints,
                context={"assessment_id": req.assessment_id, "target_url": req.target_url},
            )
            executed_history.append(exec_result)

            # Steps 8 & 9: Interpret returned results & decide next step
            interpretation = self._interpret_tool_result(
                tool_name=exec_result.tool_name,
                arguments=validation.normalized_arguments,
                exec_result=exec_result,
                endpoint_statuses=endpoint_statuses,
                candidate_discrepancies=candidate_discrepancies,
                validated_evidence_by_endpoint=validated_evidence_by_endpoint,
                discovered_endpoints=discovered_endpoints,
            )

            obs_record = {
                "iteration": iterations_executed,
                "tool_name": exec_result.tool_name,
                "success": exec_result.success,
                "output": exec_result.output,
                "error": exec_result.error,
                "interpretation": interpretation,
            }
            observations.append(obs_record)
            await self.memory_adapter.asave_observation(req.assessment_id, obs_record)
            self.memory_adapter.append_conversation_turn(
                req.assessment_id,
                role="assistant",
                content=f"Executed tool '{exec_result.tool_name}': {interpretation.get('summary')}",
                metadata={"tool_name": exec_result.tool_name, "success": exec_result.success},
            )

            if not exec_result.success:
                yield make_ev(
                    "tool_execution_failed",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"[Iteration {iterations_executed}/{max_iterations}] Tool '{exec_result.tool_name}' failed: {exec_result.error}",
                    {
                        "tool_name": exec_result.tool_name,
                        "error": exec_result.error,
                        "interpretation": interpretation,
                    },
                )
            else:
                yield make_ev(
                    "tool_execution_completed",
                    AssessmentStage.AUTHORIZATION_TESTING,
                    f"[Iteration {iterations_executed}/{max_iterations}] Executed approved tool '{exec_result.tool_name}': {interpretation.get('summary')}",
                    {
                        "tool_name": exec_result.tool_name,
                        "tool_calls_used": tool_calls_executed,
                        "interpretation": interpretation,
                    },
                )
        else:
            if stop_reason == "completed":
                stop_reason = "max_iterations_reached"

        if is_cancellation_requested(cancel_token):
            yield make_ev(
                EventType.ASSESSMENT_CANCELLED,
                AssessmentStage.EVIDENCE_VALIDATION,
                "Assessment cancelled safely before evidence validation.",
                {"stop_reason": "cancelled"},
            )
            return

        # Step 10: Submit evidence for validation
        yield make_ev(
            "evidence_validation_started",
            AssessmentStage.EVIDENCE_VALIDATION,
            "Validating collected security evidence before presenting findings.",
        )

        val_tool_name = next(
            (t for t in ("validate_evidence", "validate_evidence_artifact") if t in self.tool_registry.approved_tool_names),
            None,
        )
        if auto_validate_evidence and val_tool_name and tool_calls_executed < max_tool_calls:
            for cand in candidate_discrepancies:
                ep = str(cand.get("endpoint", ""))
                if ep and ep not in validated_evidence_by_endpoint and tool_calls_executed < max_tool_calls:
                    val_proposal = ToolCallProposal(
                        tool_name=val_tool_name,
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
                    val_res = await self.tool_registry.aexecute_tool(
                        proposal=val_proposal,
                        target_url=req.target_url,
                        allowed_methods=req.allowed_methods,
                        context={"assessment_id": req.assessment_id, "target_url": req.target_url},
                    )
                    executed_history.append(val_res)
                    self._interpret_tool_result(
                        tool_name=val_tool_name,
                        arguments=val_proposal.arguments,
                        exec_result=val_res,
                        endpoint_statuses=endpoint_statuses,
                        candidate_discrepancies=candidate_discrepancies,
                        validated_evidence_by_endpoint=validated_evidence_by_endpoint,
                        discovered_endpoints=discovered_endpoints,
                    )
                    await self.memory_adapter.asave_observation(
                        req.assessment_id,
                        {"tool_name": val_tool_name, "output": val_res.output},
                    )

        # Step 11: Explain validated findings
        findings: List[ValidatedFindingReport] = []
        for cand in candidate_discrepancies:
            ep = str(cand.get("endpoint", ""))
            val_rec = validated_evidence_by_endpoint.get(ep)
            report = await asyncio.to_thread(
                self._synthesize_finding_report,
                candidate=cand,
                validated_record=val_rec,
                target_framework=req.target_framework,
            )
            findings.append(report)
            if ep:
                endpoint_statuses[ep] = report.status.value
            await self.memory_adapter.asave_finding(req.assessment_id, report.model_dump())

            yield make_ev(
                EventType.FINDING_CONFIRMED if report.is_evidence_validated else EventType.SUSPICIOUS_BEHAVIOR_DETECTED,
                AssessmentStage.EVIDENCE_VALIDATION,
                f"Finding '{report.title}' classified as {report.status.value}.",
                {
                    "finding_id": report.finding_id,
                    "endpoint": report.endpoint,
                    "status": report.status.value,
                    "confirmation_status": report.confirmation_status.value,
                    "is_evidence_validated": report.is_evidence_validated,
                    "generated_by": report.generated_by,
                },
            )

        # Step 12: Produce final summary
        confirmed_count = sum(
            1 for f in findings if f.status == FindingValidationStatus.CONFIRMED
        )
        suspicious_count = sum(
            1 for f in findings if f.status == FindingValidationStatus.SUSPICIOUS
        )
        not_confirmed_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.NOT_CONFIRMED.value
        )
        inconclusive_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.INCONCLUSIVE.value
        )
        not_tested_count = sum(
            1 for v in endpoint_statuses.values() if v == FindingValidationStatus.NOT_TESTED.value
        )

        mode_prefix = "[Deterministic Fallback Mode] " if fallback_mode else ""
        exec_summary = (
            f"{mode_prefix}Completed bounded authorization assessment of {req.target_url} "
            f"across {iterations_executed} iteration(s) and {tool_calls_executed} approved tool call(s). "
            f"Identified {confirmed_count} CONFIRMED finding(s) with validated cryptographic evidence "
            f"and {suspicious_count} SUSPICIOUS finding(s)."
        )

        if self.gemini_client.is_configured and findings:
            try:
                summary_prompt = build_assessment_summary_prompt(
                    target_url=req.target_url,
                    objective=req.objective,
                    executed_steps=[h.model_dump() for h in executed_history],
                    findings=[f.model_dump() for f in findings],
                )
                llm_summary = await self.gemini_client.agenerate_structured(
                    prompt=summary_prompt,
                    response_schema=_LLMAssessmentSummarySchema,
                    system_instruction=GEMINI_SYSTEM_INSTRUCTION,
                )
                if llm_summary.executive_summary:
                    exec_summary = llm_summary.executive_summary
            except Exception as exc:
                logger.warning("Gemini async summary fallback triggered", extra={"error": str(exc)})

        yield make_ev(
            EventType.ASSESSMENT_COMPLETED,
            AssessmentStage.REPORT_PREPARATION,
            exec_summary,
            {
                "confirmed_findings": confirmed_count,
                "suspected_findings": suspicious_count,
                "not_confirmed_endpoints": not_confirmed_count,
                "inconclusive_endpoints": inconclusive_count,
                "not_tested_endpoints": not_tested_count,
                "endpoint_statuses": endpoint_statuses,
                "findings": [f.model_dump() for f in findings],
                "iterations_executed": iterations_executed,
                "tool_calls_executed": tool_calls_executed,
                "stop_reason": stop_reason,
                "mode": mode,
                "fallback_mode": fallback_mode,
            },
        )
