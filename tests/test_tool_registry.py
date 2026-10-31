"""Comprehensive unit and integration test suite for AuthScope Tool Registry.

Verifies:
1. Tool registration and allowlist enforcement.
2. Rejection of unknown tools and arbitrary functions.
3. Strict Pydantic argument validation and error handling.
4. ScopeGuard boundary enforcement (preventing out-of-scope targets).
5. RequestExecutor non-destructive method restrictions (prohibiting POST/PUT/DELETE).
6. Lifecycle event emission (tool_started, tool_completed, tool_failed, evidence_validated).
7. Execution of Website, Authorization, Source, and Reporting tool suites.
8. Compatibility with Claude/Gemini function declaration exports.
"""

from pathlib import Path
import pytest
from typing import List
import httpx
from pydantic import BaseModel, Field

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.tools.registry import (
    ToolDefinition,
    ToolRegistry,
    UnknownToolError,
)
from backend.tools.schemas import (
    ToolCategory,
    ToolCompletedEvent,
    ToolEventBase,
    ToolExecutionContext,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolFailedEvent,
    ToolStartedEvent,
    EvidenceValidatedEvent,
    ValidateTargetInput,
    ValidateTargetOutput,
    DiscoverEndpointsInput,
    InspectEndpointInput,
    AnalyzeResponseInput,
    CompareEndpointAccessInput,
    TestAccessControlInput,
    DetectIdorInput,
    MapEndpointToCodeInput,
    AnalyzeSourceCodeInput,
    ValidateEvidenceInput,
    ExplainFindingInput,
    GenerateRemediationInput,
    GetAssessmentSummaryInput,
)
from backend.agent.tools import AgentTools, TOOL_DEFINITIONS


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def mock_scope_guard() -> ScopeGuard:
    """Provides a ScopeGuard allowing only localhost:3000."""
    return ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http", "https"]
    )


@pytest.fixture
def mock_executor(mock_scope_guard: ScopeGuard, mock_session_manager: SessionManager) -> RequestExecutor:
    """Provides a RequestExecutor wired to mock transport returning controlled JSON responses."""
    def handler(request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        auth_header = request.headers.get("authorization", "")
        # Simulate /rest/basket/1
        if "/rest/basket/1" in url_path:
            if "mock_token_a" in auth_header:
                return httpx.Response(200, json={"status": "success", "data": {"id": 1, "owner": "user_a"}})
            elif "mock_token_b" in auth_header:
                # Simulated BOLA/IDOR vulnerability: User B can read User A's basket!
                return httpx.Response(200, json={"status": "success", "data": {"id": 1, "owner": "user_a"}})
            else:
                return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return RequestExecutor(scope_guard=mock_scope_guard, session_manager=mock_session_manager, client=client)


@pytest.fixture
def mock_session_manager() -> SessionManager:
    """Provides a SessionManager pre-configured with test role sessions."""
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "userA@juice-sh.op", "passA", token="mock_token_a")
    mgr.authenticate_role(Role.USER_B, "userB@juice-sh.op", "passB", token="mock_token_b")
    mgr.authenticate_role(Role.ADMIN, "admin@juice-sh.op", "passAdmin", token="mock_token_admin")
    sess_a = mgr.get_session(Role.USER_A)
    sess_a.register_owned_resource("basket", "1")
    return mgr


@pytest.fixture
def registry(
    mock_scope_guard: ScopeGuard,
    mock_executor: RequestExecutor,
    mock_session_manager: SessionManager
) -> ToolRegistry:
    """Provides a standard ToolRegistry instance."""
    return ToolRegistry(
        scope_guard=mock_scope_guard,
        executor=mock_executor,
        session_manager=mock_session_manager
    )


# ==============================================================================
# Test Suite 1: Tool Registry Core & Registration
# ==============================================================================


@pytest.mark.unit
class TestToolRegistryCore:
    """Verifies registry initialization, allowlist enforcement, and metadata exports."""

    def test_default_tools_registered(self, registry: ToolRegistry):
        """Ensures all essential tools across the 4 domains are registered by default."""
        tools = registry.list_tools()
        assert len(tools) >= 12
        tool_names = [t["name"] for t in tools]

        # Website assessment
        assert "validate_target" in tool_names
        assert "discover_endpoints" in tool_names
        assert "inspect_endpoint" in tool_names
        assert "analyze_response" in tool_names

        # Authorization testing
        assert "compare_endpoint_access" in tool_names
        assert "test_access_control" in tool_names
        assert "detect_idor" in tool_names

        # Source analysis
        assert "map_endpoint_to_code" in tool_names
        assert "analyze_source_code" in tool_names

        # Reporting
        assert "validate_evidence" in tool_names
        assert "explain_finding" in tool_names
        assert "generate_remediation" in tool_names
        assert "get_assessment_summary" in tool_names

    def test_unknown_tool_rejected(self, registry: ToolRegistry):
        """Calling an unregistered tool returns PERMISSION_DENIED and descriptive error."""
        result = registry.execute_tool("arbitrary_command_exec", {"cmd": "whoami"})
        assert result.status == ToolExecutionStatus.PERMISSION_DENIED
        assert "Unknown tool" in (result.error or "")

    def test_invalid_argument_rejection(self, registry: ToolRegistry):
        """Calling a tool with invalid or missing required parameters returns VALIDATION_ERROR."""
        # validate_target requires 'url'
        result = registry.execute_tool("validate_target", {})
        assert result.status == ToolExecutionStatus.VALIDATION_ERROR
        assert "url" in (result.error or "").lower()

    def test_anthropic_and_gemini_declarations_export(self, registry: ToolRegistry):
        """Verifies schema exports for Anthropic Claude and Google Gemini function calling."""
        claude_decs = registry.get_anthropic_declarations()
        gemini_decs = registry.get_gemini_declarations()

        assert len(claude_decs) == len(registry._tools)
        assert len(gemini_decs) == len(registry._tools)

        # Check Claude schema structure
        assert "name" in claude_decs[0]
        assert "description" in claude_decs[0]
        assert "input_schema" in claude_decs[0]

        # Check Gemini schema structure
        assert "name" in gemini_decs[0]
        assert "description" in gemini_decs[0]
        assert "parameters" in gemini_decs[0]


# ==============================================================================
# Test Suite 2: Lifecycle Events & Streaming (Member 4 Integration)
# ==============================================================================


@pytest.mark.unit
class TestToolStreamingEvents:
    """Verifies that tool execution lifecycle emits events for real-time frontend streaming."""

    def test_tool_execution_emits_started_and_completed_events(self, registry: ToolRegistry):
        """Successful execution emits ToolStartedEvent followed by ToolCompletedEvent."""
        events: List[ToolEventBase] = []
        registry.add_event_listener(lambda ev: events.append(ev))

        result = registry.execute_tool(
            "validate_target",
            {"url": "http://localhost:3000/rest/basket/1"}
        )

        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert len(events) >= 2
        assert isinstance(events[0], ToolStartedEvent)
        assert events[0].tool_name == "validate_target"
        assert isinstance(events[1], ToolCompletedEvent)
        assert events[1].tool_name == "validate_target"

    def test_tool_failure_emits_failed_event(self, registry: ToolRegistry):
        """Tool failure emits ToolFailedEvent with error details and duration."""
        events: List[ToolEventBase] = []
        registry.add_event_listener(lambda ev: events.append(ev))

        result = registry.execute_tool("unknown_tool", {})
        assert result.status == ToolExecutionStatus.PERMISSION_DENIED
        assert len(events) == 1
        assert isinstance(events[0], ToolFailedEvent)
        assert events[0].status == ToolExecutionStatus.PERMISSION_DENIED

    def test_evidence_validation_emits_evidence_validated_event(self, registry: ToolRegistry):
        """Calling validate_evidence emits an EvidenceValidatedEvent."""
        events: List[ToolEventBase] = []
        registry.add_event_listener(lambda ev: events.append(ev))

        result = registry.execute_tool(
            "validate_evidence",
            {
                "finding_id": "fnd_test_01",
                "status_code": 200,
                "evidence_text": '{"data": {"id": 1, "basket": []}}'
            }
        )

        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        evidence_events = [e for e in events if isinstance(e, EvidenceValidatedEvent)]
        assert len(evidence_events) == 1
        assert evidence_events[0].finding_id == "fnd_test_01"
        assert evidence_events[0].is_confirmed is True


# ==============================================================================
# Test Suite 3: Website Assessment Tools
# ==============================================================================


@pytest.mark.unit
class TestWebsiteTools:
    """Verifies website assessment tools adhere strictly to ScopeGuard and safety boundaries."""

    def test_validate_target_in_scope(self, registry: ToolRegistry):
        """Allowed localhost URL returns is_allowed=True."""
        result = registry.execute_tool(
            "validate_target",
            {"url": "http://localhost:3000/rest/basket/1"}
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["is_allowed"] is True

    def test_validate_target_out_of_scope(self, registry: ToolRegistry):
        """Out of scope external URL returns is_allowed=False."""
        result = registry.execute_tool(
            "validate_target",
            {"url": "https://external-attacker.com/steal"}
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["is_allowed"] is False

    def test_discover_endpoints_returns_routes(self, registry: ToolRegistry):
        """Discovers authorized attack surface routes without scanning out-of-scope targets."""
        result = registry.execute_tool("discover_endpoints", {"include_admin": True})
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["endpoint_count"] > 0
        paths = [ep["path"] for ep in result.data["endpoints"]]
        assert any("/rest/basket" in p for p in paths)

    def test_inspect_endpoint_prohibits_post_or_write_methods(self, registry: ToolRegistry):
        """Attempting to use POST/PUT/DELETE via inspect_endpoint raises SCOPE_VIOLATION."""
        result = registry.execute_tool(
            "inspect_endpoint",
            {
                "url": "http://localhost:3000/rest/basket/1",
                "method": "POST"
            }
        )
        assert result.status == ToolExecutionStatus.SCOPE_VIOLATION
        assert "prohibited" in (result.error or "").lower()

    def test_analyze_response_indicators(self, registry: ToolRegistry):
        """Analyzes HTTP status codes and error leak indications."""
        res_401 = registry.execute_tool(
            "analyze_response",
            {"status_code": 401, "body": "Unauthorized"}
        )
        assert res_401.data["verdict"] == "CORRECTLY_DENIED"
        assert res_401.data["is_access_granted"] is False

        res_leak = registry.execute_tool(
            "analyze_response",
            {"status_code": 500, "body": "Fatal SQLite syntax error at line 42"}
        )
        assert res_leak.data["indicates_leak"] is True


# ==============================================================================
# Test Suite 4: Authorization Testing Tools
# ==============================================================================


@pytest.mark.unit
class TestAuthorizationTools:
    """Verifies authorization testing tools execute multi-role comparisons and IDOR checks."""

    def test_test_access_control_single_role(self, registry: ToolRegistry):
        """Executes access control test under ANONYMOUS role."""
        result = registry.execute_tool(
            "test_access_control",
            {
                "endpoint": "/rest/basket/1",
                "role": "ANONYMOUS"
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["role"] == "ANONYMOUS"

    def test_compare_endpoint_access_invalid_role_rejected(self, registry: ToolRegistry):
        """Reject fabricated or invalid roles."""
        result = registry.execute_tool(
            "compare_endpoint_access",
            {
                "endpoint": "/rest/basket/1",
                "test_roles": ["SUPER_HACKER_ROLE"]
            }
        )
        assert result.status == ToolExecutionStatus.FAILED
        assert "Invalid role" in (result.error or "")

    def test_detect_idor_tool(self, registry: ToolRegistry):
        """Tests IDOR detection tool wrapper."""
        result = registry.execute_tool(
            "detect_idor",
            {
                "endpoint_template": "/rest/basket/{id}",
                "victim_resource_id": "1",
                "attacker_role": "USER_B"
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["victim_resource_id"] == "1"
        assert result.data["attacker_role"] == "USER_B"


# ==============================================================================
# Test Suite 5: Source Analysis Tools
# ==============================================================================


@pytest.mark.unit
class TestSourceAnalysisTools:
    """Verifies source code mapping and static snippet verification tools."""

    def test_map_endpoint_to_code(self, registry: ToolRegistry, tmp_path: Path):
        """Correlates an endpoint to backend code using CodeMapper."""
        # Point registry source tools to a mock repo
        routes_dir = tmp_path / "routes"
        routes_dir.mkdir()
        basket_js = routes_dir / "basket.js"
        basket_js.write_text(
            "router.get('/:id', function retrieveBasket(req, res) { res.json({}); });",
            encoding="utf-8"
        )

        from backend.tools.source_tools import SourceTools
        registry.source_tools = SourceTools(repo_root=tmp_path, repository_name="test_repo")
        registry._register_default_tools()

        result = registry.execute_tool(
            "map_endpoint_to_code",
            {"endpoint": "/rest/basket/1", "http_method": "GET"}
        )

        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["verified"] is True
        assert result.data["location"]["file_path"] == "routes/basket.js"

    def test_analyze_source_code_verifies_disk_authenticity(self, registry: ToolRegistry, tmp_path: Path):
        """Rejects fabricated line numbers or snippets not matching disk."""
        target_file = tmp_path / "service.py"
        target_file.write_text("def get_data():\n    return {'secret': True}\n", encoding="utf-8")

        from backend.tools.source_tools import SourceTools
        registry.source_tools = SourceTools(repo_root=tmp_path)
        registry._register_default_tools()

        # Valid lines
        valid_res = registry.execute_tool(
            "analyze_source_code",
            {
                "file_path": "service.py",
                "start_line": 1,
                "end_line": 2,
                "function_name": "get_data"
            }
        )
        assert valid_res.status == ToolExecutionStatus.SUCCESS
        assert valid_res.data["verified"] is True

        # Invalid lines (exceeds file)
        invalid_res = registry.execute_tool(
            "analyze_source_code",
            {
                "file_path": "service.py",
                "start_line": 100,
                "end_line": 150
            }
        )
        assert invalid_res.status == ToolExecutionStatus.SUCCESS
        assert invalid_res.data["verified"] is False


# ==============================================================================
# Test Suite 6: Reporting Tools
# ==============================================================================


@pytest.mark.unit
class TestReportingTools:
    """Verifies evidence validation, finding explanation, and remediation tools."""

    def test_validate_evidence_rejects_bearer_jwt_leak(self, registry: ToolRegistry):
        """Evidence with raw Bearer JWT in headers is flagged and rejected."""
        result = registry.execute_tool(
            "validate_evidence",
            {
                "finding_id": "fnd_jwt_leak",
                "status_code": 200,
                "evidence_text": "Sensitive user records",
                "headers": {
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc"
                }
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["is_valid"] is False
        assert result.data["has_secret_leak"] is True
        assert result.data["validation_status"] == "REJECTED_FALSE_POSITIVE"

    def test_validate_evidence_confirms_clean_evidence(self, registry: ToolRegistry):
        """Clean evidence is confirmed and returns SHA-256 hash."""
        result = registry.execute_tool(
            "validate_evidence",
            {
                "finding_id": "fnd_clean_01",
                "status_code": 200,
                "evidence_text": '{"data": "sanitized_basket_content"}',
                "headers": {"content-type": "application/json"}
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert result.data["is_valid"] is True
        assert result.data["has_secret_leak"] is False
        assert result.data["validation_status"] == "CONFIRMED"
        assert result.data["evidence_hash"] is not None

    def test_explain_finding(self, registry: ToolRegistry):
        """Generates structured finding narrative and root cause."""
        result = registry.execute_tool(
            "explain_finding",
            {
                "finding_id": "fnd_01",
                "title": "BOLA on basket endpoint",
                "endpoint": "/rest/basket/1",
                "actual_behavior": "Retrieved Victim user basket data"
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert "Missing server-side ownership" in result.data["root_cause"]

    def test_generate_remediation(self, registry: ToolRegistry):
        """Produces actionable server-side remediation recommendations."""
        result = registry.execute_tool(
            "generate_remediation",
            {
                "finding_id": "fnd_01",
                "endpoint": "/rest/basket/1",
                "code_snippet": "router.get('/:id', function(req, res) { ... })"
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS, f"Tool failed with error: {result.error}"
        assert "server-side" in result.data["recommendation"].lower()
        assert result.data["code_fix"] is not None


# ==============================================================================
# Test Suite 7: Backward Compatibility with AgentTools
# ==============================================================================


@pytest.mark.unit
class TestAgentToolsCompatibility:
    """Ensures AgentTools in backend/agent/tools.py delegates correctly to ToolRegistry."""

    def test_agent_tools_check_scope_allowed(self, mock_scope_guard: ScopeGuard, mock_executor: RequestExecutor):
        """Existing test contract: check_scope on allowed URL."""
        tools = AgentTools(scope_guard=mock_scope_guard, executor=mock_executor)
        result = tools.execute_tool("check_scope", {"url": "http://localhost:3000/rest/basket/1"})
        assert result["is_allowed"] is True

    def test_agent_tools_check_scope_rejected(self, mock_scope_guard: ScopeGuard, mock_executor: RequestExecutor):
        """Existing test contract: check_scope on external URL."""
        tools = AgentTools(scope_guard=mock_scope_guard, executor=mock_executor)
        result = tools.execute_tool("check_scope", {"url": "https://external-target.com"})
        assert result["is_allowed"] is False

    def test_agent_tools_compare_access_legacy(self, mock_scope_guard: ScopeGuard, mock_executor: RequestExecutor):
        """Existing test contract: compare_access legacy behavior."""
        tools = AgentTools(scope_guard=mock_scope_guard, executor=mock_executor)
        result = tools.execute_tool("compare_access", {"endpoint": "/rest/basket/1", "method": "GET"})
        assert result["endpoint"] == "/rest/basket/1"
        assert result["is_discrepancy_detected"] is False

    def test_agent_tools_dispatches_registry_tools(self, mock_scope_guard: ScopeGuard, mock_executor: RequestExecutor):
        """AgentTools can execute new registry tools like discover_endpoints."""
        tools = AgentTools(scope_guard=mock_scope_guard, executor=mock_executor)
        result = tools.execute_tool("discover_endpoints", {})
        assert "endpoint_count" in result
        assert result["endpoint_count"] > 0
