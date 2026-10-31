"""Security Audit and Boundary Enforcement Tests for AuthScope Tool Registry (Phase 5.3).

Explicitly validates that the Tool Registry cannot be abused or bypassed by Gemini:
1. Rejects unregistered tools (e.g., raw_shell_exec, drop_database, eval_code).
2. Rejects unexpected, malformed, or injected arguments.
3. Blocks unauthorized targets and out-of-scope egress (e.g., evil.com, metadata IPs).
4. Prevents unauthorized scope expansion (e.g., unapproved ports or domains).
5. Enforces ScopeGuard allowlist without bypass.
6. Enforces RequestExecutor safe HTTP handling.
7. Prohibits mutating/destructive HTTP methods (POST, PUT, DELETE, PATCH).
8. Blocks filesystem path traversal and arbitrary filesystem operations.
9. Enforces role authentication and human approval boundaries.
10. Rejects fabricated, empty, or secret-leaking evidence.
"""

from pathlib import Path
import pytest
from typing import List, Dict, Any
import httpx

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.tools.registry import ToolRegistry, UnknownToolError
from backend.tools.schemas import (
    ToolCategory,
    ToolExecutionStatus,
    ValidateTargetInput,
    InspectEndpointInput,
    AnalyzeSourceCodeInput,
    ValidateEvidenceInput,
    CompareEndpointAccessInput,
    DetectIdorInput,
)


@pytest.fixture
def locked_scope_guard() -> ScopeGuard:
    """Scope guard locked strictly to authorized local Juice Shop instance."""
    return ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http"]
    )


@pytest.fixture
def test_session_manager() -> SessionManager:
    """Provides isolated sessions with User A and User B tokens."""
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "usera@juice-sh.op", "passA", token="jwt_token_user_a")
    mgr.authenticate_role(Role.USER_B, "userb@juice-sh.op", "passB", token="jwt_token_user_b")
    mgr.authenticate_role(Role.ADMIN, "admin@juice-sh.op", "passAdmin", token="jwt_token_admin")
    sess_a = mgr.get_session(Role.USER_A)
    sess_a.register_owned_resource("basket", "1")
    return mgr


@pytest.fixture
def mock_executor(locked_scope_guard: ScopeGuard, test_session_manager: SessionManager) -> RequestExecutor:
    """Provides mock transport RequestExecutor preventing any real network outbound."""
    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        auth_hdr = request.headers.get("authorization", "")

        if "localhost:3000/rest/basket/1" in url_str:
            if "jwt_token_user_a" in auth_hdr:
                return httpx.Response(200, json={"data": {"id": 1, "items": []}})
            elif "jwt_token_user_b" in auth_hdr:
                # BOLA simulated condition
                return httpx.Response(200, json={"data": {"id": 1, "items": []}})
            else:
                return httpx.Response(401, json={"error": "Unauthorized"})

        return httpx.Response(200, json={"status": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return RequestExecutor(scope_guard=locked_scope_guard, session_manager=test_session_manager, client=client)


@pytest.fixture
def registry(
    locked_scope_guard: ScopeGuard,
    mock_executor: RequestExecutor,
    test_session_manager: SessionManager,
    tmp_path: Path
) -> ToolRegistry:
    """Provides an audited ToolRegistry instance."""
    from backend.tools.source_tools import SourceTools
    source_tools = SourceTools(repo_root=tmp_path, repository_name="audit_repo")
    return ToolRegistry(
        scope_guard=locked_scope_guard,
        executor=mock_executor,
        session_manager=test_session_manager,
        source_tools=source_tools
    )


# ==============================================================================
# Security Audit Test Suite (Scenarios 1 - 10)
# ==============================================================================


@pytest.mark.security
class TestToolRegistrySecurityAudit:
    """Rigorous security boundary validation against model prompt-injection & abuse vectors."""

    # --------------------------------------------------------------------------
    # Scenario 1: Unregistered tool invocation
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("dangerous_tool", [
        "raw_shell_exec",
        "drop_database",
        "eval_code",
        "system_bash",
        "cmd_exec",
        "read_secret_keys",
        "admin_grant_all",
    ])
    def test_scenario_1_unregistered_tools_rejected(self, registry: ToolRegistry, dangerous_tool: str):
        """Attempts to invoke non-allowlisted dangerous tools are blocked with PERMISSION_DENIED."""
        result = registry.execute_tool(dangerous_tool, {"command": "whoami"})
        assert result.status == ToolExecutionStatus.PERMISSION_DENIED
        assert "Unknown tool" in (result.error or "")
        assert result.data is None

    # --------------------------------------------------------------------------
    # Scenario 2: Unexpected or malformed arguments
    # --------------------------------------------------------------------------
    def test_scenario_2_unexpected_or_injected_arguments(self, registry: ToolRegistry):
        """Tool calls with malformed data, invalid types, or missing parameters fail validation."""
        # Missing required parameter 'url'
        res1 = registry.execute_tool("validate_target", {})
        assert res1.status == ToolExecutionStatus.VALIDATION_ERROR

        # Wrong type: integer instead of string url
        res2 = registry.execute_tool("validate_target", {"url": 12345})
        # Pydantic may convert int to string or fail validation; if url must be str:
        res3 = registry.execute_tool("validate_target", {"url": None})
        assert res3.status == ToolExecutionStatus.VALIDATION_ERROR

        # Injected SQL syntax in numeric line fields
        res4 = registry.execute_tool("analyze_source_code", {
            "file_path": "service.py",
            "start_line": "1; DROP TABLE findings;",
            "end_line": 10
        })
        assert res4.status == ToolExecutionStatus.VALIDATION_ERROR

    # --------------------------------------------------------------------------
    # Scenario 3: Unauthorized target access
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("unauthorized_target", [
        "https://evil-external-target.com",
        "http://google.com",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
    ])
    def test_scenario_3_unauthorized_target_rejected(self, registry: ToolRegistry, unauthorized_target: str):
        """Attempts to target non-allowlisted external or cloud metadata targets are disallowed."""
        # Check via validate_target
        res_val = registry.execute_tool("validate_target", {"url": unauthorized_target})
        assert res_val.status == ToolExecutionStatus.SUCCESS
        assert res_val.data["is_allowed"] is False

        # Attempt to inspect unauthorized target via inspect_endpoint
        res_insp = registry.execute_tool("inspect_endpoint", {"url": unauthorized_target, "method": "GET"})
        assert res_insp.status == ToolExecutionStatus.SCOPE_VIOLATION
        assert "scope" in (res_insp.error or "").lower()

    # --------------------------------------------------------------------------
    # Scenario 4: Scope expansion attempts
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("out_of_scope_url", [
        "http://localhost:8080/admin",      # Prohibited port 8080
        "http://localhost:22/ssh",          # Prohibited SSH port
        "http://localhost:5432/sql",        # Prohibited Postgres port
        "https://localhost:3000/api",       # Prohibited scheme HTTPS when HTTP configured
        "http://subdomain.localhost:3000/", # Unauthorized subdomain
    ])
    def test_scenario_4_scope_expansion_prevented(self, registry: ToolRegistry, out_of_scope_url: str):
        """ScopeGuard blocks attempts to expand testing to unapproved ports or hosts."""
        result = registry.execute_tool("validate_target", {"url": out_of_scope_url})
        assert result.data["is_allowed"] is False
        reason_lower = result.data["reason"].lower()
        assert "outside the authorized allowlist" in reason_lower or "not allowed" in reason_lower or "prohibited" in reason_lower

    # --------------------------------------------------------------------------
    # Scenario 5: ScopeGuard bypass attempts
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("evasion_url", [
        "http://localhost:3000@evil.com",         # Userinfo trick
        "http://localhost.evil.com:3000",         # Suffix match spoofing
        "http://evil.com#localhost:3000",         # Fragment trick
        "http://0.0.0.0:3000/",                   # 0.0.0.0 wildcard
        "http://[::1]:3000/",                     # IPv6 localhost evasion
    ])
    def test_scenario_5_scope_guard_evasion_blocked(self, registry: ToolRegistry, evasion_url: str):
        """ScopeGuard detects and neutralizes URL parser confusion and host spoofing."""
        result = registry.execute_tool("validate_target", {"url": evasion_url})
        assert result.data["is_allowed"] is False

    # --------------------------------------------------------------------------
    # Scenario 6: RequestExecutor bypass attempts
    # --------------------------------------------------------------------------
    def test_scenario_6_request_executor_bypass_blocked(self, registry: ToolRegistry):
        """All network inspection tools delegate through RequestExecutor with ScopeGuard checks."""
        # inspect_endpoint with an out-of-scope URL must be intercepted by RequestExecutor
        result = registry.execute_tool(
            "inspect_endpoint",
            {"url": "http://192.168.1.1:3000/admin", "method": "GET"}
        )
        assert result.status == ToolExecutionStatus.SCOPE_VIOLATION
        assert result.data is None

    # --------------------------------------------------------------------------
    # Scenario 7: Restricted HTTP methods
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("prohibited_method", ["POST", "PUT", "DELETE", "PATCH", "CONNECT", "TRACE"])
    def test_scenario_7_prohibited_http_methods_rejected(self, registry: ToolRegistry, prohibited_method: str):
        """inspect_endpoint enforces read-only GET/HEAD policy and rejects mutating methods."""
        result = registry.execute_tool(
            "inspect_endpoint",
            {
                "url": "http://localhost:3000/rest/basket/1",
                "method": prohibited_method
            }
        )
        assert result.status == ToolExecutionStatus.SCOPE_VIOLATION
        assert "prohibited" in (result.error or "").lower()

    # --------------------------------------------------------------------------
    # Scenario 8: Filesystem path traversal
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("traversal_path", [
        "../../../../etc/passwd",
        "../../../../windows/system32/cmd.exe",
        "routes/../../../../.env",
        "/etc/shadow",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ])
    def test_scenario_8_filesystem_traversal_blocked(self, registry: ToolRegistry, traversal_path: str):
        """analyze_source_code prevents path traversal outside the repository boundary."""
        result = registry.execute_tool(
            "analyze_source_code",
            {
                "file_path": traversal_path,
                "start_line": 1,
                "end_line": 5
            }
        )
        assert result.status == ToolExecutionStatus.SUCCESS
        # Must report unverified / invalid, never read host files
        assert result.data["verified"] is False
        assert "traversal" in (result.data["error"] or "").lower() or "not found" in (result.data["error"] or "").lower()

    # --------------------------------------------------------------------------
    # Scenario 9: Permission and human approval boundaries
    # --------------------------------------------------------------------------
    def test_scenario_9_unauthenticated_role_rejected(self, registry: ToolRegistry):
        """Attempting to probe with an unauthenticated or fabricated role fails safely."""
        result = registry.execute_tool(
            "test_access_control",
            {
                "endpoint": "/rest/basket/1",
                "role": "NON_EXISTENT_SUPERUSER"
            }
        )
        assert result.status == ToolExecutionStatus.FAILED
        assert "Invalid role" in (result.error or "")

    # --------------------------------------------------------------------------
    # Scenario 10: Incomplete or fabricated evidence rejected
    # --------------------------------------------------------------------------
    def test_scenario_10_fabricated_or_secret_leaking_evidence_rejected(self, registry: ToolRegistry):
        """Evidence containing raw Bearer JWTs, 404/500 errors, or empty strings cannot be CONFIRMED."""
        # 1. 404 response claimed as finding
        res_404 = registry.execute_tool("validate_evidence", {
            "finding_id": "fnd_404",
            "status_code": 404,
            "evidence_text": "Not Found"
        })
        assert res_404.data["is_valid"] is False
        assert res_404.data["validation_status"] == "REJECTED_FALSE_POSITIVE"

        # 2. Empty evidence body
        res_empty = registry.execute_tool("validate_evidence", {
            "finding_id": "fnd_empty",
            "status_code": 200,
            "evidence_text": "   "
        })
        assert res_empty.data["is_valid"] is False

        # 3. Unredacted Bearer token in headers
        res_leak = registry.execute_tool("validate_evidence", {
            "finding_id": "fnd_leak",
            "status_code": 200,
            "evidence_text": "Valid response body",
            "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.xyz"}
        })
        assert res_leak.data["is_valid"] is False
        assert res_leak.data["has_secret_leak"] is True
        assert res_leak.data["validation_status"] == "REJECTED_FALSE_POSITIVE"
