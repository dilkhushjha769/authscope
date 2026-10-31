"""Test Suite for Broken Function Level Authorization (BFLA) Detection Engine.

Covers:
- Protected administrative endpoints (/rest/admin/application-configuration, /api/Users).
- Cross-role access evaluation (Anonymous, User A, User B, Admin).
- Vertical privilege escalation detection.
- Admin baseline comparison when Admin is configured.
- Safe probing without inventing Admin credentials when unconfigured.
- Proper access denial (HTTP 401/403) verification as secure control case.
"""

import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict
from backend.tools.authorization_tools import AuthorizationTools
from backend.tools.schemas import TestBflaInput


def _create_bfla_tester(
    transport: httpx.MockTransport,
    include_admin: bool = True
) -> AuthorizationTester:
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="jwt_token_user_a")
    mgr.authenticate_role(Role.USER_B, "userb@test.com", "passB", token="jwt_token_user_b")
    if include_admin:
        mgr.authenticate_role(Role.ADMIN, "admin@test.com", "passAdmin", token="jwt_token_admin")

    client = httpx.Client(transport=transport, follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    return AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)


@pytest.mark.security
def test_bfla_admin_baseline_and_unauthorized_access_confirmed():
    """When Admin baseline is configured and lower-privilege roles access administrative endpoint."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/rest/admin/application-configuration" in url:
            # Simulate vulnerable configuration endpoint leaking app secrets to any caller
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "status": "success",
                    "config": {
                        "application": {"name": "OWASP Juice Shop"},
                        "security": {"cookieSecret": "super_secret_cookie_key"},
                    },
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    tester = _create_bfla_tester(transport, include_admin=True)

    result = tester.test_bfla(
        endpoint="http://localhost:3000/rest/admin/application-configuration",
        admin_role=Role.ADMIN,
        test_roles=[Role.ANONYMOUS, Role.USER_A, Role.USER_B],
    )

    assert result.is_confirmed is True
    assert result.is_discrepancy_detected is True
    assert result.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert len(result.evidence_artifacts) > 0


@pytest.mark.security
def test_bfla_secure_control_case():
    """Properly restricted admin endpoint returns 401/403 to unauthorized roles."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/admin/application-configuration" in str(request.url):
            if "jwt_token_admin" in auth:
                return httpx.Response(200, json={"config": {"app": "secure"}})
            elif "jwt_token_user" in auth:
                return httpx.Response(403, json={"error": "Forbidden: Requires Administrator privileges"})
            else:
                return httpx.Response(401, json={"error": "Unauthorized: Authentication required"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    tester = _create_bfla_tester(transport, include_admin=True)

    result = tester.test_bfla(
        endpoint="http://localhost:3000/rest/admin/application-configuration",
        admin_role=Role.ADMIN,
        test_roles=[Role.ANONYMOUS, Role.USER_A, Role.USER_B],
    )

    assert result.is_confirmed is False
    assert result.is_discrepancy_detected is False
    assert result.overall_verdict == AccessVerdict.CORRECTLY_DENIED


@pytest.mark.security
def test_bfla_without_admin_session_probes_roles_safely():
    """When Admin credentials are unconfigured, engine safely probes without inventing an Admin session."""
    def handler(request: httpx.Request) -> httpx.Response:
        # Both unauthenticated and authenticated users receive sensitive configuration
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            json={"server_settings": {"debug_mode": True, "admin_email": "admin@juice-sh.op"}},
        )

    transport = httpx.MockTransport(handler)
    # Admin is NOT configured
    tester = _create_bfla_tester(transport, include_admin=False)

    result = tester.test_bfla(
        endpoint="http://localhost:3000/rest/admin/application-configuration",
        admin_role=Role.ADMIN,
        test_roles=[Role.ANONYMOUS, Role.USER_A, Role.USER_B],
    )

    assert result.is_discrepancy_detected is True
    # Without an authoritative Admin baseline to compare against, it is flagged as SUSPICIOUS_ACCESS
    assert result.overall_verdict == AccessVerdict.SUSPICIOUS_ACCESS
    assert len(result.evidence_artifacts) > 0


@pytest.mark.security
def test_bfla_vertical_privilege_escalation_detection():
    """Detects when standard user accesses sensitive user management (/api/Users)."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/api/Users" in str(request.url):
            if "jwt_token_admin" in auth or "jwt_token_user_b" in auth:
                # Leaks full user list with password hashes to User B
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {"id": 1, "email": "admin@juice-sh.op", "role": "admin", "password": "hash1"},
                            {"id": 2, "email": "jim@juice-sh.op", "role": "customer", "password": "hash2"},
                        ]
                    },
                )
            return httpx.Response(401)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    tester = _create_bfla_tester(transport, include_admin=True)

    result = tester.test_bfla(
        endpoint="http://localhost:3000/api/Users",
        admin_role=Role.ADMIN,
        test_roles=[Role.USER_B],
    )

    assert result.is_confirmed is True
    assert result.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert result.evidence_artifacts[0].response_status == 200
    # Ensure sensitive fields were redacted in evidence
    assert "hash1" not in result.evidence_artifacts[0].sanitized_response_evidence


@pytest.mark.security
def test_bfla_via_authorization_tools():
    """Verifies that AuthorizationTools exposes test_bfla cleanly to the ToolRegistry."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"admin_data": "secret_dump", "access": "unrestricted"},
        )

    transport = httpx.MockTransport(handler)
    tester = _create_bfla_tester(transport, include_admin=True)
    auth_tools = AuthorizationTools(tester=tester)

    output = auth_tools.test_bfla(
        TestBflaInput(
            endpoint="http://localhost:3000/rest/admin/application-configuration",
            admin_role="admin",
            test_roles=["user_b", "anonymous"],
        )
    )

    assert output.is_bfla_detected is True
    assert output.is_confirmed is True
    assert output.verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
    assert output.vulnerability_title == "Broken Function Level Authorization (BFLA)"
