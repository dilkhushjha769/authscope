"""Test Suite for BOLA / IDOR Detection Engine.

Covers:
- User A ownership baseline verification.
- User B cross-account unauthorized access detection (confirmed BOLA/IDOR).
- Secure authorization control case (properly denied access 401/403).
- Missing credentials or unauthenticated session -> NOT_TESTED.
- Unknown resource ownership without guessing -> INCONCLUSIVE.
- User A baseline request failure -> INCONCLUSIVE.
- Public resource false positive prevention.
- HTTP 200 SPA HTML fallback / empty JSON false positive rejection.
"""

import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict
from backend.analysis.evidence_validator import EvidenceValidationStatus


def _create_test_tester(transport: httpx.MockTransport) -> AuthorizationTester:
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    # Configure authenticated personas
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="jwt_token_user_a")
    mgr.authenticate_role(Role.USER_B, "userb@test.com", "passB", token="jwt_token_user_b")
    mgr.register_resource_ownership(Role.USER_A, "basket", "1")
    mgr.register_resource_ownership(Role.USER_B, "basket", "2")

    client = httpx.Client(transport=transport, follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    return AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)


@pytest.mark.security
def test_user_a_ownership_baseline_and_b_cross_account_bola_confirmed():
    """Verifies 10-step ownership-differential detects and confirms real BOLA/IDOR."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        # Juice Shop vulnerable basket endpoint behavior:
        # Returns User 1's basket regardless of whether User A or User B calls it
        if "/rest/basket/1" in str(request.url):
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={
                    "status": "success",
                    "data": {
                        "id": 1,
                        "UserId": 1,
                        "owner": "usera@test.com",
                        "Products": [{"id": 4, "name": "Apple Juice", "price": 1.99}],
                    },
                },
            )
        return httpx.Response(404, json={"error": "Not Found"})

    transport = httpx.MockTransport(handler)
    tester = _create_test_tester(transport)

    # Execute BOLA test on User A's basket (id=1)
    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.is_confirmed is True
    assert result.is_discrepancy_detected is True
    assert result.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert len(result.evidence_artifacts) >= 1

    # Verify evidence artifact properties
    artifact = result.evidence_artifacts[0]
    assert artifact.test_role == Role.USER_B
    assert artifact.authorized_role == Role.USER_A
    assert artifact.response_status == 200
    assert "jwt_token_user_a" not in artifact.sanitized_response_evidence
    assert "jwt_token_user_b" not in artifact.sanitized_response_evidence
    assert artifact.evidence_sha256 != ""
    assert len(artifact.evidence_sha256) == 64


@pytest.mark.security
def test_secure_authorization_control_case():
    """Verifies that properly enforced 401/403 authorization is NOT flagged as a vulnerability."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/basket/1" in str(request.url):
            if "jwt_token_user_a" in auth:
                return httpx.Response(200, json={"id": 1, "UserId": 1, "items": ["Orange Juice"]})
            else:
                return httpx.Response(403, json={"error": "Access Denied: You do not own this basket."})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    tester = _create_test_tester(transport)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.is_confirmed is False
    assert result.is_discrepancy_detected is False
    assert result.overall_verdict == AccessVerdict.CORRECTLY_DENIED


@pytest.mark.security
def test_missing_credentials_returns_not_tested():
    """Engine must return NOT_TESTED if valid separate sessions are unavailable, never inventing tokens."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    # User A is authenticated, but User B has NO session/credentials
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="token_a")

    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)), follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.overall_verdict == AccessVerdict.NOT_TESTED
    assert result.is_confirmed is False
    assert "unavailable" in result.summary.lower()


@pytest.mark.security
def test_incorrect_ownership_or_missing_id_returns_inconclusive():
    """Engine must return INCONCLUSIVE when resource ID cannot be established without guessing."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="token_a")
    mgr.authenticate_role(Role.USER_B, "userb@test.com", "passB", token="token_b")
    # No owned resources registered for User A

    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)), follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/{basketId}",
        resource_id=None,  # No ID provided and none registered
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert result.is_confirmed is False
    assert "inconclusive" in result.summary.lower()


@pytest.mark.security
def test_explicit_id_without_configured_owner_is_not_requested():
    """A supplied numeric ID alone does not establish that User A owns the object."""
    guard = ScopeGuard()
    manager = SessionManager(load_from_env=False)
    manager.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="token_a")
    manager.authenticate_role(Role.USER_B, "userb@test.com", "passB", token="token_b")
    requested = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requested
        requested = True
        return httpx.Response(200, json={"id": 1, "UserId": 1})

    executor = RequestExecutor(
        scope_guard=guard,
        session_manager=manager,
        client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    tester = AuthorizationTester(executor=executor, session_manager=manager, scope_guard=guard)
    result = tester.test_bola_idor(
        endpoint="/rest/basket/{id}",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert requested is False
    assert result.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert result.is_confirmed is False


@pytest.mark.security
def test_user_a_baseline_failure_returns_inconclusive():
    """If User A's baseline request fails (e.g. 500 error), test returns INCONCLUSIVE."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "Database error"})

    transport = httpx.MockTransport(handler)
    tester = _create_test_tester(transport)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert result.is_confirmed is False
    assert "baseline" in result.summary.lower()


@pytest.mark.security
def test_public_resource_not_flagged_as_idor():
    """Endpoints returning public catalog data to both roles are NOT flagged as IDOR."""
    def handler(request: httpx.Request) -> httpx.Response:
        # Public product catalog item
        return httpx.Response(
            200,
            json={"id": 1, "name": "Apple Juice", "description": "Fresh juice", "price": 1.99}
        )

    transport = httpx.MockTransport(handler)
    tester = _create_test_tester(transport)

    # Public version endpoint is classified as EndpointCategory.PUBLIC
    result = tester.test_resource_access(
        endpoint="http://localhost:3000/rest/admin/application-version",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
        method="GET",
    )

    assert result.overall_verdict == AccessVerdict.ALLOWED_ACCESS
    assert result.is_confirmed is False


@pytest.mark.security
def test_spa_html_fallback_200_not_flagged_as_idor():
    """SPA fallback returning HTTP 200 with HTML document must not be flagged as IDOR."""
    def handler(request: httpx.Request) -> httpx.Response:
        # Single Page Application HTML fallback for missing API route
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text="<!doctype html><html><head><title>Juice Shop</title></head><body><app-root></app-root></body></html>",
        )

    transport = httpx.MockTransport(handler)
    tester = _create_test_tester(transport)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    # Baseline request fails because it's an SPA HTML fallback
    assert result.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert result.is_confirmed is False
