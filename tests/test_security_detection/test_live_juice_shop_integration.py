"""Live Integration Test Suite against Authorized Target (OWASP Juice Shop @ http://localhost:3000).

Demonstrates:
1. Actual website requests against authorized local target.
2. ScopeGuard boundary enforcement on real network requests.
3. Real response comparison and structural inspection.
4. Correct INCONCLUSIVE handling when user sessions or resource ownership are unverified.
5. Secure control case behavior.

Only executes network calls against explicitly allowlisted target: http://localhost:3000.
"""

import httpx
import pytest

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.endpoint_discovery import EndpointDiscovery
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer


def _is_juice_shop_running() -> bool:
    try:
        r = httpx.get("http://localhost:3000", timeout=1.0)
        return r.status_code == 200 and "OWASP Juice Shop" in r.text
    except Exception:
        return False


JUICE_SHOP_AVAILABLE = _is_juice_shop_running()
skip_if_no_juice_shop = pytest.mark.skipif(
    not JUICE_SHOP_AVAILABLE,
    reason="OWASP Juice Shop is not running locally at http://localhost:3000"
)


@pytest.mark.integration
@skip_if_no_juice_shop
def test_live_juice_shop_public_version_request():
    """Demonstrates actual HTTP request to authorized local Juice Shop and response inspection."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr)

    resp = executor.send_request(
        role=Role.ANONYMOUS,
        method="GET",
        url="http://localhost:3000/rest/admin/application-version"
    )

    assert resp.status_code == 200
    assert resp.content_length > 0
    inspection = ResponseAnalyzer.inspect_response(resp)
    assert inspection.is_http_success is True
    assert inspection.is_spa_html_fallback is False


@pytest.mark.integration
@skip_if_no_juice_shop
def test_live_juice_shop_missing_sessions_returns_not_tested():
    """Demonstrates that against a real website, missing sessions return NOT_TESTED without guessing credentials."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    # No credentials in environment or session manager
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr)
    tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.overall_verdict == AccessVerdict.NOT_TESTED
    assert result.is_confirmed is False


@pytest.mark.integration
@skip_if_no_juice_shop
def test_live_juice_shop_unowned_resource_returns_inconclusive():
    """Demonstrates that when resource ownership cannot be verified, engine returns INCONCLUSIVE."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    # Authenticate sessions with tokens
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "passA", token="fake_token_a")
    mgr.authenticate_role(Role.USER_B, "userb@test.com", "passB", token="fake_token_b")
    # Neither user owns resource
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr)
    tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/{basketId}",
        resource_id=None,
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert result.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert result.is_confirmed is False
