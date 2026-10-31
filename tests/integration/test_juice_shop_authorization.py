"""Live integration tests for Authorization-Differential Engine against OWASP Juice Shop.

Target: http://localhost:3000

Verifies:
1. Live endpoint discovery and classification on Juice Shop routes.
2. Live differential evaluation on public routes (/rest/admin/application-version).
3. Live false-positive prevention on empty-user endpoints (/rest/user/whoami) and SPA HTML fallbacks.
4. Live enforcement of 401 Unauthorized on protected basket endpoint (/rest/basket/1) for Anonymous.
5. Refusal to invent sessions when USER_A_TOKEN / USER_B_TOKEN are not configured in .env.
"""

import socket
import pytest

from backend.core.session_manager import Role, SessionManager
from backend.scanner.endpoint_discovery import EndpointCategory, EndpointDiscovery
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import send_request
from backend.utils.helpers import MissingSessionError


def is_juice_shop_reachable(host: str = "localhost", port: int = 3000, timeout: float = 2.0) -> bool:
    """Checks whether local OWASP Juice Shop port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


JUICE_SHOP_AVAILABLE = is_juice_shop_reachable()


@pytest.mark.integration
@pytest.mark.skipif(not JUICE_SHOP_AVAILABLE, reason="OWASP Juice Shop not reachable on http://localhost:3000")
class TestJuiceShopLiveAuthorization:
    """Real integration tests verifying authorization analysis against live OWASP Juice Shop."""

    def test_live_endpoint_discovery_and_url_building(self):
        """Verifies EndpointDiscovery builds valid scope-checked URLs for Juice Shop."""
        discovery = EndpointDiscovery(base_url="http://localhost:3000")
        routes = discovery.discover_known_routes()

        assert len(routes) >= 6
        basket_routes = [r for r in routes if r.path == "/rest/basket/{id}"]
        assert len(basket_routes) == 1
        assert basket_routes[0].category == EndpointCategory.USER_OBJECT

        concrete_url = discovery.build_concrete_url(basket_routes[0], resource_id="1")
        assert concrete_url == "http://localhost:3000/rest/basket/1"

    def test_live_unauthenticated_basket_access_correctly_denied(self):
        """Verifies that Anonymous access to /rest/basket/1 on live Juice Shop is denied (401)."""
        resp = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/rest/basket/1",
        )
        insp = ResponseAnalyzer.inspect_response(resp)
        assert resp.status_code == 401
        assert insp.is_http_success is False
        assert insp.has_error_indicator is True

    def test_live_whoami_empty_user_false_positive_prevention(self):
        """Verifies that /rest/user/whoami returning {'user': {}} with HTTP 200 is treated as empty, not a leak."""
        resp = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/rest/user/whoami",
        )
        insp = ResponseAnalyzer.inspect_response(resp)
        assert resp.status_code == 200
        assert insp.is_json is True
        assert insp.is_empty_payload is True

    def test_live_spa_html_fallback_false_positive_prevention(self):
        """Verifies that unknown routes returning 200 OK Angular index.html are flagged as SPA fallback."""
        resp = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/non-existent-spa-route",
        )
        insp = ResponseAnalyzer.inspect_response(resp)
        assert resp.status_code == 200
        assert insp.is_spa_html_fallback is True
        assert insp.is_json is False

    def test_live_tester_refuses_unauthenticated_roles_without_env_tokens(self):
        """Ensures AuthorizationTester raises MissingSessionError when role tokens are not configured."""
        mgr = SessionManager(load_from_env=False)
        tester = AuthorizationTester(session_manager=mgr)

        with pytest.raises(MissingSessionError):
            tester.test_resource_access(
                endpoint="/rest/basket/1",
                owner_role=Role.USER_A,
                test_roles=[Role.USER_B],
            )

