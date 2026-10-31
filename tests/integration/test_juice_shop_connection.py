"""Real-world integration tests verifying AuthScope against OWASP Juice Shop.

Target:
http://localhost:3000

Validates:
1. Real HTTP transmission against live target via send_request().
2. Correct capture of status codes, headers, response latency, and metadata.
3. Pre-flight ScopeGuard validation on live execution pipeline.
4. Token and cookie redaction in logging and request metadata.
5. Security boundary enforcement (external domains, unauthorized ports, non-GET methods, redirect suppression).
"""

import logging
import socket
import pytest
import httpx

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor, send_request
from backend.utils.helpers import (
    ScopeViolationError,
    UnsupportedMethodError,
    InvalidTargetURLError,
)


def is_juice_shop_reachable(host: str = "localhost", port: int = 3000, timeout: float = 2.0) -> bool:
    """Checks whether local OWASP Juice Shop port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


JUICE_SHOP_AVAILABLE = is_juice_shop_reachable()


@pytest.mark.integration
class TestJuiceShopRealConnection:
    """Real integration tests asserting live HTTP execution against OWASP Juice Shop."""

    @pytest.mark.skipif(not JUICE_SHOP_AVAILABLE, reason="OWASP Juice Shop not reachable on http://localhost:3000")
    def test_live_homepage_get_request(self):
        """Sends a real, safe GET request to the Juice Shop homepage and validates response capture."""
        target_url = "http://localhost:3000/"

        response = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url=target_url
        )

        # 1. Verify response status
        assert response.status_code == 200, f"Expected 200 OK from Juice Shop homepage, got {response.status_code}"

        # 2. Verify response content
        assert len(response.body) > 0, "Response body should not be empty"
        assert response.content_length > 0, "Content length should be greater than 0"
        assert "<!doctype html>" in response.body.lower() or "juice shop" in response.body.lower()

        # 3. Verify telemetry
        assert response.response_time_ms > 0, "Response time latency should be recorded"
        assert response.is_truncated is False, "Standard homepage should not exceed 1MB truncation limit"

        # 4. Verify request metadata
        metadata = response.request_metadata
        assert metadata is not None, "Request metadata must be captured"
        assert metadata.method == "GET"
        assert metadata.url == target_url
        assert metadata.role == Role.ANONYMOUS.value

    @pytest.mark.skipif(not JUICE_SHOP_AVAILABLE, reason="OWASP Juice Shop not reachable on http://localhost:3000")
    def test_live_admin_version_endpoint(self):
        """Sends a real GET request to /rest/admin/application-version and validates JSON parsing."""
        target_url = "http://localhost:3000/rest/admin/application-version"

        response = send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url=target_url
        )

        assert response.status_code == 200
        assert response.json_data is not None, "Endpoint should return valid JSON"
        assert "version" in response.json_data, f"JSON payload missing 'version' key: {response.json_data}"
        assert response.headers.get("content-type", "").startswith("application/json")

    @pytest.mark.skipif(not JUICE_SHOP_AVAILABLE, reason="OWASP Juice Shop not reachable on http://localhost:3000")
    def test_live_credential_redaction_in_metadata_and_logs(self, caplog):
        """Ensures that authorization tokens are redacted from metadata and logs during live requests."""
        target_url = "http://localhost:3000/rest/admin/application-version"
        secret_token = "real_live_secret_jwt_token_abcdef123456"

        # Create session manager with an explicit secret token
        session_mgr = SessionManager(load_from_env=False)
        session_mgr.set_token(Role.USER_A, secret_token)

        with caplog.at_level(logging.INFO):
            response = send_request(
                role=Role.USER_A,
                method="GET",
                url=target_url,
                session_manager=session_mgr
            )

        # 1. Request succeeded against live server
        assert response.status_code in [200, 401, 403]

        # 2. Metadata must have redacted token
        metadata = response.request_metadata
        assert metadata is not None
        assert "Authorization" in metadata.sanitized_headers
        assert metadata.sanitized_headers["Authorization"] == "Bearer [REDACTED_TOKEN]"
        assert secret_token not in str(metadata.sanitized_headers)

        # 3. Log records must NOT contain the secret token
        assert secret_token not in caplog.text, "Secret token leaked in application logs!"
        assert "[REDACTED_TOKEN]" in caplog.text


@pytest.mark.integration
@pytest.mark.scope
class TestSecurityBoundaryRestrictions:
    """Verifies that security restrictions and scope guards strictly block unsafe actions."""

    def test_external_domain_blocked_before_execution(self):
        """Asserts that https://example.com is blocked before any network socket is opened."""
        with pytest.raises(ScopeViolationError) as exc_info:
            send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="https://example.com"
            )
        assert ("prohibited" in str(exc_info.value).lower() or "outside" in str(exc_info.value).lower())

    def test_unauthorized_port_blocked(self):
        """Asserts that localhost ports other than 3000 (e.g. 8080) are blocked."""
        with pytest.raises(ScopeViolationError) as exc_info:
            send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://localhost:8080/rest/admin/application-version"
            )
        assert "port '8080' is outside" in str(exc_info.value).lower()

    def test_post_request_blocked(self):
        """Asserts that POST requests are blocked during initial GET-only phase."""
        with pytest.raises(UnsupportedMethodError) as exc_info:
            send_request(
                role=Role.ANONYMOUS,
                method="POST",
                url="http://localhost:3000/api/Users"
            )
        assert "not permitted" in str(exc_info.value).lower()

    def test_external_redirect_suppressed_and_not_followed(self):
        """Verifies that external redirects are not followed and the raw 302 is captured."""
        def redirect_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://external-malicious-site.com/steal-session"},
                content=b"Redirecting to external site"
            )

        mock_client = httpx.Client(
            transport=httpx.MockTransport(redirect_handler),
            follow_redirects=False,
            timeout=httpx.Timeout(5.0)
        )

        with RequestExecutor(client=mock_client) as executor:
            response = executor.send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://localhost:3000/external-redirect-test"
            )

            # Assert 302 is captured without redirect following
            assert response.status_code == 302
            assert response.headers.get("location") == "https://external-malicious-site.com/steal-session"
            assert "Redirecting" in response.body

