"""Unit and integration tests for RequestExecutor controls and HTTP exchange handling."""

import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor, send_request
from backend.utils.helpers import (
    ScopeViolationError,
    UnsupportedMethodError,
    InvalidTargetURLError,
    TargetUnreachableError,
    MissingSessionError,
)


@pytest.mark.unit
class TestRequestExecutor:
    """Test suite verifying RequestExecutor execution and security controls."""

    def test_valid_localhost_request(self, mocked_executor: RequestExecutor):
        """Ensures valid in-scope localhost request succeeds and returns structured model."""
        response = mocked_executor.send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/rest/basket/1"
        )

        assert response.status_code == 200
        assert response.json_data is not None
        assert response.json_data["data"]["id"] == 1
        assert response.request_metadata is not None
        assert response.request_metadata.method == "GET"
        assert response.request_metadata.url == "http://localhost:3000/rest/basket/1"
        assert response.request_metadata.role == "anonymous"

    def test_external_domain_rejection(self, mocked_executor: RequestExecutor):
        """Ensures RequestExecutor aborts before socket connection for external domains."""
        with pytest.raises(ScopeViolationError):
            mocked_executor.send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="https://external-domain.com/secret"
            )

    def test_unauthorized_port_rejection(self, mocked_executor: RequestExecutor):
        """Ensures RequestExecutor rejects non-allowlisted ports on localhost."""
        with pytest.raises(ScopeViolationError):
            mocked_executor.send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://localhost:8080/rest/basket/1"
            )

    def test_unsupported_http_method_rejection(self, mocked_executor: RequestExecutor):
        """Ensures RequestExecutor rejects methods other than GET (e.g. POST, DELETE)."""
        with pytest.raises(UnsupportedMethodError):
            mocked_executor.send_request(
                role=Role.ANONYMOUS,
                method="POST",
                url="http://localhost:3000/rest/basket/1"
            )

        with pytest.raises(UnsupportedMethodError):
            mocked_executor.send_request(
                role=Role.ANONYMOUS,
                method="DELETE",
                url="http://localhost:3000/rest/basket/1"
            )

    def test_redirect_rejection_no_follow(self, mocked_executor: RequestExecutor):
        """Ensures client does not automatically follow 302 redirects."""
        response = mocked_executor.send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/redirect-test"
        )

        # Must capture the raw 302 status code and Location header without following it
        assert response.status_code == 302
        assert response.headers.get("location") == "http://localhost:3000/login"
        assert "Redirecting" in response.body

    def test_invalid_url_rejection(self, mocked_executor: RequestExecutor):
        """Ensures malformed URLs fail before network transmission."""
        with pytest.raises(InvalidTargetURLError):
            mocked_executor.send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://localhost:3000/test\x00path"
            )

    def test_timeout_handling(self, scope_guard: ScopeGuard, session_manager: SessionManager):
        """Ensures request timeouts are caught and converted to TargetUnreachableError."""
        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Socket timed out reading from server", request=request)

        client = httpx.Client(
            transport=httpx.MockTransport(timeout_handler),
            follow_redirects=False,
            timeout=httpx.Timeout(1.0)
        )
        executor = RequestExecutor(
            scope_guard=scope_guard,
            session_manager=session_manager,
            client=client
        )

        with pytest.raises(TargetUnreachableError) as exc_info:
            executor.send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://localhost:3000/slow-endpoint"
            )
        assert "timed out" in str(exc_info.value).lower()

    def test_missing_authentication_session(self, mocked_executor: RequestExecutor):
        """Ensures querying an invalid or unsupported role raises MissingSessionError."""
        with pytest.raises(MissingSessionError):
            mocked_executor.send_request(
                role="non_existent_role",
                method="GET",
                url="http://localhost:3000/rest/basket/1"
            )

    def test_role_header_injection_and_sanitization(self, mocked_executor: RequestExecutor):
        """Verifies session manager injects role tokens and sanitizes headers in metadata."""
        # Test Admin role
        admin_response = mocked_executor.send_request(
            role=Role.ADMIN,
            method="GET",
            url="http://localhost:3000/rest/admin/application-version"
        )
        assert admin_response.status_code == 200
        assert admin_response.json_data == {"version": "17.1.1"}

        # Verify raw token is NOT in metadata sanitized_headers
        metadata = admin_response.request_metadata
        assert metadata is not None
        assert metadata.sanitized_headers["Authorization"] == "Bearer [REDACTED_TOKEN]"
        assert "mocked_jwt_admin" not in str(metadata.sanitized_headers)

        # Test Anonymous role (should send no Authorization header)
        anon_response = mocked_executor.send_request(
            role=Role.ANONYMOUS,
            method="GET",
            url="http://localhost:3000/rest/admin/application-version"
        )
        assert anon_response.status_code == 403
        assert "Authorization" not in anon_response.request_metadata.sanitized_headers

    def test_standalone_send_request_function(self, scope_guard: ScopeGuard):
        """Verifies top-level send_request function operates identically."""
        # Check out-of-scope block via standalone function
        with pytest.raises(ScopeViolationError):
            send_request(
                role=Role.ANONYMOUS,
                method="GET",
                url="http://malicious-external-site.com",
                scope_guard=scope_guard
            )
