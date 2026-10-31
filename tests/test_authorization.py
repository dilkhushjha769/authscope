"""Integration tests for authorization differential testing logic."""

import pytest
from backend.core.session_manager import Role, SessionManager
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.scanner.request_executor import HttpResponseModel


@pytest.mark.unit
class TestAuthorizationLogic:
    """Verifies response differential detection heuristics."""

    def test_response_analyzer_identifies_success(self):
        """Verifies 200 OK with valid data is evaluated as successful."""
        response = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": {"id": 1}}',
            json_data={"data": {"id": 1}}
        )
        assert ResponseAnalyzer.is_success_response(response) is True

    def test_response_analyzer_filters_error_status_codes(self):
        """Verifies 401 and 403 responses are recognized as denied access."""
        unauthorized = HttpResponseModel(status_code=401, body="Unauthorized")
        forbidden = HttpResponseModel(status_code=403, body="Forbidden")

        assert ResponseAnalyzer.is_success_response(unauthorized) is False
        assert ResponseAnalyzer.is_success_response(forbidden) is False

    def test_session_manager_role_isolation(self):
        """Ensures session manager isolates tokens between personas."""
        mgr = SessionManager()
        mgr.authenticate_role(Role.USER_A, "userA@test.com", "passA")
        mgr.authenticate_role(Role.USER_B, "userB@test.com", "passB")

        headers_a = mgr.get_auth_headers(Role.USER_A)
        headers_b = mgr.get_auth_headers(Role.USER_B)

        assert "Authorization" in headers_a
        assert "Authorization" in headers_b
        # Anonymous should have no authorization header
        assert mgr.get_auth_headers(Role.ANONYMOUS) == {}

