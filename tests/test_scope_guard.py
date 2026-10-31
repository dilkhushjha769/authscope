"""Unit tests for ScopeGuard allowlist, boundary controls, and method restrictions."""

import pytest
from backend.core.scope_guard import ScopeGuard
from backend.utils.helpers import (
    ScopeViolationError,
    UnsupportedMethodError,
    InvalidTargetURLError,
)


@pytest.mark.unit
@pytest.mark.scope
class TestScopeGuard:
    """Test suite asserting boundary conditions for ScopeGuard."""

    def test_allow_valid_localhost_target(self, scope_guard: ScopeGuard):
        """Asserts that authorized local target URLs pass scope verification."""
        result = scope_guard.validate_url("http://localhost:3000/rest/basket/1")
        assert result.is_allowed is True
        assert result.normalized_host == "localhost"
        assert result.normalized_port == 3000
        assert result.normalized_scheme == "http"

    def test_allow_valid_loopback_ip_target(self, scope_guard: ScopeGuard):
        """Asserts that authorized loopback IP target URLs pass verification."""
        result = scope_guard.validate_url("http://127.0.0.1:3000/api/Users")
        assert result.is_allowed is True
        assert result.normalized_host == "127.0.0.1"
        assert result.normalized_port == 3000

    def test_reject_external_domain(self, scope_guard: ScopeGuard):
        """Asserts that external hosts outside the allowlist are strictly rejected."""
        result = scope_guard.validate_url("http://example.com/api")
        assert result.is_allowed is False
        assert "outside the authorized allowlist" in result.reason

        with pytest.raises(ScopeViolationError):
            scope_guard.assert_in_scope("http://example.com/api")

    def test_reject_unauthorized_port(self, scope_guard: ScopeGuard):
        """Asserts that non-permitted ports on localhost are rejected."""
        result = scope_guard.validate_url("http://localhost:8080/admin")
        assert result.is_allowed is False
        assert "Port '8080' is outside" in result.reason

        # Default port 80 when not specified
        result_default_80 = scope_guard.validate_url("http://localhost/admin")
        assert result_default_80.is_allowed is False
        assert "Port '80' is outside" in result_default_80.reason

    def test_reject_unsupported_protocols(self, scope_guard: ScopeGuard):
        """Asserts that dangerous schemes like file://, ftp://, gopher:// are rejected."""
        dangerous_targets = [
            "file:///etc/passwd",
            "ftp://localhost:3000/files",
            "gopher://localhost:3000/",
            "data:text/html,<script>alert(1)</script>",
        ]
        for target in dangerous_targets:
            result = scope_guard.validate_url(target)
            assert result.is_allowed is False
            assert "prohibited" in result.reason.lower()

    def test_reject_unsupported_http_method(self, scope_guard: ScopeGuard):
        """Asserts that only GET is allowed initially; POST, PUT, DELETE are blocked."""
        # GET should succeed
        method_get = scope_guard.validate_method("GET")
        assert method_get.is_allowed is True

        # Others must fail
        for method in ["POST", "PUT", "DELETE", "PATCH"]:
            method_res = scope_guard.validate_method(method)
            assert method_res.is_allowed is False
            assert "not permitted" in method_res.reason.lower()

            with pytest.raises(UnsupportedMethodError):
                scope_guard.assert_in_scope("http://localhost:3000/api", method=method)

    def test_reject_cloud_metadata_ip(self, scope_guard: ScopeGuard):
        """Asserts that AWS/GCP instance metadata IP addresses are strictly blocked."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://0.0.0.0:3000/api",
        ]
        for url in metadata_urls:
            result = scope_guard.validate_url(url)
            assert result.is_allowed is False
            assert ("prohibited" in result.reason.lower() or "outside" in result.reason.lower())

    def test_reject_embedded_credentials(self, scope_guard: ScopeGuard):
        """Asserts that URLs containing userinfo (user:pass@) are rejected."""
        result = scope_guard.validate_url("http://admin:secret@localhost:3000/api")
        assert result.is_allowed is False
        assert "userinfo" in result.reason.lower()

    def test_reject_control_characters_and_null_bytes(self, scope_guard: ScopeGuard):
        """Asserts that URLs containing null bytes or control characters are rejected."""
        result = scope_guard.validate_url("http://localhost:3000/api\x00/test")
        assert result.is_allowed is False
        assert "control characters" in result.reason.lower()

        with pytest.raises(InvalidTargetURLError):
            scope_guard.assert_in_scope("http://localhost:3000/api\x00/test")

    def test_reject_missing_scheme_or_host(self, scope_guard: ScopeGuard):
        """Asserts that incomplete or relative URLs fail validation."""
        result_no_scheme = scope_guard.validate_url("localhost:3000/api")
        assert result_no_scheme.is_allowed is False

        result_empty = scope_guard.validate_url("")
        assert result_empty.is_allowed is False
