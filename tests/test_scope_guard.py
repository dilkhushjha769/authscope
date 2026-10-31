"""Unit tests for ScopeGuard allowlist and boundary enforcement."""

import pytest
from backend.core.scope_guard import ScopeGuard
from backend.utils.helpers import ScopeViolationError


@pytest.mark.unit
@pytest.mark.scope
class TestScopeGuard:
    """Test suite asserting boundary conditions for ScopeGuard."""

    def test_allow_valid_local_target(self, scope_guard: ScopeGuard):
        """Asserts that authorized local target URLs pass scope verification."""
        result = scope_guard.validate_url("http://localhost:3000/rest/basket/1")
        assert result.is_allowed is True
        assert result.normalized_host == "localhost"
        assert result.normalized_port == 3000

    def test_allow_valid_ip_target(self, scope_guard: ScopeGuard):
        """Asserts that authorized loopback IP target URLs pass verification."""
        result = scope_guard.validate_url("http://127.0.0.1:3000/api/Users")
        assert result.is_allowed is True
        assert result.normalized_host == "127.0.0.1"

    def test_reject_unauthorized_external_host(self, scope_guard: ScopeGuard):
        """Asserts that external hosts outside the allowlist are rejected."""
        result = scope_guard.validate_url("https://example.com/api")
        assert result.is_allowed is False
        assert "outside the authorized allowlist" in result.reason

    def test_reject_unauthorized_port(self, scope_guard: ScopeGuard):
        """Asserts that non-permitted ports on localhost are rejected."""
        result = scope_guard.validate_url("http://localhost:8080/admin")
        assert result.is_allowed is False
        assert "Port '8080' is outside" in result.reason

    def test_reject_dangerous_scheme(self, scope_guard: ScopeGuard):
        """Asserts that dangerous protocols like file:// or ftp:// are rejected."""
        result = scope_guard.validate_url("file:///etc/passwd")
        assert result.is_allowed is False
        assert "Scheme 'file' not allowed" in result.reason

    def test_reject_cloud_metadata_ip(self, scope_guard: ScopeGuard):
        """Asserts that AWS/GCP instance metadata IP addresses are strictly rejected."""
        result = scope_guard.validate_url("http://169.254.169.254/latest/meta-data/")
        assert result.is_allowed is False
        assert "cloud metadata endpoints is prohibited" in result.reason

    def test_assert_in_scope_raises_exception(self, scope_guard: ScopeGuard):
        """Asserts that assert_in_scope raises ScopeViolationError on invalid targets."""
        with pytest.raises(ScopeViolationError):
            scope_guard.assert_in_scope("https://evil.com/leak")

