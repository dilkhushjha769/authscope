"""Unit tests for RequestExecutor scope checks and execution parameters."""

import pytest
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.utils.helpers import ScopeViolationError


@pytest.mark.unit
class TestRequestExecutor:
    """Test suite verifying RequestExecutor safe operational controls."""

    def test_executor_blocks_out_of_scope_call_immediately(self):
        """Ensures RequestExecutor aborts before opening any socket for out-of-scope targets."""
        guard = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
        executor = RequestExecutor(scope_guard=guard)

        with pytest.raises(ScopeViolationError):
            executor.execute(method="GET", url="https://unauthorized-domain.com/secret")

    def test_executor_configures_no_redirects(self):
        """Ensures the underlying client is explicitly configured not to follow redirects."""
        executor = RequestExecutor()
        # Verify client does not follow redirects automatically
        assert executor.client.follow_redirects is False

