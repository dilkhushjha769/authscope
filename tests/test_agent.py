"""Unit tests for AI Agent tool dispatching and schema contracts."""

import pytest
from backend.agent.tools import AgentTools, TOOL_DEFINITIONS
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor


@pytest.mark.unit
class TestAgentTools:
    """Verifies tool definitions and dispatch logic."""

    def test_tool_definitions_present(self):
        """Verifies registered tool definitions have name, description, and input_schema."""
        assert len(TOOL_DEFINITIONS) >= 2
        tool_names = [t["name"] for t in TOOL_DEFINITIONS]
        assert "check_scope" in tool_names
        assert "compare_access" in tool_names

    def test_tool_execution_check_scope_allowed(self):
        """Verifies check_scope tool call correctly identifies in-scope URLs."""
        guard = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
        executor = RequestExecutor(scope_guard=guard)
        tools = AgentTools(scope_guard=guard, executor=executor)

        result = tools.execute_tool("check_scope", {"url": "http://localhost:3000/rest/basket/1"})
        assert result["is_allowed"] is True

    def test_tool_execution_check_scope_rejected(self):
        """Verifies check_scope tool call blocks out-of-scope URLs."""
        guard = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
        executor = RequestExecutor(scope_guard=guard)
        tools = AgentTools(scope_guard=guard, executor=executor)

        result = tools.execute_tool("check_scope", {"url": "https://external-target.com"})
        assert result["is_allowed"] is False

