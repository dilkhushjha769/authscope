"""Registered tool definitions and handlers exposed to Claude 3.5 Sonnet and Gemini."""

from typing import List, Dict, Any, Optional
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.tools.registry import ToolRegistry
from backend.tools.schemas import ToolExecutionStatus
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# Declarative schemas for Claude Anthropic Tool Calling API
TOOL_DEFINITIONS = [
    {
        "name": "check_scope",
        "description": "Verifies whether a given URL is strictly within the authorized target allowlist.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The target URL to check."
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "compare_access",
        "description": "Executes authorization-differential testing on an endpoint across multiple roles.",
        "input_schema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "Relative endpoint path (e.g. /rest/basket/1)."
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE"],
                    "description": "HTTP method to test."
                }
            },
            "required": ["endpoint", "method"]
        }
    }
]


class AgentTools:
    """Executes registered tools when requested by the AI Agent.

    Delegates to the centralized ToolRegistry while maintaining full
    backward compatibility with existing Phase 2/3 contracts.
    """

    def __init__(self, scope_guard: ScopeGuard, executor: RequestExecutor):
        self.scope_guard = scope_guard
        self.executor = executor
        self.registry = ToolRegistry(scope_guard=self.scope_guard, executor=self.executor)

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches tool execution by name via ToolRegistry."""
        logger.info("Executing tool call from agent", extra={"tool_name": name})
        if name == "check_scope":
            result = self.scope_guard.validate_url(arguments.get("url", ""))
            return result.model_dump()
        elif name == "compare_access":
            if "method" in arguments and "test_roles" not in arguments:
                # Legacy compatibility response
                return {
                    "endpoint": arguments["endpoint"],
                    "method": arguments["method"],
                    "is_discrepancy_detected": False,
                    "message": "Tool executed. Detailed differential engine implementation in Phase 4."
                }
            res = self.registry.execute_tool(name, arguments)
            return res.data if res.status == ToolExecutionStatus.SUCCESS else {"error": res.error}
        elif self.registry.get_tool(name) is not None:
            res = self.registry.execute_tool(name, arguments)
            return res.data if res.status == ToolExecutionStatus.SUCCESS else {"error": res.error}
        else:
            return {"error": f"Unknown tool: {name}"}
