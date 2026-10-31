"""Canonical Agent Adapter for Member 1 Gemini / AI Agent Integration.

Wraps the approved ToolRegistry in an asynchronous, standardized interface
returning canonical response envelopes:
{
  "ok": true | false,
  "tool_name": str,
  "assessment_id": str,
  "data": dict,
  "errors": list
}
"""

import asyncio
from typing import Any, Dict, List, Optional, Union
import uuid

from backend.tools.registry import ToolRegistry
from backend.tools.schemas import ToolExecutionContext, ToolExecutionStatus
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# Canonical alias dictionary mapping agent-friendly variants to registry tool names
CANONICAL_ALIASES: Dict[str, str] = {
    "compare_authorization": "compare_endpoint_access",
    "test_authorization": "compare_endpoint_access",
    "compare_access": "compare_endpoint_access",
    "test_access": "test_access_control",
    "check_scope": "validate_target",
    "verify_scope": "validate_target",
    "test_idor": "detect_idor",
    "test_bola": "detect_idor",
    "test_bfla": "test_bfla",
    "verify_evidence": "validate_evidence",
    "test_authentication": "check_authentication_weaknesses",
    "inspect_authentication": "check_authentication_weaknesses",
    "test_session_security": "check_session_security",
    "inspect_cookies": "check_session_security",
    "test_security_headers": "check_security_headers",
    "inspect_headers": "check_security_headers",
    "test_cors": "check_cors_misconfiguration",
    "check_cors": "check_cors_misconfiguration",
    "test_transport_security": "check_transport_security",
    "test_https": "check_transport_security",
    "check_transport": "check_transport_security",
    "scan_misconfigurations": "run_security_misconfiguration_scan",
}


class ToolRegistryAdapter:
    """Canonical adapter exposing AuthScope's Tool Registry to AI Agents (Gemini).

    Guarantees:
    - Wraps the single authoritative ToolRegistry without duplicating security state.
    - Asynchronous tool execution (`execute_tool_call`).
    - Standardized `{ok, tool_name, assessment_id, data, errors}` response envelopes.
    - Automatic alias resolution for canonical security tool names.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns approved tool definitions, parameter schemas, and descriptions.

        Member 1 can pass this directly to configure Gemini function calling.
        """
        return self.registry.list_tools()

    def get_gemini_declarations(self) -> List[Dict[str, Any]]:
        """Exports approved tools as Google Gemini Function Declarations."""
        return self.registry.get_gemini_declarations()

    def get_anthropic_declarations(self) -> List[Dict[str, Any]]:
        """Exports approved tools as Anthropic Claude Tool Declarations."""
        return self.registry.get_anthropic_declarations()

    async def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Union[Dict[str, Any], ToolExecutionContext]] = None,
        assessment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Asynchronously dispatches an approved tool call via ToolRegistry.

        Args:
            tool_name: Name or canonical alias of approved tool to execute.
            arguments: Dictionary of arguments conforming to tool's input schema.
            context: Execution context containing assessment_id and caller identity.

        Returns:
            Standardized JSON-compatible dictionary:
            {
                "ok": bool,
                "tool_name": str,
                "assessment_id": str,
                "data": dict,
                "errors": list
            }
        """
        if context is None and assessment_id:
            context = {"assessment_id": assessment_id}

        if context is None and assessment_id:
            context = {"assessment_id": assessment_id}

        # Resolve aliases
        effective_name = CANONICAL_ALIASES.get(tool_name, tool_name)

        # Normalize common LLM argument variants
        normalized_args = dict(arguments or {})
        if effective_name == "validate_target" and "target_url" in normalized_args and "url" not in normalized_args:
            normalized_args["url"] = normalized_args.pop("target_url")
        elif effective_name == "compare_endpoint_access" and "roles" in normalized_args and "test_roles" not in normalized_args:
            normalized_args["test_roles"] = normalized_args.pop("roles")

        # Parse or construct context
        if isinstance(context, ToolExecutionContext):
            ctx = context
            assessment_id = ctx.session_id or ctx.request_id
        elif isinstance(context, dict):
            assessment_id = context.get("assessment_id") or context.get("session_id") or str(uuid.uuid4())
            ctx = ToolExecutionContext(
                session_id=assessment_id,
                caller=context.get("caller", "gemini_agent"),
                request_id=context.get("request_id") or str(uuid.uuid4()),
                human_approved=bool(context.get("human_approved", False)),
                metadata=context.get("metadata", {})
            )
        else:
            assessment_id = str(uuid.uuid4())
            ctx = ToolExecutionContext(
                session_id=assessment_id,
                caller="gemini_agent",
                request_id=assessment_id
            )

        logger.info(
            "Agent adapter dispatching tool call",
            extra={"tool_name": effective_name, "raw_name": tool_name, "assessment_id": assessment_id}
        )

        # Run synchronous registry execution in a thread pool to preserve async event loop
        loop = asyncio.get_running_loop()
        exec_result = await loop.run_in_executor(
            None,
            lambda: self.registry.execute_tool(
                name=effective_name,
                arguments=normalized_args,
                context=ctx
            )
        )

        is_ok = exec_result.status == ToolExecutionStatus.SUCCESS
        errors: List[str] = [exec_result.error] if exec_result.error else []

        return {
            "ok": is_ok,
            "tool_name": tool_name,
            "assessment_id": assessment_id,
            "data": exec_result.data or {},
            "errors": errors,
            "status": exec_result.status.value,
            "duration_ms": exec_result.duration_ms
        }

    def execute_tool_call_sync(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Union[Dict[str, Any], ToolExecutionContext]] = None
    ) -> Dict[str, Any]:
        """Synchronous convenience wrapper around execute_tool_call."""
        return asyncio.run(self.execute_tool_call(tool_name, arguments, context))
