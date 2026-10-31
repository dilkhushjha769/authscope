"""Test Suite for Canonical Tool Interface and Finding Formats (Phase 5.3 Contract).

Covers:
- ToolRegistryAdapter interface (list_tools, execute_tool_call).
- Gemini Function Declarations export.
- Standardized return envelope: {ok, tool_name, assessment_id, data, errors}.
- Aliasing of canonical names (compare_authorization, test_idor, test_bfla, check_scope).
- 12-field Canonical Finding contract validation (Section J).
- Unregistered tool rejection and error safety.
"""

import asyncio
import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import RequestExecutor
from backend.tools.agent_adapter import ToolRegistryAdapter
from backend.tools.registry import ToolRegistry
from backend.tools.schemas import CanonicalFinding


@pytest.mark.asyncio
async def test_tool_registry_adapter_list_and_declarations():
    """Adapter exposes list_tools and Gemini declarations matching Member 1 consumption contract."""
    adapter = ToolRegistryAdapter()
    tools = adapter.list_tools()
    assert len(tools) >= 8

    tool_names = [t["name"] for t in tools]
    assert "validate_target" in tool_names
    assert "compare_endpoint_access" in tool_names
    assert "detect_idor" in tool_names
    assert "test_bfla" in tool_names

    gemini_decls = adapter.get_gemini_declarations()
    assert len(gemini_decls) >= 8
    for decl in gemini_decls:
        assert "name" in decl
        assert "description" in decl
        assert "parameters" in decl


@pytest.mark.asyncio
async def test_async_execute_tool_call_canonical_envelope():
    """execute_tool_call must return standardized {ok, tool_name, assessment_id, data, errors}."""
    adapter = ToolRegistryAdapter()

    result = await adapter.execute_tool_call(
        tool_name="validate_target",
        arguments={"target_url": "http://localhost:3000/rest/admin"},
        context={"assessment_id": "assessment_test_001", "caller": "gemini_agent"}
    )

    assert result["ok"] is True
    assert result["tool_name"] == "validate_target"
    assert result["assessment_id"] == "assessment_test_001"
    assert isinstance(result["data"], dict)
    assert result["data"]["is_allowed"] is True
    assert result["errors"] == []


@pytest.mark.asyncio
async def test_alias_resolution_for_canonical_names():
    """Adapter translates canonical aliases (compare_authorization, check_scope, test_idor) seamlessly."""
    adapter = ToolRegistryAdapter()

    # 1. check_scope -> validate_target
    res_scope = await adapter.execute_tool_call(
        tool_name="check_scope",
        arguments={"target_url": "http://localhost:3000/api"},
        context={"assessment_id": "assess_alias_1"}
    )
    assert res_scope["ok"] is True
    assert res_scope["tool_name"] == "check_scope"
    assert res_scope["data"]["is_allowed"] is True

    # 2. compare_authorization alias
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"version": "1.0"})

    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "a@t.c", "p", token="tok_a")
    mgr.authenticate_role(Role.USER_B, "b@t.c", "p", token="tok_b")
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    custom_tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    from backend.tools.authorization_tools import AuthorizationTools
    auth_tools = AuthorizationTools(tester=custom_tester)
    reg = ToolRegistry(authorization_tools=auth_tools)
    custom_adapter = ToolRegistryAdapter(registry=reg)

    res_auth = await custom_adapter.execute_tool_call(
        tool_name="compare_authorization",
        arguments={"endpoint": "http://localhost:3000/rest/admin/application-version", "roles": ["user_b"]},
        context={"assessment_id": "assess_alias_2"}
    )
    assert res_auth["ok"] is True
    assert "role_results" in res_auth["data"]


@pytest.mark.asyncio
async def test_unregistered_tool_rejected():
    """Unapproved tools are rejected cleanly without crashing."""
    adapter = ToolRegistryAdapter()

    result = await adapter.execute_tool_call(
        tool_name="raw_shell_exec",
        arguments={"cmd": "whoami"},
        context={"assessment_id": "assess_bad"}
    )

    assert result["ok"] is False
    assert len(result["errors"]) > 0
    assert any(phrase in result["errors"][0].lower() for phrase in ("unknown tool", "access denied", "not an approved"))


def test_canonical_finding_structure_12_fields():
    """Validates the 12-field Finding Format mandated in Section J."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "owner": "usera@test.com", "secret": "leak"})

    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "usera@test.com", "p", token="jwt_a")
    mgr.authenticate_role(Role.USER_B, "userb@test.com", "p", token="jwt_b")
    mgr.register_resource_ownership(Role.USER_A, "basket", "1")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    tester = AuthorizationTester(executor=executor, session_manager=mgr, scope_guard=guard)

    diff_result = tester.test_bola_idor(
        endpoint="http://localhost:3000/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    finding_dict = AuthorizationTester.build_canonical_finding(
        diff_result,
        assessment_id="assess_canon_001"
    )

    assert finding_dict is not None

    # Verify all 12 canonical fields required by Section J
    expected_fields = [
        "finding_id",
        "assessment_id",
        "target_url",
        "endpoint",
        "method",
        "testing_role",
        "baseline_response",
        "comparison_response",
        "sanitized_evidence",
        "response_hashes",
        "validation_status",
        "confirmation_reason",
    ]
    for field in expected_fields:
        assert field in finding_dict, f"Missing required field: {field}"

    # Verify Pydantic schema validation
    validated_model = CanonicalFinding(**finding_dict)
    assert validated_model.finding_id == finding_dict["finding_id"]
    assert validated_model.assessment_id == "assess_canon_001"
    assert validated_model.method == "GET"
    assert validated_model.testing_role == Role.USER_B.value
    assert validated_model.validation_status == "CONFIRMED"
    assert "response_hashes" in finding_dict
    assert finding_dict["response_hashes"]["evidence_sha256"] is not None
