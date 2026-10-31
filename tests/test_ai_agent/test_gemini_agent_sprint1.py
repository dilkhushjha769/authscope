"""Independent Unit & Async Integration Tests for Sprint Member 1 (`backend.ai_agent`).

Covers all required areas using mocked tool and memory providers:
1. Gemini client & configuration (`GEMINI_API_KEY`, `GEMINI_MODEL`, `AGENT_MAX_ITERATIONS=8`,
   `AGENT_MAX_TOOL_CALLS=15`, `AGENT_TEMPERATURE=0.2`, `GEMINI_TIMEOUT=30`).
2. Agent planning & ScopeGuard enforcement.
3. Function calling (`generate_with_tools` & `agenerate_with_tools`).
4. Tool selection & `ToolExecutorProtocol` (`list_tools`, `execute_tool_call`).
5. Invalid tool rejection (unknown tools, shell/eval/SQL keys, out-of-scope URLs).
6. Tool execution errors & `INCONCLUSIVE` classification.
7. Iteration & tool-call limits (`max_iterations`, `max_tool_calls`).
8. Cancellation (`cancel_token` during `astream_assessment`).
9. Missing API key & explicit deterministic fallback mode reporting.
10. Memory integration (`MemoryProviderProtocol`: `get_context`, `save_observation`,
    `search_knowledge`, `save_finding`).
11. Evidence-validation workflow, all 5 statuses (`CONFIRMED`, `SUSPICIOUS`,
    `NOT_CONFIRMED`, `INCONCLUSIVE`, `NOT_TESTED`), and HTTP 200 anti-IDOR-proof guardrail.
12. Final report & structured event stream generation (`astream_assessment`).
"""

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import httpx
import pytest
from google.genai import errors as genai_errors

from backend.ai_agent import (
    AgentStreamEvent,
    AssessmentRequest,
    FindingValidationStatus,
    GeminiAPIError,
    GeminiAgentConfig,
    GeminiAuthScopeAgent,
    GeminiAuthenticationError,
    GeminiClient,
    GeminiConfigurationError,
    GeminiRateLimitError,
    GeminiTimeoutError,
    InvalidToolProposalError,
    MemoryProviderProtocol,
    ToolCallProposal,
    ToolExecutorProtocol,
)
from backend.utils.helpers import ScopeViolationError


# ==============================================================================
# Mock Tool Executor & Mock Memory Provider (Contracts E & F)
# ==============================================================================


class MockSprintToolExecutor:
    """Mock implementation of Member 2's `ToolExecutorProtocol`."""

    def __init__(self, fail_tools: Optional[List[str]] = None, bare_200_only: bool = False) -> None:
        self.fail_tools = set(fail_tools or [])
        self.bare_200_only = bare_200_only
        self.executed_calls: List[Dict[str, Any]] = []

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "check_scope",
                "description": "Checks target URL against ScopeGuard.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET"]},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "discover_endpoints",
                "description": "Discovers routes on target.",
                "input_schema": {
                    "type": "object",
                    "properties": {"target_url": {"type": "string"}},
                    "required": ["target_url"],
                },
            },
            {
                "name": "inspect_endpoint",
                "description": "Inspects an endpoint with a single GET request.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET"]},
                    },
                    "required": ["endpoint"],
                },
            },
            {
                "name": "compare_access",
                "description": "Performs cross-role differential authorization check.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET"]},
                    },
                    "required": ["endpoint", "method"],
                },
            },
            {
                "name": "validate_evidence",
                "description": "Validates differential evidence in security engine.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET"]},
                        "status_code": {"type": "integer"},
                        "response_excerpt": {"type": "string"},
                        "suspected_category": {"type": "string"},
                    },
                    "required": ["endpoint"],
                },
            },
        ]

    async def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.executed_calls.append(
            {"tool_name": tool_name, "arguments": dict(arguments), "context": dict(context or {})}
        )
        if tool_name in self.fail_tools:
            raise RuntimeError(f"Simulated execution failure in {tool_name}")

        if tool_name == "check_scope":
            return {"is_allowed": True, "target_url": arguments["url"], "method": "GET"}
        if tool_name == "discover_endpoints":
            return {
                "target_url": arguments["target_url"],
                "discovered_endpoints": ["/rest/basket/1", "/rest/basket/2", "/api/public"],
                "endpoint_count": 3,
            }
        if tool_name == "inspect_endpoint":
            return {
                "endpoint": arguments["endpoint"],
                "status_code": 200,
                "response_excerpt": '{"status":"ok"}',
            }
        if tool_name == "compare_access":
            ep = arguments["endpoint"]
            if self.bare_200_only:
                # Simulates a bare HTTP 200 response with NO differential discrepancy
                return {
                    "endpoint": ep,
                    "method": "GET",
                    "status_code": 200,
                    "is_discrepancy_detected": False,
                    "http_200_only": True,
                    "mark_suspicious": True,
                    "response_excerpt": '{"status":"success","data":{}}',
                }
            if ep == "/api/public":
                return {
                    "endpoint": ep,
                    "method": "GET",
                    "status_code": 403,
                    "verdict": "CORRECTLY_DENIED",
                    "is_discrepancy_detected": False,
                }
            return {
                "endpoint": ep,
                "method": "GET",
                "testing_role": "user_b",
                "authorized_role": "user_a",
                "status_code": 200,
                "is_discrepancy_detected": True,
                "suspected_category": "BOLA_IDOR",
                "response_excerpt": '{"id":1,"UserId":1,"items":["secret_item"]}',
            }
        if tool_name == "validate_evidence":
            ep = arguments["endpoint"]
            return {
                "finding_id": "fnd_mock_001",
                "endpoint": ep,
                "is_validated": not self.bare_200_only,
                "validation_status": "VALIDATED" if not self.bare_200_only else "SUSPICIOUS",
                "evidence_sha256": "a" * 64,
            }
        return {"ok": True}


class MockSprintMemoryProvider:
    """Mock implementation of Member 3's `MemoryProviderProtocol`."""

    def __init__(self) -> None:
        self.contexts: Dict[str, Dict[str, Any]] = {}
        self.observations: Dict[str, List[Dict[str, Any]]] = {}
        self.findings: Dict[str, List[Dict[str, Any]]] = {}
        self.knowledge_queries: List[Dict[str, Any]] = []

    def get_context(self, assessment_id: str) -> Dict[str, Any]:
        return self.contexts.get(
            assessment_id,
            {"assessment_id": assessment_id, "observations": self.observations.get(assessment_id, [])},
        )

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        self.observations.setdefault(assessment_id, []).append(observation)

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        self.knowledge_queries.append({"query": query, "category": category, "limit": limit})
        return [
            {
                "id": "kb_bola_01",
                "category": "BOLA_IDOR",
                "title": "OWASP BOLA Testing Guide",
                "guidance": "Compare User A and User B responses on object IDs.",
            }
        ][:limit]

    def save_finding(self, assessment_id: str, finding: Dict[str, Any]) -> None:
        self.findings.setdefault(assessment_id, []).append(finding)


def _build_mock_sdk(
    response_text: Optional[str] = None,
    function_calls: Optional[List[Any]] = None,
    side_effect: Optional[Any] = None,
) -> MagicMock:
    sdk = MagicMock()
    if side_effect is not None:
        sdk.models.generate_content.side_effect = side_effect
        return sdk
    resp = MagicMock()
    resp.text = response_text
    resp.parsed = None
    resp.function_calls = function_calls or []
    resp.usage_metadata = MagicMock(total_token_count=64)
    sdk.models.generate_content.return_value = resp
    return sdk


# ==============================================================================
# 1. Gemini Configuration & Client Tests
# ==============================================================================


class TestSprintGeminiConfigurationAndClient:
    """Tests GeminiAgentConfig, environment variables, and official google-genai client."""

    def test_env_configuration_defaults_and_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaTestKeyForSprintMember1")
        monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash")
        monkeypatch.setenv("AGENT_MAX_ITERATIONS", "8")
        monkeypatch.setenv("AGENT_MAX_TOOL_CALLS", "15")
        monkeypatch.setenv("AGENT_TEMPERATURE", "0.2")
        monkeypatch.setenv("GEMINI_TIMEOUT", "30")

        cfg = GeminiAgentConfig.from_env()
        assert cfg.is_configured is True
        assert cfg.fallback_mode is False
        assert cfg.mode == "gemini"
        assert cfg.model == "gemini-2.5-flash"
        assert cfg.max_iterations == 8
        assert cfg.max_tool_calls == 15
        assert cfg.temperature == pytest.approx(0.2)
        assert cfg.timeout == pytest.approx(30.0)

        # Never expose API keys
        assert "AIzaTestKeyForSprintMember1" not in repr(cfg)
        assert "AIzaTestKeyForSprintMember1" not in str(cfg.to_safe_dict())
        assert cfg.to_safe_dict()["api_key"] == "[REDACTED]"

    def test_missing_api_key_reports_deterministic_fallback_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        cfg = GeminiAgentConfig(api_key=None)

        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=cfg,
        )
        assert agent.is_configured is False
        assert agent.fallback_mode is True
        assert agent.mode == "deterministic_fallback"
        status = agent.get_status()
        assert status["fallback_mode"] is True
        assert status["mode"] == "deterministic_fallback"

        with pytest.raises(GeminiConfigurationError):
            agent.gemini_client.generate_text("Should fail when called directly without key")

    async def test_client_function_calling_and_error_handling(self) -> None:
        fn_call = MagicMock()
        fn_call.name = "compare_access"
        fn_call.args = {"endpoint": "/rest/basket/1", "method": "GET"}
        sdk = _build_mock_sdk(response_text="", function_calls=[fn_call])

        client = GeminiClient(api_key="test_key", sdk_client=sdk, retry_delay=0.0)
        tool_exec = MockSprintToolExecutor()
        out = await client.agenerate_with_tools(
            prompt="Propose next tool",
            tool_declarations=tool_exec.list_tools(),
        )
        assert len(out["function_calls"]) == 1
        assert out["function_calls"][0]["name"] == "compare_access"
        assert out["function_calls"][0]["arguments"] == {"endpoint": "/rest/basket/1", "method": "GET"}

        # Verify auth, rate limit, timeout, and API error classifications
        auth_sdk = _build_mock_sdk(
            side_effect=genai_errors.ClientError(403, {"error": {"message": "PERMISSION_DENIED"}})
        )
        auth_client = GeminiClient(api_key="test_key", sdk_client=auth_sdk, max_retries=2, retry_delay=0.0)
        with pytest.raises(GeminiAuthenticationError):
            await auth_client.agenerate_text("test")

        rl_sdk = _build_mock_sdk(
            side_effect=genai_errors.ClientError(429, {"error": {"message": "RESOURCE_EXHAUSTED"}})
        )
        rl_client = GeminiClient(api_key="test_key", sdk_client=rl_sdk, max_retries=2, retry_delay=0.0)
        with pytest.raises(GeminiRateLimitError):
            await rl_client.agenerate_text("test")

        to_sdk = _build_mock_sdk(side_effect=httpx.ConnectTimeout("Timed out"))
        to_client = GeminiClient(api_key="test_key", sdk_client=to_sdk, max_retries=2, retry_delay=0.0)
        with pytest.raises(GeminiTimeoutError):
            await to_client.agenerate_text("test")


# ==============================================================================
# 2. Public Interface, Protocols, Planning, Tool Selection & Rejection Tests
# ==============================================================================


class TestAgentPublicInterfaceAndToolContracts:
    """Tests `GeminiAuthScopeAgent(tool_executor, memory_provider, config)` and tool guardrails."""

    def test_constructor_accepts_positional_tool_executor_memory_provider_config(self) -> None:
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        cfg = GeminiAgentConfig(api_key=None, max_iterations=5, max_tool_calls=10)

        assert isinstance(tool_exec, ToolExecutorProtocol)
        assert isinstance(mem_prov, MemoryProviderProtocol)

        agent = GeminiAuthScopeAgent(tool_exec, mem_prov, cfg)
        assert agent.tool_executor is tool_exec
        assert agent.memory_provider is mem_prov
        assert agent.config.max_iterations == 5
        assert agent.config.max_tool_calls == 10

    def test_invalid_tool_rejection_and_scope_confinement(self) -> None:
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        agent = GeminiAuthScopeAgent(tool_exec, mem_prov, GeminiAgentConfig(api_key=None))

        # 1. Invented / unknown tool rejected
        v_unknown = agent.validate_tool_proposal(
            ToolCallProposal(tool_name="invented_hacker_tool", arguments={}),
            target_url="http://localhost:3000",
        )
        assert v_unknown.is_valid is False
        assert "not in the approved tool registry" in (v_unknown.rejection_reason or "")

        # 2. Arbitrary shell / eval / SQL argument rejected
        v_shell = agent.validate_tool_proposal(
            ToolCallProposal(
                tool_name="inspect_endpoint",
                arguments={"endpoint": "/rest/basket/1", "shell": "cat /etc/passwd"},
            ),
            target_url="http://localhost:3000",
        )
        assert v_shell.is_valid is False
        assert "Forbidden argument key" in (v_shell.rejection_reason or "")

        # 3. Destructive payload rejected
        v_payload = agent.validate_tool_proposal(
            ToolCallProposal(
                tool_name="inspect_endpoint",
                arguments={"endpoint": "/rest/basket/1; rm -rf /"},
            ),
            target_url="http://localhost:3000",
        )
        assert v_payload.is_valid is False

        # 4. Out-of-scope URL rejected
        v_scope = agent.validate_tool_proposal(
            ToolCallProposal(
                tool_name="check_scope",
                arguments={"url": "https://external.example.com/api"},
            ),
            target_url="http://localhost:3000",
        )
        assert v_scope.is_valid is False

        with pytest.raises(InvalidToolProposalError):
            agent.execute_tool_proposal(
                ToolCallProposal(tool_name="invented_tool", arguments={}),
                target_url="http://localhost:3000",
            )


# ==============================================================================
# 3. Tool Execution Errors, Iteration Limits, and Cancellation Tests
# ==============================================================================


class TestAgentResilienceLimitsAndCancellation:
    """Tests tool execution errors, iteration/tool bounds, and `cancel_token` support."""

    async def test_tool_execution_error_is_handled_and_marked_inconclusive(self) -> None:
        tool_exec = MockSprintToolExecutor(fail_tools=["compare_access"])
        mem_prov = MockSprintMemoryProvider()
        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=GeminiAgentConfig(api_key=None, max_iterations=4, max_tool_calls=6),
        )

        req = AssessmentRequest(
            assessment_id="assess_err_01",
            target_url="http://localhost:3000",
            objective="Test tool failure handling",
            candidate_endpoints=["/rest/basket/1"],
        )

        events: List[Dict[str, Any]] = []
        async for ev in agent.astream_assessment(req):
            assert isinstance(ev, dict)
            events.append(ev)

        failed_events = [e for e in events if e["type"] == "tool_execution_failed"]
        assert len(failed_events) == 1
        assert "Simulated execution failure" in failed_events[0]["message"]
        assert failed_events[0]["data"]["interpretation"]["status"] == FindingValidationStatus.INCONCLUSIVE.value

        final_ev = events[-1]
        assert final_ev["type"] == "assessment_completed"
        assert final_ev["data"]["endpoint_statuses"]["/rest/basket/1"] == FindingValidationStatus.INCONCLUSIVE.value

    async def test_cancellation_stops_astream_assessment_cleanly(self) -> None:
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=GeminiAgentConfig(api_key=None, max_iterations=8, max_tool_calls=15),
        )

        cancel_event = asyncio.Event()
        req = AssessmentRequest(
            assessment_id="assess_cancel_01",
            target_url="http://localhost:3000",
            objective="Test cancellation mid-stream",
        )

        collected: List[Dict[str, Any]] = []
        async for ev in agent.astream_assessment(req, cancel_token=cancel_event):
            collected.append(ev)
            if ev["type"] == "agent_plan":
                # Signal cancellation right after plan is emitted
                cancel_event.set()

        assert any(e["type"] == "agent_plan" for e in collected)
        assert collected[-1]["type"] == "assessment_cancelled"
        assert collected[-1]["data"]["stop_reason"] == "cancelled"
        # No tools should have been executed after cancellation
        assert len(tool_exec.executed_calls) == 0


# ==============================================================================
# 4. Real Vulnerability Requirements, Evidence Validation & Full Loop Streaming
# ==============================================================================


class TestEvidenceValidationAndVulnerabilityRequirements:
    """Tests Section G & H requirements: HTTP 200 guardrail, 5 statuses, memory & final report."""

    async def test_http_200_alone_is_never_treated_as_proof_of_idor(self) -> None:
        tool_exec = MockSprintToolExecutor(bare_200_only=True)
        mem_prov = MockSprintMemoryProvider()
        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=GeminiAgentConfig(api_key=None, max_iterations=5, max_tool_calls=10),
        )

        req = AssessmentRequest(
            assessment_id="assess_200_guard",
            target_url="http://localhost:3000",
            objective="Verify HTTP 200 alone is never CONFIRMED IDOR",
            candidate_endpoints=["/rest/basket/1"],
        )

        result = await agent.arun_assessment(req, auto_validate_evidence=True)
        # Even though HTTP 200 was returned, there was no differential ownership proof
        for f in result.findings:
            assert f.status != FindingValidationStatus.CONFIRMED
            assert f.status == FindingValidationStatus.SUSPICIOUS
            assert f.is_evidence_validated is False
        assert result.endpoint_statuses.get("/rest/basket/1") == FindingValidationStatus.SUSPICIOUS.value

    async def test_full_12_step_astream_assessment_with_mocked_providers(self) -> None:
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        cfg = GeminiAgentConfig(api_key=None, max_iterations=6, max_tool_calls=10)

        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=cfg,
        )

        req = AssessmentRequest(
            assessment_id="assess_full_01",
            target_url="http://localhost:3000",
            objective="Perform full authorization assessment on baskets",
        )

        streamed_events: List[Dict[str, Any]] = []
        async for event in agent.astream_assessment(req):
            assert isinstance(event, dict)
            assert set(event.keys()) >= {"type", "assessment_id", "timestamp", "message", "data"}
            assert event["assessment_id"] == "assess_full_01"
            streamed_events.append(event)

        event_types = [e["type"] for e in streamed_events]
        # Verify key lifecycle events were emitted
        assert "memory_context_loaded" in event_types
        assert "knowledge_retrieved" in event_types
        assert "agent_plan" in event_types
        assert "tool_selected" in event_types
        assert "tool_execution_completed" in event_types
        assert "finding_confirmed" in event_types
        assert event_types[-1] == "assessment_completed"

        # Check plan event matches Section D contract example
        plan_ev = next(e for e in streamed_events if e["type"] == "agent_plan")
        assert plan_ev["message"] == "Authorization assessment plan created"
        assert plan_ev["data"]["generated_by"] == "deterministic_planner"
        assert plan_ev["data"]["fallback_mode"] is True

        # Check tool executor calls
        called_tool_names = [c["tool_name"] for c in tool_exec.executed_calls]
        assert "check_scope" in called_tool_names
        assert "discover_endpoints" in called_tool_names
        assert "compare_access" in called_tool_names
        assert "validate_evidence" in called_tool_names

        # Check memory provider calls (Section F contract)
        assert len(mem_prov.knowledge_queries) >= 1
        assert len(mem_prov.observations.get("assess_full_01", [])) >= 3
        saved_findings = mem_prov.findings.get("assess_full_01", [])
        assert len(saved_findings) == 1
        assert saved_findings[0]["status"] == FindingValidationStatus.CONFIRMED.value
        assert saved_findings[0]["generated_by"] == "deterministic_fallback"

        # Check final summary event includes CONFIRMED and NOT_TESTED statuses
        done_ev = streamed_events[-1]
        assert done_ev["data"]["confirmed_findings"] == 1
        ep_statuses = done_ev["data"]["endpoint_statuses"]
        assert ep_statuses["/rest/basket/1"] == FindingValidationStatus.CONFIRMED.value
        # /rest/basket/2 was discovered but not tested in this single-endpoint pass -> NOT_TESTED
        assert ep_statuses["/rest/basket/2"] == FindingValidationStatus.NOT_TESTED.value

    async def test_not_confirmed_status_when_access_is_properly_denied(self) -> None:
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=GeminiAgentConfig(api_key=None, max_iterations=4, max_tool_calls=6),
        )

        req = AssessmentRequest(
            assessment_id="assess_denied_01",
            target_url="http://localhost:3000",
            objective="Verify properly denied endpoint is NOT_CONFIRMED",
            candidate_endpoints=["/api/public"],
        )

        events: List[Dict[str, Any]] = []
        async for ev in agent.astream_assessment(req):
            events.append(ev)

        done_ev = events[-1]
        assert done_ev["type"] == "assessment_completed"
        assert done_ev["data"]["confirmed_findings"] == 0
        assert done_ev["data"]["endpoint_statuses"]["/api/public"] == FindingValidationStatus.NOT_CONFIRMED.value

    async def test_iteration_and_tool_call_limits_in_astream_assessment(self) -> None:
        endless_json = """
        {
          "action": "call_tool",
          "thought": "Repeatedly inspect endpoint",
          "tool_name": "inspect_endpoint",
          "arguments": {"endpoint": "/rest/basket/1", "method": "GET"}
        }
        """
        sdk = _build_mock_sdk(response_text=endless_json)
        tool_exec = MockSprintToolExecutor()
        mem_prov = MockSprintMemoryProvider()
        cfg = GeminiAgentConfig(api_key="test_key", max_iterations=3, max_tool_calls=2)

        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=mem_prov,
            config=cfg,
            sdk_client=sdk,
        )

        req = AssessmentRequest(
            assessment_id="assess_bounds_01",
            target_url="http://localhost:3000",
            objective="Test tool call cap in astream_assessment",
        )
        events: List[Dict[str, Any]] = []
        async for ev in agent.astream_assessment(req):
            events.append(ev)

        done_ev = events[-1]
        assert done_ev["type"] == "assessment_completed"
        assert done_ev["data"]["tool_calls_executed"] == 2
        assert done_ev["data"]["stop_reason"] == "max_tool_calls_reached"
        # inspect_endpoint returned HTTP 200 -> marked SUSPICIOUS, never CONFIRMED
        assert done_ev["data"]["endpoint_statuses"]["/rest/basket/1"] == FindingValidationStatus.SUSPICIOUS.value
        assert done_ev["data"]["confirmed_findings"] == 0

    async def test_async_memory_provider_methods_supported(self) -> None:
        class AsyncMemoryProvider:
            def __init__(self) -> None:
                self.saved_obs: List[Dict[str, Any]] = []
                self.saved_findings: List[Dict[str, Any]] = []

            async def get_context(self, assessment_id: str) -> Dict[str, Any]:
                return {"assessment_id": assessment_id, "observations": self.saved_obs}

            async def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
                self.saved_obs.append(observation)

            async def search_knowledge(
                self, query: str, category: Optional[str] = None, limit: int = 5
            ) -> List[Dict[str, Any]]:
                return [{"id": "async_kb", "category": "BOLA_IDOR", "title": "Async KB", "guidance": "Check IDs"}]

            async def save_finding(self, assessment_id: str, finding: Dict[str, Any]) -> None:
                self.saved_findings.append(finding)

        tool_exec = MockSprintToolExecutor()
        async_mem = AsyncMemoryProvider()
        agent = GeminiAuthScopeAgent(
            tool_executor=tool_exec,
            memory_provider=async_mem,
            config=GeminiAgentConfig(api_key=None, max_iterations=5, max_tool_calls=8),
        )

        req = AssessmentRequest(
            assessment_id="assess_async_mem",
            target_url="http://localhost:3000",
            objective="Test async memory provider",
            candidate_endpoints=["/rest/basket/1"],
        )
        events = [ev async for ev in agent.astream_assessment(req)]
        assert events[-1]["type"] == "assessment_completed"
        assert len(async_mem.saved_obs) >= 3
        assert len(async_mem.saved_findings) == 1
        assert async_mem.saved_findings[0]["status"] == FindingValidationStatus.CONFIRMED.value

