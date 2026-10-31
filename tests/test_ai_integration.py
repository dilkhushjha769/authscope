"""Comprehensive integration test suite for AuthScope AI Agent, Tool Registry, and Memory System.

Tests:
1. Assessment endpoint validation (valid URL, empty URL, out-of-scope URL).
2. ScopeGuard enforcement boundaries.
3. SSE real-time event streaming (assessment_started, agent_thinking, agent_plan, tool events, etc.).
4. ToolRegistry tool execution, schema compliance, error handling, and event callbacks.
5. AssessmentMemory tracking, conversation history, and RAG knowledge retrieval.
6. GeminiAgent planning and explanation synthesis with deterministic fallback.
7. Safe cancellation mechanics.
"""

import json
import pytest
from starlette.testclient import TestClient

from backend.api.app import app, active_tokens
from backend.agent.gemini_agent import GeminiAgent
from backend.agent.memory import AssessmentMemory
from backend.agent.tools import ToolRegistry, ToolExecutionResult
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import ScanSessionRecord


@pytest.fixture
def test_client():
    """Provides a TestClient fixture against the FastAPI application."""
    return TestClient(app)


@pytest.fixture
def memory_fixture():
    """Provides an isolated AssessmentMemory instance."""
    return AssessmentMemory(assessment_id="test_mem_001", target_url="http://localhost:3000")


@pytest.fixture
def tool_registry_fixture(memory_fixture):
    """Provides an isolated ToolRegistry instance with scope guard."""
    scope_guard = ScopeGuard()
    executor = RequestExecutor(scope_guard=scope_guard)
    return ToolRegistry(scope_guard=scope_guard, executor=executor, memory=memory_fixture)


# ==============================================================================
# 1. Assessment Endpoint & Scope Enforcement Tests
# ==============================================================================


class TestAssessmentEndpoint:
    """Verifies POST /api/assessments contract and ScopeGuard integration."""

    def test_create_assessment_valid_target(self, test_client):
        """Valid target URL initiates session with 201 Created and PENDING status."""
        resp = test_client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        assert resp.status_code == 201
        data = resp.json()
        assert "assessment_id" in data
        assert data["target_url"] == "http://localhost:3000"
        assert data["status"] == "PENDING"
        assert data["assessment_id"].startswith("scan_")

    def test_create_assessment_empty_target(self, test_client):
        """Empty target URL rejected with HTTP 400 Bad Request."""
        resp = test_client.post("/api/assessments", json={"target_url": "   "})
        assert resp.status_code == 400
        assert "Target URL must not be empty" in resp.json()["detail"]

    def test_create_assessment_out_of_scope_target(self, test_client):
        """Out-of-scope targets rejected by ScopeGuard with HTTP 400."""
        resp = test_client.post("/api/assessments", json={"target_url": "https://external-bank.com"})
        assert resp.status_code == 400
        assert "Scope violation" in resp.json()["detail"]

    def test_create_assessment_with_optional_repo(self, test_client):
        """Accepts optional repository and archive parameters without breaking."""
        resp = test_client.post("/api/assessments", json={
            "target_url": "http://localhost:3000",
            "github_repo": "https://github.com/juice-shop/juice-shop",
            "source_archive_path": "uploads/juice-shop.zip",
        })
        assert resp.status_code == 201
        assert resp.json()["target_url"] == "http://localhost:3000"


# ==============================================================================
# 2. SSE Streaming & Structured Events Tests
# ==============================================================================


class TestSSEStreaming:
    """Verifies Server-Sent Events endpoint and structured AI event emission."""

    def test_stream_nonexistent_assessment(self, test_client):
        """Requesting stream for unknown assessment returns HTTP 404."""
        resp = test_client.get("/api/assessments/unknown_scan_id_9999/stream")
        assert resp.status_code == 404

    def test_stream_event_structure(self, test_client):
        """Connects to assessment stream and validates structured SSE event types."""
        # 1. Create assessment
        create_res = test_client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        scan_id = create_res.json()["assessment_id"]

        # 2. Connect to SSE stream
        with test_client.stream("GET", f"/api/assessments/{scan_id}/stream") as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]

            events_received = []
            for line in response.iter_lines():
                if line.startswith("event:"):
                    events_received.append(line.replace("event:", "").strip())
                # Read initial batch and break
                if len(events_received) >= 5:
                    break

            # Assert structured agent events were emitted
            assert "assessment_started" in events_received
            assert "agent_thinking" in events_received or "agent_plan" in events_received


# ==============================================================================
# 3. Tool Registry Integration Tests (Member 2)
# ==============================================================================


class TestToolRegistry:
    """Verifies tool registration, execution, error containment, and event callbacks."""

    def test_list_tools(self, tool_registry_fixture):
        """ToolRegistry returns approved declarative schemas."""
        tools = tool_registry_fixture.list_tools()
        names = [t["name"] for t in tools]
        assert "check_scope" in names
        assert "compare_access" in names
        assert "retrieve_security_knowledge" in names

    def test_execute_check_scope_tool(self, tool_registry_fixture):
        """check_scope tool executes ScopeGuard validation accurately."""
        # Authorized scope
        res_allowed = tool_registry_fixture.execute("check_scope", {"url": "http://localhost:3000/rest/basket/1"})
        assert res_allowed.success is True
        assert res_allowed.data["is_allowed"] is True

        # Unauthorized scope
        res_denied = tool_registry_fixture.execute("check_scope", {"url": "https://malicious.org/api"})
        assert res_denied.success is True
        assert res_denied.data["is_allowed"] is False

    def test_execute_unknown_tool(self, tool_registry_fixture):
        """Unknown tool execution fails safely without crashing."""
        events_emitted = []
        res = tool_registry_fixture.execute(
            "nonexistent_tool",
            {},
            on_event=lambda etype, data: events_emitted.append((etype, data)),
        )
        assert res.success is False
        assert "Unknown tool" in res.error
        assert any(e[0] == "tool_failed" for e in events_emitted)

    def test_tool_callbacks_emitted(self, tool_registry_fixture):
        """Successful execution emits tool_started and tool_completed."""
        events_emitted = []
        res = tool_registry_fixture.execute(
            "check_scope",
            {"url": "http://localhost:3000"},
            on_event=lambda etype, data: events_emitted.append((etype, data)),
        )
        assert res.success is True
        event_types = [e[0] for e in events_emitted]
        assert "tool_started" in event_types
        assert "tool_completed" in event_types


# ==============================================================================
# 4. Assessment Memory & Knowledge Retrieval (RAG) Tests (Member 3)
# ==============================================================================


class TestAssessmentMemory:
    """Verifies short-term context tracking and OWASP API Top 10 RAG retrieval."""

    def test_record_thoughts_and_plans(self, memory_fixture):
        """Records agent reasoning chronologically."""
        th = memory_fixture.record_thought("Analyzing authorization differential outcome")
        pl = memory_fixture.record_plan("Execute cross-account test on /rest/basket/1")

        assert th.category == "thought"
        assert pl.category == "plan"
        assert len(memory_fixture.history) == 2

        ctx = memory_fixture.get_current_context()
        assert ctx["assessment_id"] == "test_mem_001"
        assert ctx["target_url"] == "http://localhost:3000"

    def test_retrieve_security_knowledge_rag(self, memory_fixture):
        """Retrieves targeted vulnerability blueprints from knowledge base."""
        # Query BOLA / IDOR
        bola_items = memory_fixture.retrieve_security_knowledge("broken object level authorization basket", "BOLA_IDOR")
        assert len(bola_items) > 0
        top = bola_items[0]
        assert "BOLA" in top.vulnerability_id or "BOLA_IDOR" in top.category
        assert "Basket" in top.code_pattern_secure

        # Query BFLA
        bfla_items = memory_fixture.retrieve_security_knowledge("admin route privilege escalation", "BFLA")
        assert len(bfla_items) > 0
        assert "BFLA" in bfla_items[0].vulnerability_id

    def test_previous_assessment_metadata(self, memory_fixture):
        """Queries repository for past assessment metadata without throwing."""
        past = memory_fixture.get_previous_assessment_metadata()
        assert isinstance(past, list)


# ==============================================================================
# 5. Gemini AI Agent Connector Tests (Member 1)
# ==============================================================================


class TestGeminiAgent:
    """Verifies strategic planning and explanation synthesis with deterministic fallback."""

    def test_plan_assessment(self, tool_registry_fixture, memory_fixture):
        """Generates 7-stage plan and emits agent_thinking and agent_plan events."""
        agent = GeminiAgent(tool_registry=tool_registry_fixture, memory=memory_fixture)
        events = []
        plan = agent.plan_assessment(
            "http://localhost:3000",
            on_event=lambda etype, data: events.append((etype, data)),
        )

        assert "plan_summary" in plan
        assert len(plan["steps"]) == 7
        event_types = [e[0] for e in events]
        assert "agent_thinking" in event_types
        assert "agent_plan" in event_types

    def test_generate_explanation_deterministic_fallback(self, tool_registry_fixture, memory_fixture):
        """Synthesizes grounded root-cause explanation when GEMINI_API_KEY is not configured."""
        agent = GeminiAgent(tool_registry=tool_registry_fixture, memory=memory_fixture, api_key="")
        events = []
        expl = agent.generate_explanation(
            endpoint="/rest/basket/1",
            vulnerability_category="BOLA_IDOR",
            validation_status="CONFIRMED",
            evidence_summary="User B was able to view basket belonging to User A",
            on_event=lambda etype, data: events.append((etype, data)),
        )

        assert expl["endpoint"] == "/rest/basket/1"
        assert expl["category"] == "BOLA_IDOR"
        assert "Broken Object Level Authorization" in expl["explanation"]
        assert len(expl["remediation_code"]) > 0
        event_types = [e[0] for e in events]
        assert "explanation_generated" in event_types


# ==============================================================================
# 6. Cancellation & Error Resilience Tests
# ==============================================================================


class TestCancellationAndResilience:
    """Verifies safe operator cancellation and error containment."""

    def test_stop_assessment_endpoint(self, test_client):
        """POST /api/assessments/{id}/stop cancels an active assessment cleanly."""
        create_res = test_client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        scan_id = create_res.json()["assessment_id"]

        stop_res = test_client.post(f"/api/assessments/{scan_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "CANCELLING"

    def test_stop_nonexistent_assessment(self, test_client):
        """Attempting to stop an unknown assessment returns HTTP 404."""
        resp = test_client.post("/api/assessments/unknown_scan_id_888/stop")
        assert resp.status_code == 404
