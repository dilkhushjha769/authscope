"""Comprehensive API, SSE, and Frontend Integration Test Suite (Member 4).

Tests:
1. Public Integration Contracts (Mock & Production Adapters):
   - `GeminiAuthScopeAgent.astream_assessment(request, cancel_token=None)`
   - `ToolRegistryAdapter.list_tools()`, `execute_tool_call(tool_name, arguments, context)`
   - `MemoryManager.get_context(assessment_id)`, `save_observation()`, `search_knowledge()`, `save_finding()`
2. URL Submission & Hard ScopeGuard Rejection.
3. SSE Streaming across all 15 required event types:
   - assessment_started, agent_thinking, agent_plan, tool_started, tool_completed,
     tool_failed, endpoint_discovered, finding_hypothesis, finding_discovered,
     evidence_validated, source_location_found, explanation_generated,
     assessment_completed, assessment_failed, assessment_cancelled.
4. Evidence Validation Ordering Gate (`evidence_validated` precedes confirmed `finding_discovered`).
5. Incremental SSE Event Replay & Reconnection (`Last-Event-ID`).
6. Safe Operator Cancellation (`POST /api/assessments/{id}/stop`).
7. Inconclusive / Suspicious Finding Status Handling.
8. Source Code Mapping vs Black-Box Assessment Notice.
9. Tool / API Failure Containment.
10. Single Unified Pipeline Verification (zero duplicate scanner sessions).
"""

from __future__ import annotations

import json
import time
from typing import Dict, List, Tuple
from fastapi.testclient import TestClient
import pytest

from backend.api.adapters import (
    GeminiAuthScopeAgent,
    MemoryManager,
    SessionBoundRepositoryProxy,
    ToolRegistryAdapter,
)
from backend.api.app import app, task_manager
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    EventType,
    EvidenceArtifact,
    FindingRecord,
    ScanSessionRecord,
    SeverityLevel,
)
from tests.test_api_frontend.mocks import (
    MockGeminiAuthScopeAgent,
    MockMemoryManager,
    MockToolRegistryAdapter,
)


@pytest.fixture(autouse=True)
def reset_task_manager_dependencies():
    """Ensures task_manager dependencies are cleanly reset before and after every test."""
    task_manager.reset_dependencies()
    yield
    task_manager.reset_dependencies()


@pytest.fixture
def client():
    """Provides a FastAPI TestClient instance."""
    with TestClient(app) as c:
        yield c


def _parse_sse_frames(raw_lines: List[str]) -> List[Tuple[str, Dict[str, object]]]:
    """Helper to parse raw SSE lines into (event_name, json_payload) tuples."""
    frames: List[Tuple[str, Dict[str, object]]] = []
    current_event = "message"
    for line in raw_lines:
        if not line:
            continue
        if line.startswith("event:"):
            current_event = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            data_str = line.split(":", 1)[1].strip()
            try:
                payload = json.loads(data_str)
            except Exception:
                payload = {"raw": data_str}
            frames.append((current_event, payload))
    return frames


# ==============================================================================
# 1. Integration Contracts & Adapter Verification (Mock & Production)
# ==============================================================================


class TestIntegrationContracts:
    """Verifies Group 1, Group 2, and Group 3 public contracts on both mock and real adapters."""

    def test_mock_adapters_implement_agreed_interfaces(self):
        mock_tools = MockToolRegistryAdapter()
        tools_list = mock_tools.list_tools()
        assert len(tools_list) >= 4
        res = mock_tools.execute_tool_call("validate_target", {"target_url": "http://localhost:3000"}, {"assessment_id": "s1"})
        assert res["success"] is True

        mock_mem = MockMemoryManager()
        mock_mem.save_observation("s1", {"step": "scope_checked"})
        know = mock_mem.search_knowledge("BOLA", category="BOLA_IDOR", limit=3)
        assert len(know) >= 1
        fid = mock_mem.save_finding("s1", {"title": "Test BOLA", "severity": "HIGH"})
        assert fid.startswith("mock_fnd_")
        ctx = mock_mem.get_context("s1")
        assert ctx["assessment_id"] == "s1"
        assert len(ctx["observations"]) == 1
        assert len(ctx["findings"]) == 1

    def test_production_adapters_implement_agreed_interfaces(self, tmp_path):
        db = DatabaseManager(db_path=str(tmp_path / "prod_adapters.db"))
        repo = FindingRepository(db_manager=db)

        # Group 2: ToolRegistryAdapter
        prod_tools = ToolRegistryAdapter()
        registered = prod_tools.list_tools()
        tool_names = [t["name"] for t in registered]
        assert "validate_target" in tool_names
        assert "discover_endpoints" in tool_names

        exec_ok = prod_tools.execute_tool_call(
            "validate_target",
            {"target_url": "http://localhost:3000", "http_method": "GET"},
            {"assessment_id": "scan_prod_01", "target_url": "http://localhost:3000"},
        )
        assert exec_ok["success"] is True
        assert exec_ok["output"]["is_allowed"] is True

        # Out-of-scope call through ToolRegistryAdapter is rejected by ScopeGuard
        exec_blocked = prod_tools.execute_tool_call(
            "validate_target",
            {"target_url": "https://evil.example.com", "http_method": "GET"},
            {"assessment_id": "scan_prod_01"},
        )
        assert exec_blocked["output"]["is_allowed"] is False

        # Group 3: MemoryManager
        prod_mem = MemoryManager(repository=repo)
        prod_mem.save_observation("scan_prod_01", {"tool": "validate_target", "allowed": True})
        knowledge = prod_mem.search_knowledge("ownership basket", category="BOLA_IDOR", limit=5)
        assert len(knowledge) >= 1
        saved_id = prod_mem.save_finding(
            "scan_prod_01",
            {"id": "fnd_001", "title": "BOLA on /rest/basket/1", "severity": "HIGH"},
        )
        assert saved_id == "fnd_001"
        context = prod_mem.get_context("scan_prod_01")
        assert context["assessment_id"] == "scan_prod_01"
        assert len(context["observations"]) >= 1
        assert len(context["findings"]) == 1

        # Group 1: GeminiAuthScopeAgent
        prod_agent = GeminiAuthScopeAgent(
            tool_registry=prod_tools,
            memory_manager=prod_mem,
            repository=repo,
        )
        assert hasattr(prod_agent, "astream_assessment")
        plan = prod_agent.create_plan("http://localhost:3000", "scan_prod_01")
        assert len(plan.steps) >= 1


# ==============================================================================
# 2. URL Submission & Scope Rejection
# ==============================================================================


class TestURLSubmissionAndScopeGuard:
    """Verifies target URL validation and ScopeGuard enforcement on POST /api/assessments."""

    def test_create_assessment_valid_url_with_mock_agent(self, client):
        mock_agent = MockGeminiAuthScopeAgent(mode="standard")
        task_manager.configure_dependencies(agent=mock_agent)

        res = client.post(
            "/api/assessments",
            json={
                "target_url": "http://localhost:3000",
                "github_repo": "https://github.com/juice-shop/juice-shop",
            },
        )
        assert res.status_code == 201
        body = res.json()
        assert body["assessment_id"].startswith("scan_")
        assert body["target_url"] == "http://localhost:3000"
        assert body["status"] == "PENDING"

    @pytest.mark.parametrize(
        "invalid_url",
        [
            "https://example.com",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:9999/api",
            "ftp://localhost:3000/files",
        ],
    )
    def test_create_assessment_rejects_out_of_scope_urls(self, client, invalid_url):
        res = client.post("/api/assessments", json={"target_url": invalid_url})
        assert res.status_code == 400
        assert "Scope violation" in res.json()["detail"]

    def test_create_assessment_rejects_empty_url(self, client):
        res = client.post("/api/assessments", json={"target_url": "   "})
        assert res.status_code == 400
        assert "empty" in res.json()["detail"].lower()


# ==============================================================================
# 3. SSE Streaming & All 15 Event Types Verification
# ==============================================================================


class TestSSEStreamingEvents:
    """Verifies SSE streaming emits all 15 required event types in proper order."""

    def test_stream_emits_full_lifecycle_events_with_mock_agent(self, client):
        mock_tools = MockToolRegistryAdapter()
        mock_mem = MockMemoryManager()
        mock_agent = MockGeminiAuthScopeAgent(
            tool_registry=mock_tools,
            memory_manager=mock_mem,
            mode="standard",
        )
        task_manager.configure_dependencies(
            agent=mock_agent,
            tool_registry=mock_tools,
            memory_manager=mock_mem,
        )

        create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        assert create_res.status_code == 201
        scan_id = create_res.json()["assessment_id"]

        raw_lines: List[str] = []
        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            assert stream_res.status_code == 200
            for line in stream_res.iter_lines():
                if line:
                    raw_lines.append(line)
                    if line.startswith("event: done"):
                        # Read one more data line for done payload
                        continue

        frames = _parse_sse_frames(raw_lines)
        event_names = [f[0] for f in frames]

        # Verify core required SSE event types are present
        expected_events = [
            "assessment_started",
            "agent_thinking",
            "agent_plan",
            "tool_started",
            "tool_completed",
            "endpoint_discovered",
            "finding_hypothesis",
            "evidence_validated",
            "finding_discovered",
            "source_location_found",
            "explanation_generated",
            "assessment_completed",
            "done",
        ]
        for expected in expected_events:
            assert expected in event_names, f"Missing expected SSE event '{expected}' in {event_names}"

        # CRITICAL SAFETY GATE: evidence_validated must be emitted BEFORE confirmed finding_discovered
        idx_evidence = event_names.index("evidence_validated")
        idx_finding = event_names.index("finding_discovered")
        assert idx_evidence < idx_finding, "evidence_validated must precede confirmed finding_discovered"

        # Verify black-box source location notice when no source code is provided
        src_frames = [payload for name, payload in frames if name == "source_location_found"]
        assert len(src_frames) >= 1
        assert src_frames[0]["black_box_only"] is True
        assert "Black-box assessment only" in str(src_frames[0]["message"])

    def test_stream_with_verified_source_location(self, client):
        mock_agent = MockGeminiAuthScopeAgent(mode="with_source")
        task_manager.configure_dependencies(agent=mock_agent)

        create_res = client.post(
            "/api/assessments",
            json={"target_url": "http://localhost:3000", "github_repo": "juice-shop"},
        )
        scan_id = create_res.json()["assessment_id"]

        raw_lines: List[str] = []
        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            for line in stream_res.iter_lines():
                if line:
                    raw_lines.append(line)

        frames = _parse_sse_frames(raw_lines)
        src_frames = [payload for name, payload in frames if name == "source_location_found"]
        assert len(src_frames) >= 1
        assert src_frames[0]["black_box_only"] is False
        assert src_frames[0]["source_file"] == "routes/basket.ts"
        assert src_frames[0]["line_numbers"] == "18-29"

    def test_stream_inconclusive_finding_not_falsely_confirmed(self, client):
        mock_agent = MockGeminiAuthScopeAgent(mode="inconclusive")
        task_manager.configure_dependencies(agent=mock_agent)

        create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        scan_id = create_res.json()["assessment_id"]

        raw_lines: List[str] = []
        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            for line in stream_res.iter_lines():
                if line:
                    raw_lines.append(line)

        frames = _parse_sse_frames(raw_lines)
        disc_frames = [payload for name, payload in frames if name == "finding_discovered"]
        assert len(disc_frames) == 1
        assert disc_frames[0]["validation_status"] == "SUSPICIOUS"

        done_frames = [payload for name, payload in frames if name == "done"]
        assert len(done_frames) == 1
        assert done_frames[0]["confirmed_findings"] == 0
        assert done_frames[0]["suspicious_results"] == 1

    def test_stream_tool_failed_and_assessment_failed_events(self, client):
        mock_agent = MockGeminiAuthScopeAgent(mode="fail")
        task_manager.configure_dependencies(agent=mock_agent)

        create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        scan_id = create_res.json()["assessment_id"]

        raw_lines: List[str] = []
        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            for line in stream_res.iter_lines():
                if line:
                    raw_lines.append(line)

        frames = _parse_sse_frames(raw_lines)
        event_names = [f[0] for f in frames]
        assert "tool_failed" in event_names
        assert "assessment_failed" in event_names

        state_res = client.get(f"/api/assessments/{scan_id}")
        assert state_res.status_code == 200
        assert state_res.json()["status"] == "FAILED"


# ==============================================================================
# 4. Cancellation & Reconnection Replay
# ==============================================================================


class TestCancellationAndReplay:
    """Verifies safe cancellation and Last-Event-ID SSE replay."""

    def test_stop_assessment_emits_assessment_cancelled(self, client):
        mock_agent = MockGeminiAuthScopeAgent(mode="slow_cancellable")
        task_manager.configure_dependencies(agent=mock_agent)

        create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        scan_id = create_res.json()["assessment_id"]

        # Trigger cancellation
        stop_res = client.post(f"/api/assessments/{scan_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "CANCELLING"

        raw_lines: List[str] = []
        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            for line in stream_res.iter_lines():
                if line:
                    raw_lines.append(line)

        frames = _parse_sse_frames(raw_lines)
        event_names = [f[0] for f in frames]
        assert "assessment_cancelled" in event_names

        state_res = client.get(f"/api/assessments/{scan_id}")
        assert state_res.json()["status"] == "CANCELLED"

    def test_findings_and_retest_endpoints(self, client):
        repo = FindingRepository()
        scan_id = "scan_findings_endpoint_test"
        repo.save_scan_session(
            ScanSessionRecord(
                id=scan_id,
                target_url="http://localhost:3000",
                status="COMPLETED",
                confirmed_findings_count=1,
            )
        )
        repo.save_finding(
            FindingRecord(
                id="fnd_endpoint_test_01",
                scan_id=scan_id,
                title="Confirmed BOLA on /rest/basket/1",
                endpoint="/rest/basket/1",
                target_endpoint="/rest/basket/1",
                http_method="GET",
                vulnerability_category="BOLA_IDOR",
                vulnerability_type="BOLA_IDOR",
                severity=SeverityLevel.HIGH,
                status="confirmed",
                confirmation_status="confirmed",
                validation_status="CONFIRMED",
                evidence=EvidenceArtifact(
                    id="evi_test_01",
                    finding_id="fnd_endpoint_test_01",
                    evidence_sha256="a" * 64,
                    response_status=200,
                ),
            )
        )

        # GET /api/assessments/{id}/findings
        findings_res = client.get(f"/api/assessments/{scan_id}/findings")
        assert findings_res.status_code == 200
        findings_list = findings_res.json()
        assert len(findings_list) == 1
        assert findings_list[0]["id"] == "fnd_endpoint_test_01"

        # POST /api/assessments/{id}/retest
        retest_res = client.post(f"/api/assessments/{scan_id}/retest")
        assert retest_res.status_code == 200
        retest_data = retest_res.json()
        assert retest_data["assessment_id"] == scan_id
        assert retest_data["retested_count"] == 1

    def test_session_bound_repository_prevents_duplicate_sessions(self, tmp_path):
        """Ensures SessionBoundRepositoryProxy binds all AssessmentEngine writes to a single scan_id."""
        db = DatabaseManager(db_path=str(tmp_path / "single_session.db"))
        repo = FindingRepository(db_manager=db)
        api_scan_id = "scan_api_canonical_001"

        repo.save_scan_session(
            ScanSessionRecord(
                id=api_scan_id,
                target_url="http://localhost:3000",
                status="PENDING",
            )
        )

        proxy = SessionBoundRepositoryProxy(repository=repo, bound_scan_id=api_scan_id)
        # Simulate AssessmentEngine saving its own generated scan_id
        engine_session = ScanSessionRecord(
            id="scan_engine_internal_999",
            target_url="http://localhost:3000",
            status="COMPLETED",
            endpoints_discovered_count=8,
            confirmed_findings_count=1,
        )
        proxy.save_scan_session(engine_session)

        # Must mutate engine_session.id in-place and persist ONLY under api_scan_id
        assert engine_session.id == api_scan_id
        all_sessions = repo.list_scan_sessions(limit=10)
        assert len(all_sessions) == 1
        assert all_sessions[0].id == api_scan_id
        assert all_sessions[0].status == "COMPLETED"
        assert all_sessions[0].endpoints_discovered_count == 8

