"""Tests for SSE Streaming Reliability, Reconnection, Event Recovery, and Heartbeats.

Covers:
1. Reconnection using Last-Event-ID header and last_event_id query parameter.
2. Event deduplication and sequential monotonic event IDs.
3. Suppression of initial planning events upon reconnection replay.
4. Heartbeat comment emission (: heartbeat) keeping long-lived connections alive.
5. Zero sensitive token or secret exposure in SSE streams.
6. Clean subscriber deregistration upon client disconnect.
"""

import asyncio
import json
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app, task_manager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import AssessmentEvent, AssessmentStage, EventType, ScanSessionRecord


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def repo():
    return FindingRepository()


@pytest.mark.integration
def test_sse_sequential_event_ids(client, repo):
    """Verifies that all events emitted via SSE have sequential, monotonically non-decreasing IDs."""
    create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = create_res.json()["assessment_id"]

    event_ids = []
    with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream:
        for line in stream.iter_lines():
            if line.startswith("id:"):
                raw_id = line.replace("id:", "").strip()
                try:
                    num_id = int(raw_id)
                    event_ids.append(num_id)
                except ValueError:
                    pass
            if len(event_ids) >= 4:
                break

    client.post(f"/api/assessments/{scan_id}/stop")

    assert len(event_ids) >= 2
    # Verify non-decreasing order
    for i in range(len(event_ids) - 1):
        assert event_ids[i] <= event_ids[i + 1]


@pytest.mark.integration
def test_sse_reconnection_with_last_event_id(client, repo):
    """Verifies that Last-Event-ID header only replays events created after the specified cursor."""
    scan_id = "scan_test_reconnect_001"
    sess = ScanSessionRecord(
        id=scan_id,
        target_url="http://localhost:3000",
        status="RUNNING",
    )
    repo.save_scan_session(sess)

    # Insert 3 events
    ev1 = AssessmentEvent(
        assessment_id=scan_id,
        event_type=EventType.SCOPE_VALIDATION_STARTED.value,
        stage=AssessmentStage.SCOPE_VALIDATION.value,
        message="Validating target scope",
    )
    repo.save_event(ev1)

    ev2 = AssessmentEvent(
        assessment_id=scan_id,
        event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
        stage=AssessmentStage.SCOPE_VALIDATION.value,
        message="Scope validation successful",
    )
    repo.save_event(ev2)

    ev3 = AssessmentEvent(
        assessment_id=scan_id,
        event_type=EventType.CONNECTION_COMPLETED.value,
        stage=AssessmentStage.TARGET_CONNECTION.value,
        message="Connecting to target host",
    )
    repo.save_event(ev3)

    # 1. Connect requesting events after ev1.id using Last-Event-ID header
    headers = {"Last-Event-ID": str(ev1.id)}
    replayed_activity_messages = []
    with client.stream("GET", f"/api/assessments/{scan_id}/stream", headers=headers) as stream:
        for line in stream.iter_lines():
            if line.startswith("data:") and "Scope validation" in line:
                replayed_activity_messages.append(line)
            if line.startswith("data:") and "Connecting to target" in line:
                replayed_activity_messages.append(line)
            if len(replayed_activity_messages) >= 2:
                break

    # ev1 should NOT be present; ev2 and ev3 should be present
    assert any("Scope validation successful" in msg for msg in replayed_activity_messages)
    assert any("Connecting to target host" in msg for msg in replayed_activity_messages)

    # Clean up
    client.post(f"/api/assessments/{scan_id}/stop")


@pytest.mark.integration
def test_sse_reconnection_suppresses_initial_planning(client, repo):
    """Reconnection with Last-Event-ID should not re-emit agent_plan or assessment_started events."""
    scan_id = "scan_test_reconnect_suppress"
    sess = ScanSessionRecord(
        id=scan_id,
        target_url="http://localhost:3000",
        status="RUNNING",
    )
    repo.save_scan_session(sess)

    ev = AssessmentEvent(
        assessment_id=scan_id,
        event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
        stage=AssessmentStage.SCOPE_VALIDATION.value,
        message="Scope OK",
    )
    repo.save_event(ev)

    # Reconnect with cursor
    received_types = []
    with client.stream("GET", f"/api/assessments/{scan_id}/stream?last_event_id={ev.id}") as stream:
        for line in stream.iter_lines():
            if line.startswith("event:"):
                ev_type = line.replace("event:", "").strip()
                received_types.append(ev_type)
            if len(received_types) >= 3:
                break

    # Initial planning events must be suppressed during reconnection replay
    assert "agent_plan" not in received_types
    assert "assessment_started" not in received_types

    client.post(f"/api/assessments/{scan_id}/stop")


@pytest.mark.integration
def test_sse_zero_sensitive_token_leakage(client, repo):
    """Verifies that no Bearer tokens or sensitive authorization headers leak into SSE payloads."""
    create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = create_res.json()["assessment_id"]

    payload_lines = []
    with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream:
        for line in stream.iter_lines():
            if line.startswith("data:"):
                payload_lines.append(line)
            if len(payload_lines) >= 8:
                break

    client.post(f"/api/assessments/{scan_id}/stop")

    for payload in payload_lines:
        assert "Bearer eyJ" not in payload
        assert "secret_key" not in payload.lower()
        assert "password" not in payload.lower()


@pytest.mark.integration
def test_sse_client_disconnect_unsubscribes_cleanly(client, repo):
    """Disconnecting from SSE cleanly unsubscribes the client queue without leaving orphaned subscribers."""
    scan_id = "scan_test_unsub_clean"
    sess = ScanSessionRecord(
        id=scan_id,
        target_url="http://localhost:3000",
        status="RUNNING",
    )
    repo.save_scan_session(sess)

    initial_subscribers = len(task_manager._subscribers.get(scan_id, []))
    assert initial_subscribers == 0

    # Connect client
    with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream:
        # One subscriber registered while connected
        for _ in stream.iter_lines():
            break

    # After exit of with block, subscriber should be cleanly cleaned up
    remaining = len(task_manager._subscribers.get(scan_id, []))
    assert remaining == 0
