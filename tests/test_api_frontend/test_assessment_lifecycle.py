"""Unit and integration tests for AuthScope Assessment Lifecycle Management.

Covers:
1. Canonical lifecycle states and state machine transitions.
2. Prevention of duplicate scans on identical active target URLs.
3. Accurate cancellation using CancellationToken and event persistence.
4. Retry mechanism on terminal assessments and rejection on active sessions (HTTP 409).
5. Detached background execution ensuring client disconnection does not destroy scan tasks.
"""

import asyncio
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app, task_manager, active_tokens
from backend.api.lifecycle import (
    AssessmentStatus,
    InvalidStateTransitionError,
    validate_state_transition,
    is_terminal_state,
    is_active_state,
)
from backend.core.assessment_engine import CancellationToken
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import ScanSessionRecord


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def repo():
    return FindingRepository()


@pytest.mark.unit
def test_lifecycle_state_machine_valid_transitions():
    """Verifies that legal lifecycle state progressions pass validation."""
    assert validate_state_transition("CREATED", "QUEUED") is True
    assert validate_state_transition("QUEUED", "RUNNING") is True
    assert validate_state_transition("RUNNING", "COMPLETED") is True
    assert validate_state_transition("RUNNING", "FAILED") is True
    assert validate_state_transition("RUNNING", "CANCELLED") is True
    assert validate_state_transition("PENDING", "RUNNING") is True
    # Self-transitions are idempotent
    assert validate_state_transition("RUNNING", "RUNNING") is True
    assert validate_state_transition("COMPLETED", "COMPLETED") is True


@pytest.mark.unit
def test_lifecycle_state_machine_invalid_transitions():
    """Verifies that illegal transitions from terminal states raise InvalidStateTransitionError."""
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        validate_state_transition("COMPLETED", "RUNNING")
    assert "Invalid state transition" in str(exc_info.value)
    assert exc_info.value.current_state == "COMPLETED"
    assert exc_info.value.target_state == "RUNNING"

    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition("FAILED", "RUNNING")

    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition("CANCELLED", "RUNNING")


@pytest.mark.unit
def test_terminal_and_active_state_predicates():
    """Verifies predicate functions for identifying active and terminal states."""
    assert is_terminal_state("COMPLETED") is True
    assert is_terminal_state("FAILED") is True
    assert is_terminal_state("CANCELLED") is True
    assert is_terminal_state("RUNNING") is False
    assert is_terminal_state("QUEUED") is False

    assert is_active_state("RUNNING") is True
    assert is_active_state("QUEUED") is True
    assert is_active_state("PENDING") is True
    assert is_active_state("COMPLETED") is False
    assert is_active_state("CANCELLED") is False


@pytest.mark.integration
def test_prevent_duplicate_active_scan(client, repo):
    """Submitting a start request for an already actively running target returns existing assessment."""
    # 1. Create first assessment
    res1 = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    assert res1.status_code == 201
    scan_id_1 = res1.json()["assessment_id"]

    # 2. While first scan is actively tracked, submit duplicate request for same target
    res2 = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    assert res2.status_code == 201
    data2 = res2.json()

    # Must return the existing active assessment without spawning a duplicate
    assert data2["assessment_id"] == scan_id_1
    assert "already running" in data2["message"].lower()

    # Clean up
    client.post(f"/api/assessments/{scan_id_1}/stop")


@pytest.mark.integration
def test_stop_assessment_lifecycle(client, repo):
    """Cancellation updates state to CANCELLED, cancels token, and persists cancellation event."""
    res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = res.json()["assessment_id"]

    # Trigger stop
    stop_res = client.post(f"/api/assessments/{scan_id}/stop")
    assert stop_res.status_code == 200
    stop_data = stop_res.json()
    assert "cancellation" in stop_data["message"].lower() or "cancelled" in stop_data["status"].lower()

    # Verify session in DB is marked CANCELLED
    sess = repo.get_scan_session(scan_id)
    assert sess.status == "CANCELLED"
    assert sess.completed_at is not None

    # Calling stop again on already terminal session reports terminal state cleanly
    stop_res2 = client.post(f"/api/assessments/{scan_id}/stop")
    assert stop_res2.status_code == 200
    assert stop_res2.json()["status"] == "CANCELLED"


@pytest.mark.integration
def test_retry_terminal_assessment(client, repo):
    """Retrying a cancelled or failed assessment resets session and launches background task."""
    # 1. Create and cancel an assessment
    res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = res.json()["assessment_id"]
    client.post(f"/api/assessments/{scan_id}/stop")

    # Verify cancelled
    sess = repo.get_scan_session(scan_id)
    assert sess.status == "CANCELLED"

    # 2. Invoke retry endpoint
    retry_res = client.post(f"/api/assessments/{scan_id}/retry")
    assert retry_res.status_code == 200
    retry_data = retry_res.json()
    assert retry_data["assessment_id"] == scan_id
    assert retry_data["status"] == "PENDING"
    assert "retried" in retry_data["message"].lower()

    # Clean up
    client.post(f"/api/assessments/{scan_id}/stop")


@pytest.mark.integration
def test_retry_active_assessment_rejected(client, repo):
    """Retrying an actively running assessment is rejected with HTTP 409 Conflict."""
    res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = res.json()["assessment_id"]

    # Try retrying while active
    retry_res = client.post(f"/api/assessments/{scan_id}/retry")
    assert retry_res.status_code == 409
    assert "already actively running" in retry_res.json()["detail"].lower()

    # Clean up
    client.post(f"/api/assessments/{scan_id}/stop")


@pytest.mark.integration
def test_detached_client_execution(client, repo):
    """Client disconnecting from SSE stream does not terminate background assessment."""
    res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    scan_id = res.json()["assessment_id"]

    # Open stream briefly then close connection
    with client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
        assert stream_res.status_code == 200
        for _ in stream_res.iter_lines():
            break  # Disconnect immediately

    # Verify task manager still holds running background execution or token
    token = task_manager.get_token(scan_id)
    assert token is not None
    assert not token.is_cancelled

    # Clean up
    client.post(f"/api/assessments/{scan_id}/stop")

