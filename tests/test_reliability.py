"""Unit and Integration Tests for AuthScope Reliability and Hardening Improvements.

Covers:
1. Decoupled background assessment execution & browser disconnection tolerance.
2. SSE event replay, cursor resumption with Last-Event-ID, and event deduplication.
3. CORS configuration restrictions (no wildcard with credentials, allowed dev origins only).
4. Validated finding messages built from actual FindingRecord and EvidenceValidator status.
5. Browser refresh recovery of in-progress and completed sessions.
"""

import json
import time
from typing import Dict, Any
from fastapi.testclient import TestClient
import pytest

from backend.api.app import app, _format_event_message_chunk, task_manager
from backend.config import settings
from backend.core.session_manager import Role
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


@pytest.fixture
def test_client():
    with TestClient(app) as client:
        yield client


@pytest.mark.unit
class TestCORSRestrictions:
    """Verifies Requirement 2: CORS restricts origins and never combines wildcard with credentials."""

    def test_allowed_development_origin_cors_headers(self, test_client):
        """Allowed development origins receive matching Access-Control-Allow-Origin header with credentials."""
        response = test_client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert response.headers.get("access-control-allow-credentials") == "true"
        # Must never be wildcard
        assert response.headers.get("access-control-allow-origin") != "*"

    def test_alternate_allowed_origin_localhost_3001(self, test_client):
        """Next.js alternate development port 3001 is permitted."""
        response = test_client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:3001",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3001"
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_unauthorized_external_origin_rejected(self, test_client):
        """External unauthorized origins do not receive allow-origin permission."""
        response = test_client.options(
            "/api/health",
            headers={
                "Origin": "https://attacker-controlled-site.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Unauthorized origins must not be allowed access
        allow_origin = response.headers.get("access-control-allow-origin")
        assert allow_origin != "https://attacker-controlled-site.com"
        assert allow_origin != "*"


@pytest.mark.unit
class TestValidatedFindingMessages:
    """Verifies Requirement 3: Finding messages are built from verified FindingRecord and EvidenceValidator status."""

    def test_confirmed_finding_message_uses_actual_record_fields(self):
        """Confirmed vulnerability message builds from actual FindingRecord properties with zero generic text."""
        finding = FindingRecord(
            id="fnd_real_idor_99",
            scan_id="scan_unit_test_01",
            title="Insecure Direct Object Reference on /rest/basket/{id}",
            endpoint="/rest/basket/5",
            target_endpoint="/rest/basket/5",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            vulnerability_type="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="User B request to User A basket must be denied with HTTP 403 Forbidden.",
            actual_behavior="User B received HTTP 200 OK with User A private shopping cart data.",
            severity=SeverityLevel.HIGH,
            status="confirmed",
            confirmation_status="confirmed",
            validation_status="CONFIRMED",
            access_verdict="CONFIRMED_UNAUTHORIZED_ACCESS",
            impact_explanation="Tenant isolation failure allows cross-account shopping cart surveillance.",
            remediation_guidance="// Verify ownership\nif (basket.UserId !== req.user.id) return res.status(403);",
            evidence=EvidenceArtifact(
                id="evi_99",
                finding_id="fnd_real_idor_99",
                evidence_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                testing_role="user_b",
                response_status=200,
            ),
        )

        event = AssessmentEvent(
            assessment_id="scan_unit_test_01",
            event_type=EventType.FINDING_CONFIRMED.value,
            stage=AssessmentStage.EVIDENCE_VALIDATION.value,
            message=f"Evidence validated: {finding.title}",
            metadata={
                "finding_id": finding.id,
                "endpoint": finding.target_endpoint,
                "severity": "HIGH",
                "sha256": finding.evidence.evidence_sha256,
            },
        )

        msg = _format_event_message_chunk(event, finding=finding)
        assert msg is not None
        # Confirmed vulnerability emoji and heading
        assert "### 🚨 Confirmed Vulnerability:" in msg
        assert finding.title in msg
        # Actual dynamic fields from finding record
        assert "/rest/basket/5" in msg
        assert "User B received HTTP 200 OK with User A private shopping cart data." in msg
        assert "User B request to User A basket must be denied with HTTP 403 Forbidden." in msg
        assert "Tenant isolation failure allows cross-account shopping cart surveillance." in msg
        assert "CONFIRMED_UNAUTHORIZED_ACCESS" in msg
        assert "abcdef1234567890" in msg
        assert "if (basket.UserId !== req.user.id)" in msg

    def test_suspicious_finding_message_distinguishes_unconfirmed_status(self):
        """Suspicious finding message clearly indicates unverified baseline status."""
        event = AssessmentEvent(
            assessment_id="scan_unit_test_02",
            event_type=EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value,
            stage=AssessmentStage.AUTHORIZATION_TESTING.value,
            message="Suspicious access observed on /rest/admin/whoami",
            metadata={
                "endpoint": "/rest/admin/whoami",
                "status_code": 200,
                "verdict": "SUSPICIOUS_ACCESS",
                "actual_behavior": "Anonymous request returned HTTP 200 with 150 bytes of JSON.",
                "expected_behavior": "Admin route should require elevated credentials.",
                "validation_status": "SUSPICIOUS",
                "remediation": "// Require admin\napp.use(verifyAdmin);",
            },
        )

        msg = _format_event_message_chunk(event)
        assert msg is not None
        # Suspicious warning emoji and label
        assert "### ⚠️ Suspicious Access Pattern (Requires Review):" in msg
        assert "/rest/admin/whoami" in msg
        assert "SUSPICIOUS_ACCESS" in msg
        assert "SUSPICIOUS" in msg
        assert "Anonymous request returned HTTP 200 with 150 bytes of JSON." in msg
        assert "Admin route should require elevated credentials." in msg
        assert "Comparative multi-role session baselines were unverified" in msg


@pytest.mark.unit
class TestBackgroundExecutionAndBrowserDisconnect:
    """Verifies Requirement 1: Assessment execution continues in background even if client disconnects."""

    def test_create_assessment_starts_background_task(self, test_client):
        """POST /api/assessments accepts request and registers a background task."""
        create_res = test_client.post(
            "/api/assessments",
            json={"target_url": "http://localhost:3000"},
        )
        assert create_res.status_code == 201
        data = create_res.json()
        scan_id = data["assessment_id"]
        assert data["status"] == "PENDING"
        assert "background" in data["message"].lower()

        # Task manager has registered token and task
        token = task_manager.get_token(scan_id)
        assert token is not None
        assert token.is_cancelled is False

    def test_browser_disconnect_does_not_abort_background_task(self, test_client):
        """Disconnecting the SSE stream client does not terminate the background assessment."""
        create_res = test_client.post(
            "/api/assessments",
            json={"target_url": "http://localhost:3000"},
        )
        scan_id = create_res.json()["assessment_id"]

        # Simulate browser opening stream then closing abruptly after reading 2 lines
        with test_client.stream("GET", f"/api/assessments/{scan_id}/stream") as stream_res:
            assert stream_res.status_code == 200
            read_count = 0
            for line in stream_res.iter_lines():
                if line:
                    read_count += 1
                if read_count >= 2:
                    break

        # Stream context closed (simulating disconnect). Background token is NOT cancelled!
        token = task_manager.get_token(scan_id)
        assert token is not None
        assert token.is_cancelled is False


@pytest.mark.unit
class TestSSEReconnectionAndDeduplication:
    """Verifies Requirement 4: SSE reconnection and event deduplication via Last-Event-ID."""

    def test_incremental_replay_with_last_event_id(self, test_client):
        """Events prior to Last-Event-ID cursor are skipped; subsequent events are delivered."""
        repo = FindingRepository()
        scan_id = "scan_replay_test_01"
        session = ScanSessionRecord(
            id=scan_id,
            target_url="http://localhost:3000",
            status="COMPLETED",
            summary_text="Replay test completed",
        )
        repo.save_scan_session(session)

        # Insert 3 events
        ev1 = AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
            stage=AssessmentStage.SCOPE_VALIDATION.value,
            message="Event 1: Scope verified",
        )
        ev2 = AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.CONNECTION_COMPLETED.value,
            stage=AssessmentStage.TARGET_CONNECTION.value,
            message="Event 2: Connection verified",
        )
        ev3 = AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.ENDPOINT_DISCOVERY_COMPLETED.value,
            stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
            message="Event 3: Endpoints mapped",
            metadata={"endpoints_discovered": 5},
        )

        id1 = repo.save_event(ev1)
        id2 = repo.save_event(ev2)
        id3 = repo.save_event(ev3)

        assert id1 > 0 and id2 > id1 and id3 > id2

        # Reconnect with cursor matching id2 (events 1 & 2 already seen)
        with test_client.stream(
            "GET",
            f"/api/assessments/{scan_id}/stream",
            headers={"Last-Event-ID": str(id2)},
        ) as stream_res:
            assert stream_res.status_code == 200
            content = "".join(stream_res.iter_text())

            # Event 1 and 2 must NOT be replayed
            assert f"id: {id1}\n" not in content
            assert f"id: {id2}\n" not in content
            assert "Event 1: Scope verified" not in content
            assert "Event 2: Connection verified" not in content

            # Event 3 must be delivered with its unique id
            assert f"id: {id3}\n" in content
            assert "Event 3: Endpoints mapped" in content
            assert "event: done" in content


@pytest.mark.unit
class TestRefreshRecovery:
    """Verifies Requirement 5: Refresh recovery restores session and reconnects to active stream."""

    def test_refresh_recovery_returns_active_session_state(self, test_client):
        """Active session state and stages are fully queryable upon browser reload."""
        create_res = test_client.post(
            "/api/assessments",
            json={"target_url": "http://localhost:3000"},
        )
        scan_id = create_res.json()["assessment_id"]

        # Simulate page refresh by fetching session state
        get_res = test_client.get(f"/api/assessments/{scan_id}")
        assert get_res.status_code == 200
        state = get_res.json()
        assert state["id"] == scan_id
        assert state["target_url"] == "http://localhost:3000"
        assert state["status"] in ("PENDING", "RUNNING", "COMPLETED")
        assert "stages" in state
        assert len(state["stages"]) == 7
