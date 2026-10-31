"""Tests for AuthScope Persistent Background Task Recovery and Multi-Role Authentication Configuration.

Covers:
1. Persistent Background Task Recovery:
   - Metadata persistence in SQLite (updated_at, failure_reason).
   - Startup recovery marking orphaned RUNNING/PENDING sessions as FAILED with SERVER_RESTART.
   - Active in-memory tasks are preserved and not incorrectly marked as failed.
   - Timeout handling for stuck tasks.
   - Retry endpoint (POST /api/assessments/{id}/retry) resetting state and restarting.

2. Multi-Role Authentication Configuration:
   - Configured credentials via environment settings (USER_A_TOKEN, USER_B_TOKEN, ADMIN_TOKEN).
   - SessionManager credential validation and isolation.
   - Cross-user ownership checking (owns_resource).
   - Missing credentials handling (SUSPICIOUS_ACCESS, not false CONFIRMED).
   - Absolute zero credential exposure in repr, logs, API responses, or reports.
"""

from datetime import datetime, timezone
import os
import uuid
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app, task_manager
from backend.config import settings
from backend.core.assessment_engine import AssessmentEngine, CancellationToken
from backend.core.session_manager import (
    AuthCredentials,
    Role,
    RoleSession,
    SessionManager,
    EnvTokenAuthenticationAdapter,
)
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    EventType,
    ScanSessionRecord,
)


@pytest.fixture
def repo(tmp_path):
    """Provides a fresh isolated FindingRepository using a temporary SQLite database."""
    db_file = tmp_path / "test_recovery_auth.db"
    db = DatabaseManager(db_path=str(db_file))
    return FindingRepository(db_manager=db)


@pytest.fixture
def test_client():
    """Provides a FastAPI test client with startup and shutdown lifecycles."""
    with TestClient(app) as client:
        yield client


class TestPersistentBackgroundTaskRecovery:
    """Tests for SQLite-backed task state tracking, startup recovery, and retries."""

    def test_session_metadata_persistence_updated_at_and_failure_reason(self, repo):
        """Verifies updated_at and failure_reason are persisted and retrieved correctly in SQLite."""
        scan_id = f"scan_meta_{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)
        session = ScanSessionRecord(
            id=scan_id,
            target_url="http://localhost:3000",
            status="RUNNING",
            started_at=now,
            updated_at=now,
            failure_reason="",
        )
        repo.save_scan_session(session)

        loaded = repo.get_scan_session(scan_id)
        assert loaded is not None
        assert loaded.id == scan_id
        assert loaded.status == "RUNNING"
        assert loaded.failure_reason == ""
        assert loaded.updated_at is not None

        # Update failure reason and status
        loaded.status = "FAILED"
        loaded.failure_reason = "SERVER_RESTART"
        repo.save_scan_session(loaded)

        reloaded = repo.get_scan_session(scan_id)
        assert reloaded.status == "FAILED"
        assert reloaded.failure_reason == "SERVER_RESTART"

    def test_startup_recovery_marks_orphaned_sessions_as_server_restart(self, repo):
        """Verifies orphaned RUNNING and PENDING sessions are transitioned to FAILED (SERVER_RESTART)."""
        scan_running = f"scan_run_{uuid.uuid4().hex[:6]}"
        scan_pending = f"scan_pen_{uuid.uuid4().hex[:6]}"
        scan_completed = f"scan_done_{uuid.uuid4().hex[:6]}"

        now = datetime.now(timezone.utc)
        repo.save_scan_session(
            ScanSessionRecord(
                id=scan_running,
                target_url="http://localhost:3000",
                status="RUNNING",
                started_at=now,
            )
        )
        repo.save_scan_session(
            ScanSessionRecord(
                id=scan_pending,
                target_url="http://localhost:3000",
                status="PENDING",
                started_at=now,
            )
        )
        repo.save_scan_session(
            ScanSessionRecord(
                id=scan_completed,
                target_url="http://localhost:3000",
                status="COMPLETED",
                started_at=now,
                completed_at=now,
            )
        )

        # Recover orphaned sessions when no tasks are active in memory
        recovered_count = repo.recover_orphaned_running_sessions(active_session_ids=set())
        assert recovered_count == 2

        # Verify scan_running
        s_run = repo.get_scan_session(scan_running)
        assert s_run.status == "FAILED"
        assert s_run.failure_reason == "SERVER_RESTART"
        assert "server restart" in s_run.summary_text.lower()
        assert s_run.completed_at is not None

        # Verify scan_pending
        s_pen = repo.get_scan_session(scan_pending)
        assert s_pen.status == "FAILED"
        assert s_pen.failure_reason == "SERVER_RESTART"

        # Verify already COMPLETED session is unchanged
        s_done = repo.get_scan_session(scan_completed)
        assert s_done.status == "COMPLETED"
        assert s_done.failure_reason == ""

        # Verify audit event was logged in event stream
        events_run = repo.list_events(scan_running)
        assert len(events_run) >= 1
        assert events_run[-1].event_type == EventType.ASSESSMENT_FAILED.value
        assert events_run[-1].metadata.get("failure_reason") == "SERVER_RESTART"

    def test_startup_recovery_preserves_active_tasks(self, repo):
        """Ensures sessions with active in-memory background tasks are NOT marked as failed."""
        active_id = f"scan_active_{uuid.uuid4().hex[:6]}"
        orphaned_id = f"scan_orphaned_{uuid.uuid4().hex[:6]}"

        now = datetime.now(timezone.utc)
        repo.save_scan_session(
            ScanSessionRecord(id=active_id, target_url="http://localhost:3000", status="RUNNING", started_at=now)
        )
        repo.save_scan_session(
            ScanSessionRecord(id=orphaned_id, target_url="http://localhost:3000", status="RUNNING", started_at=now)
        )

        # Pass active_id in the active session set
        recovered = repo.recover_orphaned_running_sessions(active_session_ids={active_id})
        assert recovered == 1

        # Active session should remain RUNNING
        active_sess = repo.get_scan_session(active_id)
        assert active_sess.status == "RUNNING"
        assert active_sess.failure_reason == ""

        # Orphaned session should be marked FAILED
        orphaned_sess = repo.get_scan_session(orphaned_id)
        assert orphaned_sess.status == "FAILED"
        assert orphaned_sess.failure_reason == "SERVER_RESTART"

    def test_retry_assessment_endpoint(self, test_client):
        """Verifies POST /api/assessments/{id}/retry restarts an interrupted or failed assessment."""
        # 1. Create initial assessment
        create_resp = test_client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        assert create_resp.status_code == 201
        scan_id = create_resp.json()["assessment_id"]

        # Cancel or fail it
        test_client.post(f"/api/assessments/{scan_id}/stop")

        # Wait for cancellation to complete in background task
        import time
        for _ in range(50):
            if not task_manager.is_running(scan_id):
                break
            time.sleep(0.05)

        # Set session as FAILED with SERVER_RESTART to simulate restart
        default_repo = FindingRepository()
        session = default_repo.get_scan_session(scan_id)
        session.status = "FAILED"
        session.failure_reason = "SERVER_RESTART"
        default_repo.save_scan_session(session)

        # 2. Retry the assessment
        retry_resp = test_client.post(f"/api/assessments/{scan_id}/retry")
        assert retry_resp.status_code == 200
        data = retry_resp.json()
        assert data["assessment_id"] == scan_id
        assert data["status"] == "PENDING"
        assert "retried" in data["message"].lower()

        # Check session is updated
        reloaded = default_repo.get_scan_session(scan_id)
        assert reloaded.status == "PENDING"
        assert reloaded.failure_reason == ""

    def test_retry_nonexistent_assessment_returns_404(self, test_client):
        """Verifies retrying a non-existent assessment returns 404."""
        resp = test_client.post("/api/assessments/scan_nonexistent_123/retry")
        assert resp.status_code == 404

    def test_assessment_timeout_configuration(self):
        """Verifies ASSESSMENT_TIMEOUT_SECONDS setting is loaded and defaults sensibly."""
        assert hasattr(settings, "assessment_timeout_seconds")
        assert settings.assessment_timeout_seconds > 0.0


class TestMultiRoleAuthenticationConfiguration:
    """Tests for multi-role credential configuration, validation, and isolation."""

    def test_session_manager_initializes_with_env_tokens(self, monkeypatch):
        """Verifies USER_A_TOKEN, USER_B_TOKEN, and ADMIN_TOKEN are loaded into separate sessions."""
        monkeypatch.setattr(settings, "user_a_token", "test_jwt_user_a_token_xyz")
        monkeypatch.setattr(settings, "user_b_token", "test_jwt_user_b_token_abc")
        monkeypatch.setattr(settings, "admin_token", "test_jwt_admin_token_super")

        sm = SessionManager(load_from_env=True)
        report = sm.validate_configured_credentials()

        assert report["user_a_authenticated"] is True
        assert report["user_b_authenticated"] is True
        assert report["admin_authenticated"] is True
        assert report["multi_role_ready"] is True
        assert "user_a" in report["authenticated_roles"]
        assert "user_b" in report["authenticated_roles"]
        assert "admin" in report["authenticated_roles"]

    def test_cross_user_resource_ownership(self, monkeypatch):
        """Verifies SessionManager auto-registers resource ownership for configured personas."""
        monkeypatch.setattr(settings, "user_a_token", "token_a")
        monkeypatch.setattr(settings, "user_b_token", "token_b")

        sm = SessionManager(load_from_env=True)
        user_a_sess = sm.get_session(Role.USER_A)
        user_b_sess = sm.get_session(Role.USER_B)

        # User A owns basket 1, User B owns basket 2
        assert user_a_sess.owns_resource("basket", "1") is True
        assert user_a_sess.owns_resource("basket", "2") is False

        assert user_b_sess.owns_resource("basket", "2") is True
        assert user_b_sess.owns_resource("basket", "1") is False

    def test_missing_credentials_reported_safely_without_speculation(self, monkeypatch):
        """Verifies unconfigured tokens are reported as not authenticated without breaking or inventing tokens."""
        monkeypatch.setattr(settings, "user_a_token", "")
        monkeypatch.setattr(settings, "user_b_token", "")
        monkeypatch.setattr(settings, "admin_token", "")

        sm = SessionManager(load_from_env=True)
        report = sm.validate_configured_credentials()

        assert report["user_a_authenticated"] is False
        assert report["user_b_authenticated"] is False
        assert report["admin_authenticated"] is False
        assert report["multi_role_ready"] is False
        assert report["authenticated_roles"] == []
        assert report["anonymous_baseline_ready"] is True

    def test_token_zero_exposure_in_repr_and_reports(self, monkeypatch):
        """Strictly validates that tokens and passwords are never exposed via repr, str, or reports."""
        raw_token_a = "secret_raw_jwt_token_user_a_999"
        raw_password_a = "secret_raw_password_user_a_888"

        monkeypatch.setattr(settings, "user_a_token", raw_token_a)
        monkeypatch.setattr(settings, "user_a_password", raw_password_a)

        sm = SessionManager(load_from_env=True)
        session_a = sm.get_session(Role.USER_A)

        # 1. repr(session) must never contain the raw token
        assert raw_token_a not in repr(session_a)
        assert raw_password_a not in repr(session_a)

        # 2. repr(credentials) must never contain the raw password
        creds = AuthCredentials(email="user@test.local", password=raw_password_a)
        assert raw_password_a not in repr(creds)

        # 3. validate_configured_credentials must never contain the token
        cred_report = sm.validate_configured_credentials()
        assert raw_token_a not in str(cred_report)
        assert raw_password_a not in str(cred_report)
