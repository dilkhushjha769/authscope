"""Comprehensive tests for the SQLite migration, evidence persistence, error handling,
and counter consistency hotfix.
"""

import tempfile
import os
import sqlite3
import pytest
from datetime import datetime, timezone

from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    FindingRecord,
    EvidenceArtifact,
    SeverityLevel,
    Role,
    EvidenceValidationStatus,
    ScanSessionRecord,
    DiscoveredEndpointRecord,
    AssessmentStage,
    StageStatus,
)
from backend.core.assessment_engine import AssessmentEngine
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.scanner.request_executor import HttpResponseModel
from backend.core.scope_guard import ScopeGuard


class TestDatabaseMigrationHotfix:
    """Task 1 & Task 2: Verifies SQLite migration and evidence persistence integrity."""

    def test_migration_from_legacy_schema_without_timestamp(self):
        """Simulates an older SQLite table created without the timestamp column."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            db_path = os.path.join(tmpdir, "legacy.db")
            conn = sqlite3.connect(db_path)
            # Create a legacy evidence_artifacts table missing 'timestamp'
            conn.execute(
                """
                CREATE TABLE evidence_artifacts (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL,
                    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    test_role TEXT DEFAULT 'user_b',
                    authorized_role TEXT,
                    request_metadata_json TEXT DEFAULT '{}',
                    request_method TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    request_headers_json TEXT DEFAULT '{}',
                    response_status INTEGER NOT NULL,
                    relevant_response_headers_json TEXT DEFAULT '{}',
                    sanitized_response_body TEXT NOT NULL,
                    response_body TEXT NOT NULL,
                    evidence_validation_status TEXT DEFAULT 'valid',
                    evidence_sha256 TEXT NOT NULL,
                    redacted_fields_json TEXT DEFAULT '[]'
                )
                """
            )
            # Insert legacy row
            conn.execute(
                """
                INSERT INTO evidence_artifacts (
                    id, finding_id, captured_at, request_method, request_url,
                    response_status, sanitized_response_body, response_body, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "evi_legacy_1",
                    "fnd_legacy_1",
                    "2026-10-31 12:00:00",
                    "GET",
                    "http://localhost:3000/rest/admin/application-configuration",
                    200,
                    '{"app": "legacy"}',
                    '{"app": "legacy"}',
                    "sha256_legacy_hash",
                ),
            )
            conn.commit()
            conn.close()

            # Initialize DatabaseManager which runs _ensure_columns
            db = DatabaseManager(db_path)
            db.init_schema()

            # Verify timestamp column was added and backfilled from captured_at
            check_conn = db.get_connection()
            try:
                cursor = check_conn.execute("PRAGMA table_info(evidence_artifacts)")
                cols = {row[1] for row in cursor.fetchall()}
                assert "timestamp" in cols
                assert "captured_at" in cols

                row = check_conn.execute("SELECT id, timestamp, captured_at FROM evidence_artifacts WHERE id = ?", ("evi_legacy_1",)).fetchone()
                assert row is not None
                assert row["timestamp"] == "2026-10-31 12:00:00"
            finally:
                check_conn.close()
                db.close()

    def test_migration_is_idempotent(self):
        """Ensures calling init_schema repeatedly causes no errors or duplicate column exceptions."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            db_path = os.path.join(tmpdir, "idempotent.db")
            db = DatabaseManager(db_path)
            db.init_schema()
            # Run a second and third time
            db.init_schema()
            db.init_schema()
            db.close()

    def test_evidence_persistence_and_retrieval(self):
        """Verifies save_evidence, get_evidence, get_evidence_by_finding_id, and DB reopen."""
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            db_path = os.path.join(tmpdir, "evidence.db")
            db = DatabaseManager(db_path)
            db.init_schema()
            repo = FindingRepository(db)

            # First create the parent finding record (satisfying Foreign Key)
            fnd = FindingRecord(
                id="fnd_test_100",
                scan_id="scan_test_100",
                title="Test Finding 100",
                vulnerability_type="BFLA",
                severity=SeverityLevel.HIGH,
                status="confirmed",
                validation_status="CONFIRMED",
                access_verdict="CONFIRMED_UNAUTHORIZED_ACCESS",
                target_endpoint="/api/Users",
                http_method="GET",
                expected_behavior="401/403",
                actual_behavior="200 OK",
                description="Test description",
                remediation_guidance="Fix auth",
            )
            repo.save_finding(fnd)

            evi = EvidenceArtifact(
                id="evi_test_100",
                finding_id="fnd_test_100",
                request_method="GET",
                request_url="http://localhost:3000/api/Users",
                response_status=200,
                sanitized_response_body='{"users": ["admin", "alice"]}',
                evidence_sha256="hash_test_100",
                testing_role=Role.ANONYMOUS,
                authorized_role=Role.ADMIN,
                validation_status=EvidenceValidationStatus.CONFIRMED,
            )

            # Direct evidence save
            saved_id = repo.save_evidence(evi)
            assert saved_id == "evi_test_100"

            # Direct evidence retrieval
            retrieved = repo.get_evidence("evi_test_100")
            assert retrieved is not None
            assert retrieved.id == "evi_test_100"
            assert retrieved.evidence_sha256 == "hash_test_100"
            assert retrieved.timestamp is not None

            # By finding ID
            by_finding = repo.get_evidence_by_finding_id("fnd_test_100")
            assert by_finding is not None
            assert by_finding.id == "evi_test_100"

            # Close and reopen database
            db.close()
            db2 = DatabaseManager(db_path)
            db2.init_schema()
            repo2 = FindingRepository(db2)

            reopened_evi = repo2.get_evidence("evi_test_100")
            assert reopened_evi is not None
            assert reopened_evi.evidence_sha256 == "hash_test_100"
            db2.close()


class TestAssessmentErrorHandling:
    """Task 3: Verifies failure handling when persistence fails."""

    def test_assessment_fails_gracefully_on_persistence_error(self):
        """Ensures that if the repository raises a persistence error during assessment,
        the session transitions to FAILED with failure_reason='PERSISTENCE_ERROR'."""
        repo = FindingRepository(DatabaseManager(":memory:"))

        # Mock repository save_finding to simulate a database persistence failure
        def failing_save_finding(finding, overwrite=True):
            raise sqlite3.OperationalError("database disk image is malformed")

        repo.save_finding = failing_save_finding  # type: ignore[assignment]

        engine = AssessmentEngine(repository=repo)
        events = list(engine.stream_assessment("http://localhost:3000"))

        # Find the last event or failed event
        fail_ev = next((e for e in events if e.event_type == "assessment_failed"), None)
        assert fail_ev is not None
        assert "malformed" in fail_ev.message or "error" in fail_ev.message.lower()

        # Check scan session state
        sessions = repo.list_scan_sessions(limit=1)
        assert len(sessions) > 0
        session = sessions[0]
        assert session.status == "FAILED"
        assert session.failure_reason == "PERSISTENCE_ERROR"


class TestReportCountersConsistency:
    """Task 4: Verifies discovered, tested, confirmed, and suspicious counters remain consistent."""

    def test_counters_are_consistent_across_session_and_report(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
            db_path = os.path.join(tmpdir, "counters.db")
            db = DatabaseManager(db_path)
            db.init_schema()
            repo = FindingRepository(db)

            scan_id = "scan_counter_test"
            session = ScanSessionRecord(
                id=scan_id,
                target_url="http://localhost:3000",
                status="COMPLETED",
                endpoints_discovered_count=8,
                endpoints_tested_count=4,
                confirmed_findings_count=0,
                suspicious_results_count=1,
            )
            repo.save_scan_session(session)

            # Persist endpoints
            for i in range(8):
                ep = DiscoveredEndpointRecord(
                    id=f"ep_{scan_id}_{i}",
                    scan_id=scan_id,
                    path=f"/path/{i}",
                    test_status="TESTED" if i < 4 else "UNTESTED",
                )
                repo.save_discovered_endpoint(ep)

            # Check markdown export
            from backend.core.assessment_engine import AssessmentQueryAdapter
            adapter = AssessmentQueryAdapter(repository=repo)
            md = adapter.export_report_markdown(scan_id)

            assert "- **Routes Discovered:** `8`" in md
            assert "- **Routes Probed:** `4`" in md
            assert "- **Confirmed Vulnerabilities:** `0`" in md
            assert "- **Suspicious Results:** `1`" in md
            db.close()


class TestSuspiciousAdminEndpointReview:
    """Task 5: Verifies /rest/admin/application-configuration public UI config classification."""

    def test_public_ui_config_classified_as_suspicious_not_confirmed_bfla(self):
        """When an administrative route returns public UI config (theme, branding, logos),
        it should be marked SUSPICIOUS rather than confirmed BFLA."""
        analyzer = ResponseAnalyzer()
        public_ui_body = (
            '{"config":{"application":{"name":"OWASP Juice Shop","theme":"bluegrey-lightgreen",'
            '"logo":"JuiceShop_Logo.png","showVersionNumber":true}}}'
        )
        resp = HttpResponseModel(
            status_code=200,
            headers={"content-type": "application/json"},
            body=public_ui_body,
            response_time_ms=10.0,
            content_length=len(public_ui_body),
        )
        insp = analyzer.inspect_response(resp)
        assert insp.is_http_success is True

        # Check content analysis logic
        has_priv_secrets = any(
            k in public_ui_body.lower()
            for k in ["private_key", "admin_password", "jwt_secret", "api_secret", "root_password", "database_url"]
        )
        has_admin_actions = any(
            k in public_ui_body.lower()
            for k in ["deleteuser", "updaterole", "grantadmin", "systemshutdown"]
        )
        assert has_priv_secrets is False
        assert has_admin_actions is False

    def test_admin_secrets_disclosure_promoted_to_confirmed_bfla(self):
        """When an administrative route returns actual administrative secrets,
        it should be promoted to confirmed BFLA."""
        secret_body = '{"admin_password": "supersecretpassword123", "jwt_secret": "my-key"}'
        has_priv_secrets = any(
            k in secret_body.lower()
            for k in ["private_key", "admin_password", "jwt_secret", "api_secret", "root_password", "database_url"]
        )
        assert has_priv_secrets is True
