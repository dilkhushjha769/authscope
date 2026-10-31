"""Unit and integration tests for SQLite Storage, Finding Repository, and Evidence Management."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import pytest
from pydantic import ValidationError

from backend.storage.database import DatabaseManager, initialize_database
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    FindingRecord,
    EvidenceArtifact,
    RetestLogRecord,
    ScanSessionRecord,
    SeverityLevel,
    VulnerabilityType,
    FindingStatus,
    Role,
)
from backend.utils.helpers import (
    RecordNotFoundError,
    DuplicateRecordError,
    InvalidDataError,
    compute_sha256,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Provides a fresh temporary file-backed SQLite database path."""
    return str(tmp_path / "test_authscope.db")


@pytest.fixture
def repo(temp_db_path: str) -> FindingRepository:
    """Provides a FindingRepository backed by a temporary file database."""
    db_mgr = DatabaseManager(db_path=temp_db_path)
    return FindingRepository(db_manager=db_mgr)


@pytest.mark.unit
class TestStorageAndEvidence:
    """Test suite covering database lifecycle, finding repository, evidence sanitization, and QA."""

    def test_database_initialization(self, tmp_path: Path):
        """Verifies schema DDL execution, table creation, and foreign keys."""
        db_file = str(tmp_path / "init_check.db")
        db_manager = initialize_database(db_path=db_file)

        with db_manager.get_connection() as conn:
            # Verify foreign keys pragma is active
            fk_status = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
            assert fk_status == 1

            # Verify tables exist
            tables = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            ]
            assert "findings" in tables
            assert "evidence_artifacts" in tables
            assert "retest_logs" in tables
            assert "scan_sessions" in tables

            # Verify indexes exist
            indexes = [
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index';"
                ).fetchall()
            ]
            assert "idx_findings_scan_id" in indexes
            assert "idx_findings_target_id" in indexes
            assert "idx_findings_status" in indexes
            assert "idx_findings_severity" in indexes

        db_manager.close()

    def test_finding_insertion(self, repo: FindingRepository):
        """Verifies inserting findings both with and without attached evidence."""
        # 1. Finding without evidence
        fnd_no_evi = FindingRecord(
            id="fnd_simple_01",
            target_identifier="scan_01",
            endpoint="/rest/user/login",
            http_method="POST",
            vulnerability_category="BFLA",
            affected_role="anonymous",
            expected_behavior="Reject unauthorized administration login",
            actual_behavior="Allowed anonymous caller to retrieve admin session",
            severity=SeverityLevel.HIGH,
            impact_explanation="Unauthenticated administrative account takeover",
            remediation_recommendation="Enforce multi-factor auth and role verification",
        )
        saved_id1 = repo.save_finding(fnd_no_evi)
        assert saved_id1 == "fnd_simple_01"

        # 2. Finding with evidence artifact
        evidence = EvidenceArtifact(
            id="evi_basket_01",
            finding_id="fnd_idor_01",
            testing_role=Role.USER_B,
            authorized_role=Role.USER_A,
            request_method="GET",
            request_url="http://localhost:3000/rest/basket/1",
            request_headers={"Authorization": "Bearer victim_token_secret"},
            response_status=200,
            sanitized_response_body='{"status":"success","data":{"id":1,"items":["apple"]}}',
            evidence_validation_status="valid",
        )

        fnd_with_evi = FindingRecord(
            id="fnd_idor_01",
            target_identifier="scan_01",
            endpoint="/rest/basket/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="Return 403 Forbidden for User B accessing Basket 1",
            actual_behavior="Returned 200 OK with User A basket contents",
            severity=SeverityLevel.HIGH,
            impact_explanation="Horizontal data leak of shopping baskets",
            remediation_recommendation="Verify basket ownership against authenticated user session",
            evidence=evidence,
        )
        saved_id2 = repo.save_finding(fnd_with_evi)
        assert saved_id2 == "fnd_idor_01"

    def test_finding_retrieval(self, repo: FindingRepository):
        """Verifies single retrieval, all retrieval, and parameterized filtering."""
        evidence = EvidenceArtifact(
            id="evi_retrieval_01",
            finding_id="fnd_ret_01",
            testing_role="user_b",
            authorized_role="user_a",
            request_method="GET",
            request_url="http://localhost:3000/api/orders/42",
            response_status=200,
            sanitized_response_body='{"order": 42, "user": "alice"}',
        )

        finding1 = FindingRecord(
            id="fnd_ret_01",
            target_identifier="scan_orders",
            endpoint="/api/orders/42",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="Access denied",
            actual_behavior="Access granted",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed",
            impact_explanation="Order disclosure",
            remediation_recommendation="Check ownership",
            evidence=evidence,
        )

        finding2 = FindingRecord(
            id="fnd_ret_02",
            target_identifier="scan_orders",
            endpoint="/api/admin/roles",
            http_method="GET",
            vulnerability_category="BFLA",
            affected_role="user_a",
            expected_behavior="Admin only",
            actual_behavior="User A fetched roles",
            severity=SeverityLevel.CRITICAL,
            confirmation_status="suspected",
            impact_explanation="Privilege escalation",
            remediation_recommendation="Enforce admin middleware",
        )

        repo.save_finding(finding1)
        repo.save_finding(finding2)

        # Retrieve single finding
        fetched = repo.get_finding("fnd_ret_01")
        assert fetched is not None
        assert fetched.id == "fnd_ret_01"
        assert fetched.endpoint == "/api/orders/42"
        assert fetched.target_endpoint == "/api/orders/42"
        assert fetched.severity == SeverityLevel.HIGH
        assert fetched.evidence is not None
        assert fetched.evidence.id == "evi_retrieval_01"
        assert fetched.evidence.response_status == 200
        assert fetched.evidence.sanitized_response_body == '{"order": 42, "user": "alice"}'

        # Retrieve non-existent
        assert repo.get_finding("fnd_nonexistent") is None

        # Filter by severity
        crit_findings = repo.get_all_findings(severity=SeverityLevel.CRITICAL)
        assert len(crit_findings) == 1
        assert crit_findings[0].id == "fnd_ret_02"

        # Filter by status
        confirmed = repo.get_all_findings(status="confirmed")
        assert len(confirmed) == 1
        assert confirmed[0].id == "fnd_ret_01"

        # Filter by vulnerability category
        bfla = repo.get_all_findings(vulnerability_category="BFLA")
        assert len(bfla) == 1
        assert bfla[0].id == "fnd_ret_02"

        # Filter by target_identifier
        all_scan = repo.get_all_findings(target_identifier="scan_orders")
        assert len(all_scan) == 2

    def test_finding_updates(self, repo: FindingRepository):
        """Verifies partial updates to finding fields using parameterized SQL."""
        fnd = FindingRecord(
            id="fnd_update_01",
            target_identifier="scan_patch",
            endpoint="/api/v1/profile",
            http_method="PUT",
            vulnerability_category="MASS_ASSIGNMENT",
            affected_role="user_b",
            expected_behavior="Ignore role parameter",
            actual_behavior="Role changed to admin",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed",
            impact_explanation="Role tampering",
            remediation_recommendation="Whitelist allowed fields",
        )
        repo.save_finding(fnd)

        # Update finding to remediated
        updated = repo.update_finding("fnd_update_01", {
            "status": "remediated",
            "severity": SeverityLevel.LOW,
            "remediation_recommendation": "Field whitelist middleware applied.",
            "last_retested_timestamp": datetime.now(timezone.utc),
            "retest_status": "remediated",
        })

        assert updated.id == "fnd_update_01"
        assert updated.status == "remediated"
        assert updated.confirmation_status == "remediated"
        assert updated.severity == SeverityLevel.LOW
        assert updated.remediation_recommendation == "Field whitelist middleware applied."
        assert updated.retest_status == "remediated"
        assert updated.last_retested_timestamp is not None

        # Update non-existent finding raises RecordNotFoundError
        with pytest.raises(RecordNotFoundError):
            repo.update_finding("fnd_ghost", {"status": "remediated"})

    def test_duplicate_ids(self, repo: FindingRepository):
        """Ensures duplicate finding IDs are rejected unless overwrite is explicitly requested."""
        fnd = FindingRecord(
            id="fnd_unique_01",
            target_identifier="scan_01",
            endpoint="/api/profile",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="Ownership check",
            actual_behavior="Leaked profile",
            severity=SeverityLevel.HIGH,
            impact_explanation="Leak",
            remediation_recommendation="Fix",
        )
        repo.save_finding(fnd)

        # Attempting second insert with identical ID without overwrite must raise DuplicateRecordError
        duplicate_fnd = FindingRecord(
            id="fnd_unique_01",
            target_identifier="scan_02",
            endpoint="/api/other",
            http_method="POST",
            vulnerability_category="BFLA",
            affected_role="anonymous",
            expected_behavior="Auth check",
            actual_behavior="No auth",
            severity=SeverityLevel.CRITICAL,
            impact_explanation="Bypass",
            remediation_recommendation="Fix",
        )

        with pytest.raises(DuplicateRecordError) as exc_info:
            repo.save_finding(duplicate_fnd, overwrite=False)

        assert "already exists" in str(exc_info.value)

        # With overwrite=True, update succeeds
        saved_id = repo.save_finding(duplicate_fnd, overwrite=True)
        assert saved_id == "fnd_unique_01"
        overwritten = repo.get_finding("fnd_unique_01")
        assert overwritten.endpoint == "/api/other"
        assert overwritten.severity == SeverityLevel.CRITICAL

    def test_invalid_data(self, repo: FindingRepository):
        """Verifies that invalid parameters fail Pydantic or Storage validation."""
        # Missing or empty ID
        with pytest.raises(ValidationError):
            FindingRecord(
                id="",
                endpoint="/api/test",
                http_method="GET",
                severity=SeverityLevel.MEDIUM,
            )

        # Empty endpoint
        with pytest.raises(ValidationError):
            FindingRecord(
                id="fnd_inv_01",
                endpoint="",
                http_method="GET",
                severity=SeverityLevel.MEDIUM,
            )

        # Malformed HTTP method
        with pytest.raises(ValidationError):
            FindingRecord(
                id="fnd_inv_02",
                endpoint="/api/test",
                http_method="INVALID_METHOD",
                severity=SeverityLevel.MEDIUM,
            )

        # Invalid Severity
        with pytest.raises(ValidationError):
            FindingRecord(
                id="fnd_inv_03",
                endpoint="/api/test",
                http_method="GET",
                severity="SUPER_CRITICAL_INVALID",  # Not in SeverityLevel enum
            )

        # Invalid update payload
        with pytest.raises(InvalidDataError):
            repo.update_finding("fnd_any", "not_a_dict_or_record")

    def test_evidence_sanitization(self, repo: FindingRepository):
        """Verifies that Bearer tokens, cookies, passwords, and API keys are redacted."""
        raw_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MX0.secret_sig_xyz",
            "Cookie": "connect.sid=s%3A_secret_cookie_session_12345; Path=/",
            "X-Api-Key": "super_secret_admin_api_key_value",
            "Content-Type": "application/json",
        }
        raw_body = '{"user": "victim@example.com", "password": "SuperSecretPassword99!", "token": "sensitive_access_token_abc"}'

        evidence = EvidenceArtifact(
            id="evi_sanitize_test",
            finding_id="fnd_sanitized_01",
            testing_role=Role.USER_B,
            authorized_role=Role.USER_A,
            request_method="GET",
            request_url="http://localhost:3000/api/users/1",
            request_headers=raw_headers,
            response_status=200,
            sanitized_response_body=raw_body,
            evidence_validation_status="valid",
        )

        # Assert headers sanitized
        assert "eyJhbGci" not in evidence.request_headers["Authorization"]
        assert evidence.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"
        assert evidence.request_headers["Cookie"] == "[REDACTED_COOKIE]"
        assert evidence.request_headers["X-Api-Key"] == "[REDACTED_API_KEY]"
        assert evidence.request_headers["Content-Type"] == "application/json"

        # Assert body sanitized
        assert "SuperSecretPassword99!" not in evidence.sanitized_response_body
        assert "[REDACTED_SECRET]" in evidence.sanitized_response_body

        # Assert SHA-256 computed
        assert len(evidence.evidence_sha256) == 64

        # Save finding to SQLite and verify database contents are sanitized
        finding = FindingRecord(
            id="fnd_sanitized_01",
            target_identifier="scan_sec_01",
            endpoint="/api/users/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="No access to password",
            actual_behavior="Leaked password SuperSecretPassword99!",
            severity=SeverityLevel.HIGH,
            impact_explanation="Credential disclosure",
            remediation_recommendation="Exclude password from JSON response",
            evidence=evidence,
        )

        repo.save_finding(finding)

        # Inspect raw database rows directly via SQL query
        with repo.db.get_connection() as conn:
            row = conn.execute(
                "SELECT sanitized_response_body, request_headers_json FROM evidence_artifacts WHERE finding_id = ?",
                ("fnd_sanitized_01",)
            ).fetchone()

            assert "SuperSecretPassword99!" not in row["sanitized_response_body"]
            assert "super_secret_admin_api_key_value" not in row["request_headers_json"]
            assert "secret_sig_xyz" not in row["request_headers_json"]

            fnd_row = conn.execute(
                "SELECT actual_behavior FROM findings WHERE id = ?",
                ("fnd_sanitized_01",)
            ).fetchone()
            # Finding actual behavior should not store raw password
            assert "SuperSecretPassword99!" not in fnd_row["actual_behavior"]

    def test_retest_history(self, repo: FindingRepository):
        """Verifies saving retests, finding status progression, and retest log history."""
        finding = FindingRecord(
            id="fnd_retest_test",
            target_identifier="scan_01",
            endpoint="/api/basket/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="Ownership enforcement",
            actual_behavior="Discrepancy confirmed",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed",
            impact_explanation="IDOR",
            remediation_recommendation="Fix",
        )
        repo.save_finding(finding)

        # First retest: Still vulnerable
        retest_1 = RetestLogRecord(
            id="ret_001",
            finding_id="fnd_retest_test",
            previous_status="confirmed",
            new_status="confirmed",
            is_vulnerable=True,
            summary="Vulnerability persists on re-probe (200 OK)",
            notes="User B still accessed User A basket.",
        )
        repo.save_retest_result(retest_1)

        f_after_1 = repo.get_finding("fnd_retest_test")
        assert f_after_1.retest_status == "vulnerable"
        assert f_after_1.status == "confirmed"
        assert f_after_1.last_retested_timestamp is not None

        # Second retest: Remediated
        retest_2 = RetestLogRecord(
            id="ret_002",
            finding_id="fnd_retest_test",
            previous_status="confirmed",
            new_status="remediated",
            is_vulnerable=False,
            summary="Target returned 403 Forbidden on differential probe",
            notes="Remediation patch verified.",
        )
        repo.save_retest_result(retest_2)

        f_after_2 = repo.get_finding("fnd_retest_test")
        assert f_after_2.retest_status == "remediated"
        assert f_after_2.status == "remediated"
        assert f_after_2.confirmation_status == "remediated"

        # Check retest history retrieval
        history = repo.get_retest_history("fnd_retest_test")
        assert len(history) == 2
        # Most recent first
        assert history[0].id == "ret_002"
        assert history[0].is_vulnerable is False
        assert history[1].id == "ret_001"
        assert history[1].is_vulnerable is True

    def test_persistence_after_reopening_database(self, tmp_path: Path):
        """Verifies database persistence across process/connection restarts."""
        db_file = str(tmp_path / "persistence_check.db")

        # 1. Open and insert records
        mgr1 = DatabaseManager(db_path=db_file)
        repo1 = FindingRepository(db_manager=mgr1)

        evidence = EvidenceArtifact(
            id="evi_persist_01",
            finding_id="fnd_persist_01",
            testing_role=Role.USER_B,
            authorized_role=Role.USER_A,
            request_method="GET",
            request_url="http://localhost:3000/api/feedback/1",
            response_status=200,
            sanitized_response_body='{"feedback": "sensitive message"}',
        )

        finding = FindingRecord(
            id="fnd_persist_01",
            target_identifier="scan_persist",
            endpoint="/api/feedback/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK with message",
            severity=SeverityLevel.MEDIUM,
            confirmation_status="confirmed",
            impact_explanation="Feedback leakage",
            remediation_recommendation="Check ownership",
            evidence=evidence,
        )

        repo1.save_finding(finding)

        retest = RetestLogRecord(
            id="ret_persist_01",
            finding_id="fnd_persist_01",
            previous_status="confirmed",
            new_status="confirmed",
            is_vulnerable=True,
            summary="Initial baseline check",
        )
        repo1.save_retest_result(retest)

        # Close first connection
        mgr1.close()

        # 2. Re-open database with completely new DatabaseManager and Repository
        mgr2 = DatabaseManager(db_path=db_file)
        repo2 = FindingRepository(db_manager=mgr2)

        persisted_fnd = repo2.get_finding("fnd_persist_01")
        assert persisted_fnd is not None
        assert persisted_fnd.endpoint == "/api/feedback/1"
        assert persisted_fnd.severity == SeverityLevel.MEDIUM
        assert persisted_fnd.evidence is not None
        assert persisted_fnd.evidence.id == "evi_persist_01"
        assert persisted_fnd.evidence.sanitized_response_body == '{"feedback": "sensitive message"}'
        assert persisted_fnd.retest_status == "vulnerable"

        persisted_history = repo2.get_retest_history("fnd_persist_01")
        assert len(persisted_history) == 1
        assert persisted_history[0].id == "ret_persist_01"

        mgr2.close()

    def test_sample_findings_file_compatibility(self, repo: FindingRepository):
        """Ensures the delivery sample_findings.json can be loaded and persisted cleanly."""
        import json
        sample_path = Path(__file__).parent.parent / "data" / "sample_findings.json"
        assert sample_path.exists(), "data/sample_findings.json must exist"

        with open(sample_path, "r", encoding="utf-8") as f:
            raw_samples = json.load(f)

        assert len(raw_samples) >= 4

        for item in raw_samples:
            finding = FindingRecord(**item)
            saved_id = repo.save_finding(finding)
            assert saved_id == finding.id

            fetched = repo.get_finding(saved_id)
            assert fetched is not None
            assert fetched.endpoint == finding.endpoint
            assert fetched.severity == finding.severity
            if finding.evidence:
                assert fetched.evidence is not None
                assert fetched.evidence.evidence_sha256 == finding.evidence.evidence_sha256

