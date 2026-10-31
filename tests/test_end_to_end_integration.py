"""End-to-End Integration and Cross-Module QA Test Suite for AuthScope.

Validates the full workflow integration across:
- Layer 1: Core Scope Guard & Session Manager
- Layer 2: Scanner (RequestExecutor, ResponseAnalyzer, AuthorizationTester, EvidenceValidator)
- Layer 3: AI Agent (FindingAnalyzer, SeverityEngine, RemediationEngine, AgentTools)
- Layer 4: Storage & Evidence Repository (SQLite DatabaseManager, FindingRepository)
- Layer 5: Retest Engine & Historical Verification

All network traffic is mocked or in-memory to guarantee boundary safety and zero external egress.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import SessionManager, Role
from backend.scanner.request_executor import RequestExecutor, HttpResponseModel
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.scanner.authorization_tester import DifferentialResult
from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.severity_engine import SeverityEngine, SeverityLevel
from backend.analysis.remediation import RemediationEngine
from backend.agent.tools import AgentTools
from backend.retesting.retest_engine import RetestEngine
from backend.storage.database import DatabaseManager, initialize_database
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord, EvidenceArtifact, RetestLogRecord
from backend.utils.helpers import (
    ScopeViolationError,
    DuplicateRecordError,
    InvalidDataError,
    RecordNotFoundError,
    StorageError,
)


@pytest.fixture
def test_db_path(tmp_path: Path) -> str:
    """Provides a fresh temporary file-backed SQLite database path."""
    return str(tmp_path / "e2e_authscope.db")


@pytest.fixture
def e2e_repo(test_db_path: str) -> FindingRepository:
    """Provides a FindingRepository backed by a temporary SQLite file."""
    mgr = DatabaseManager(db_path=test_db_path)
    return FindingRepository(db_manager=mgr)


@pytest.fixture
def strict_scope_guard() -> ScopeGuard:
    """Scope guard locked strictly to authorized local target http://localhost:3000."""
    return ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http", "https"]
    )


@pytest.mark.integration
class TestEndToEndIntegrationQA:
    """Cross-module end-to-end integration and security QA test suite."""

    # -------------------------------------------------------------------------
    # Scenario 1: Authorized target -> Scope Guard -> Scanner -> Finding -> SQLite
    # -------------------------------------------------------------------------
    def test_authorized_target_to_storage_flow(
        self, strict_scope_guard: ScopeGuard, e2e_repo: FindingRepository
    ):
        """Validates in-scope request execution, response analysis, evidence signing, and SQLite persistence."""
        target_url = "http://localhost:3000/rest/basket/1"

        # 1. Scope Guard validates target
        scope_result = strict_scope_guard.validate_url(target_url)
        assert scope_result.is_allowed is True
        assert scope_result.normalized_host == "localhost"
        assert scope_result.normalized_port == 3000

        # 2. Scanner executes request with ScopeGuard enforcement
        executor = RequestExecutor(scope_guard=strict_scope_guard)
        mock_auth_token = os.getenv("TEST_AUTH_TOKEN", "mock_session_token_xyz")
        req_headers = {"Authorization": f"Bearer {mock_auth_token}", "Accept": "application/json"}
        mock_response_body = '{"id": 1, "UserId": 2, "items": [{"id": 42, "product": "Juice"}]}'

        # Mock httpx response to avoid real network socket opening
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.text = mock_response_body
        mock_resp.json.return_value = json.loads(mock_response_body)

        with patch.object(executor.client, "request", return_value=mock_resp):
            http_response = executor.execute(method="GET", url=target_url, headers=req_headers)

        assert http_response.status_code == 200
        assert ResponseAnalyzer.is_success_response(http_response) is True

        # 3. EvidenceValidator generates cryptographic signed proof
        validator = EvidenceValidator()
        finding_id = "fnd_e2e_basket_idor"
        artifact = validator.create_and_sign_evidence(
            finding_id=finding_id,
            test_role=Role.USER_B,
            authorized_role=Role.USER_A,
            method="GET",
            url=target_url,
            headers=req_headers,
            response=http_response
        )

        assert artifact.finding_id == finding_id
        assert len(artifact.evidence_sha256) == 64
        # Proof that secrets are sanitized before persistence
        assert artifact.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"

        # 4. FindingRecord creation and persistence into SQLite
        finding = FindingRecord(
            id=finding_id,
            target_identifier="scan_e2e_01",
            endpoint="/rest/basket/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role=Role.USER_B.value,
            expected_behavior="403 Forbidden for User B accessing Basket 1",
            actual_behavior="200 OK with User A basket contents",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed",
            evidence=artifact
        )

        saved_id = e2e_repo.save_finding(finding)
        assert saved_id == finding_id

        # 5. Verification from SQLite database
        persisted = e2e_repo.get_finding(finding_id)
        assert persisted is not None
        assert persisted.endpoint == "/rest/basket/1"
        assert persisted.severity == SeverityLevel.HIGH
        assert persisted.evidence is not None
        assert persisted.evidence.evidence_sha256 == artifact.evidence_sha256
        assert persisted.evidence.response_status == 200

    # -------------------------------------------------------------------------
    # Scenario 2: Scanner response -> Evidence sanitization -> Evidence persistence
    # -------------------------------------------------------------------------
    def test_scanner_response_evidence_sanitization_and_persistence(
        self, e2e_repo: FindingRepository
    ):
        """Ensures all credentials, cookies, tokens, and sensitive body parameters are sanitized before disk storage."""
        mock_raw_secret = os.getenv("TEST_AUTH_TOKEN", "mock_sensitive_credential_987")
        raw_evidence = EvidenceArtifact(
            id="evi_sec_audit_01",
            finding_id="fnd_sec_audit_01",
            testing_role=Role.ANONYMOUS,
            request_method="POST",
            request_url=f"http://localhost:3000/api/users/login?token={mock_raw_secret}",
            request_headers={
                "Authorization": f"Bearer {mock_raw_secret}",
                "Proxy-Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
                "Cookie": f"session_id={mock_raw_secret}; tracking=active",
                "X-Api-Key": mock_raw_secret
            },
            request_metadata={
                "auth_token": mock_raw_secret,
                "debug_info": {"nested_key": mock_raw_secret}
            },
            response_status=200,
            relevant_response_headers={
                "Set-Cookie": f"jwt={mock_raw_secret}; Path=/; Secure"
            },
            sanitized_response_body=(
                f'{{"status": "success", "password": "supersecretplainpassword", '
                f'"secret_token": "{mock_raw_secret}", "card_number": "4111111111111111"}}'
            )
        )

        finding = FindingRecord(
            id="fnd_sec_audit_01",
            target_identifier="scan_01",
            endpoint="/api/users/login",
            http_method="POST",
            vulnerability_category="Missing_Authentication",
            affected_role="anonymous",
            expected_behavior="401 Unauthorized",
            actual_behavior="200 OK",
            evidence=raw_evidence
        )

        e2e_repo.save_finding(finding)

        # Inspect through Repository interface
        retrieved = e2e_repo.get_finding("fnd_sec_audit_01")
        assert retrieved is not None
        assert retrieved.evidence is not None

        evi = retrieved.evidence
        assert evi.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"
        assert evi.request_headers["Proxy-Authorization"] == "Basic [REDACTED_BASIC_AUTH]"
        assert evi.request_headers["Cookie"] == "[REDACTED_COOKIE]"
        assert evi.request_headers["X-Api-Key"] == "[REDACTED_API_KEY]"
        assert evi.relevant_response_headers["Set-Cookie"] == "[REDACTED_COOKIE]"

        # Request URL query parameter sanitized
        assert mock_raw_secret not in evi.request_url
        assert "[REDACTED" in evi.request_url

        # Body credentials sanitized
        assert "supersecretplainpassword" not in evi.sanitized_response_body
        assert mock_raw_secret not in evi.sanitized_response_body
        assert "[REDACTED_SECRET]" in evi.sanitized_response_body

        # Raw SQLite level verification: Direct SQL query confirms zero credentials in SQLite tables
        with e2e_repo.db.get_connection() as conn:
            cursor = conn.execute(
                "SELECT request_headers_json, relevant_response_headers_json, sanitized_response_body, request_url "
                "FROM evidence_artifacts WHERE id = 'evi_sec_audit_01'"
            )
            row = cursor.fetchone()
            assert row is not None
            db_headers, db_resp_headers, db_body, db_url = row

            assert mock_raw_secret not in db_headers
            assert mock_raw_secret not in db_resp_headers
            assert mock_raw_secret not in db_body
            assert mock_raw_secret not in db_url
            assert "supersecretplainpassword" not in db_body

    # -------------------------------------------------------------------------
    # Scenario 3: Stored finding -> AI Agent processing -> Updated finding
    # -------------------------------------------------------------------------
    def test_stored_finding_to_ai_agent_enrichment(self, e2e_repo: FindingRepository):
        """Simulates Member 2 AI Agent retrieving suspected finding, evaluating risk, and updating finding in-place."""
        # 1. Scanner stores suspected finding
        initial_finding = FindingRecord(
            id="fnd_ai_flow_01",
            target_identifier="scan_flow_01",
            endpoint="/api/v1/patient/records/55",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK with patient medical history",
            severity=SeverityLevel.MEDIUM,
            confirmation_status="suspected",
            impact_explanation="Initial discovery",
            remediation_recommendation="Pending analysis"
        )
        e2e_repo.save_finding(initial_finding)

        # 2. AI Agent queries suspected findings
        suspected_findings = e2e_repo.get_all_findings(status="suspected")
        assert len(suspected_findings) >= 1
        finding_to_enrich = next(f for f in suspected_findings if f.id == "fnd_ai_flow_01")

        # 3. AI Agent utilizes SeverityEngine and RemediationEngine to synthesize fix
        severity_calculator = SeverityEngine()
        calculated_severity = severity_calculator.calculate_severity(
            vulnerability_type=finding_to_enrich.vulnerability_category,
            exposes_pii=True
        )
        assert calculated_severity == SeverityLevel.HIGH

        patch_generator = RemediationEngine()
        suggested_patch = patch_generator.generate_patch(
            vulnerability_type=finding_to_enrich.vulnerability_category,
            framework="express"
        )
        assert "req.user.id !== requestedBasket.UserId" in suggested_patch or "Remediation" in suggested_patch

        # 4. AI Agent produces structured update payload
        ai_updates = {
            "severity": calculated_severity,
            "confirmation_status": "confirmed",
            "impact_explanation": "BOLA flaw allows unauthorized tenant to view sensitive Protected Health Information (PHI).",
            "remediation_recommendation": suggested_patch
        }

        # 5. Persist updates to SQLite
        updated_record = e2e_repo.update_finding(finding_to_enrich.id, ai_updates)
        assert updated_record.severity == SeverityLevel.HIGH
        assert updated_record.confirmation_status == "confirmed"
        assert "Protected Health Information" in updated_record.impact_explanation

        # 6. Verify original core properties are preserved in SQLite
        persisted = e2e_repo.get_finding("fnd_ai_flow_01")
        assert persisted is not None
        assert persisted.endpoint == "/api/v1/patient/records/55"
        assert persisted.http_method == "GET"
        assert persisted.affected_role == "user_b"
        assert persisted.severity == SeverityLevel.HIGH
        assert persisted.confirmation_status == "confirmed"

    # -------------------------------------------------------------------------
    # Scenario 4: Updated finding -> Retest -> Retest history
    # -------------------------------------------------------------------------
    def test_updated_finding_to_retest_and_history_lifecycle(self, e2e_repo: FindingRepository):
        """Simulates iterative retesting and status progression (confirmed -> vulnerable -> remediated)."""
        finding = FindingRecord(
            id="fnd_retest_life_01",
            target_identifier="scan_01",
            endpoint="/api/v1/invoices/301",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK invoice leaked",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed"
        )
        e2e_repo.save_finding(finding)

        # Baseline: Retest status is untested or None initially
        fnd_base = e2e_repo.get_finding("fnd_retest_life_01")
        assert fnd_base.retest_status in (None, "untested")
        assert fnd_base.last_retested_timestamp is None

        # Retest Iteration 1: Target still vulnerable
        retest_1 = RetestLogRecord(
            id="ret_life_01",
            finding_id="fnd_retest_life_01",
            previous_status="confirmed",
            new_status="confirmed",
            is_vulnerable=True,
            summary="Retest run 1 failed: Endpoint still returned 200 OK."
        )
        e2e_repo.save_retest_result(retest_1)

        fnd_after_r1 = e2e_repo.get_finding("fnd_retest_life_01")
        assert fnd_after_r1.retest_status == "confirmed"
        assert fnd_after_r1.status == "confirmed"
        assert fnd_after_r1.last_retested_timestamp is not None

        # Retest Iteration 2: Patch deployed, verification succeeds
        retest_2 = RetestLogRecord(
            id="ret_life_02",
            finding_id="fnd_retest_life_01",
            previous_status="confirmed",
            new_status="remediated",
            is_vulnerable=False,
            summary="Retest run 2 passed: Endpoint returned 403 Forbidden as expected."
        )
        e2e_repo.save_retest_result(retest_2)

        fnd_after_r2 = e2e_repo.get_finding("fnd_retest_life_01")
        assert fnd_after_r2.retest_status == "remediated"
        assert fnd_after_r2.status == "confirmed"

        # Verify historical log ordering and integrity
        history = e2e_repo.get_retest_history("fnd_retest_life_01")
        assert len(history) == 2
        # History is ordered by retested_at DESC
        assert history[0].id == "ret_life_02"
        assert history[0].is_vulnerable is False
        assert history[1].id == "ret_life_01"
        assert history[1].is_vulnerable is True

    # -------------------------------------------------------------------------
    # Scenario 5: Out-of-scope target -> Request blocked
    # -------------------------------------------------------------------------
    def test_out_of_scope_target_blocked_preventing_pipeline_execution(
        self, strict_scope_guard: ScopeGuard, e2e_repo: FindingRepository
    ):
        """Ensures ScopeGuard blocks out-of-scope egress, preventing any findings from being recorded."""
        executor = RequestExecutor(scope_guard=strict_scope_guard)
        out_of_scope_targets = [
            "https://external-bank.com/api/accounts",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/rest/admin",
            "ftp://localhost:3000/data",
            "http://evil.attacker.com:3000/payload"
        ]

        for target in out_of_scope_targets:
            # 1. Assert ScopeGuard rejects target
            scope_res = strict_scope_guard.validate_url(target)
            assert scope_res.is_allowed is False

            # 2. Assert RequestExecutor immediately halts with ScopeViolationError
            with pytest.raises(ScopeViolationError):
                executor.execute("GET", target)

        # 3. Assert zero findings or evidence were persisted for out-of-scope targets
        all_findings = e2e_repo.get_all_findings()
        assert len(all_findings) == 0

    # -------------------------------------------------------------------------
    # Scenario 6: Invalid scanner output -> Safe rejection
    # -------------------------------------------------------------------------
    def test_invalid_scanner_output_safe_rejection(self, e2e_repo: FindingRepository):
        """Verifies that invalid or malformed scanner outputs are rejected by Pydantic without corrupting SQLite."""
        # 1. Missing required endpoint
        invalid_item_1 = {
            "id": "fnd_bad_01",
            "http_method": "GET",
            "vulnerability_category": "BOLA_IDOR"
        }
        with pytest.raises(InvalidDataError):
            e2e_repo.save_finding(invalid_item_1)

        # 2. Invalid HTTP method verb
        invalid_item_2 = {
            "id": "fnd_bad_02",
            "endpoint": "/api/users",
            "http_method": "DROP_DATABASE",
            "vulnerability_category": "BOLA_IDOR"
        }
        with pytest.raises(InvalidDataError):
            e2e_repo.save_finding(invalid_item_2)

        # 3. Invalid severity string
        invalid_item_3 = {
            "id": "fnd_bad_03",
            "endpoint": "/api/users",
            "http_method": "GET",
            "severity": "NON_EXISTENT_SEVERITY"
        }
        with pytest.raises(InvalidDataError):
            e2e_repo.save_finding(invalid_item_3)

        # Confirm no corrupt records entered SQLite
        assert len(e2e_repo.get_all_findings()) == 0

    # -------------------------------------------------------------------------
    # Scenario 7: Database reopening -> Findings and evidence remain available
    # -------------------------------------------------------------------------
    def test_database_reopening_findings_and_evidence_available(self, test_db_path: str):
        """Verifies full roundtrip persistence across complete database connection closing and reopening."""
        # Session 1: Create manager and save finding + evidence
        mgr1 = DatabaseManager(db_path=test_db_path)
        repo1 = FindingRepository(db_manager=mgr1)

        evidence = EvidenceArtifact(
            id="evi_durability_01",
            finding_id="fnd_durability_01",
            testing_role=Role.USER_B,
            authorized_role=Role.USER_A,
            request_method="GET",
            request_url="http://localhost:3000/api/documents/10",
            response_status=200,
            sanitized_response_body='{"doc_id": 10, "content": "confidential contract"}'
        )
        finding = FindingRecord(
            id="fnd_durability_01",
            target_identifier="scan_durability",
            endpoint="/api/documents/10",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK",
            severity=SeverityLevel.HIGH,
            confirmation_status="confirmed",
            evidence=evidence
        )
        repo1.save_finding(finding)

        retest = RetestLogRecord(
            id="ret_durability_01",
            finding_id="fnd_durability_01",
            previous_status="confirmed",
            new_status="remediated",
            is_vulnerable=False,
            summary="Verified fix after ACL patch."
        )
        repo1.save_retest_result(retest)

        # Explicitly close session 1 connection
        mgr1.close()

        # Session 2: Fresh DatabaseManager and FindingRepository on same file
        mgr2 = DatabaseManager(db_path=test_db_path)
        repo2 = FindingRepository(db_manager=mgr2)

        persisted_finding = repo2.get_finding("fnd_durability_01")
        assert persisted_finding is not None
        assert persisted_finding.endpoint == "/api/documents/10"
        assert persisted_finding.retest_status == "remediated"
        assert persisted_finding.evidence is not None
        assert persisted_finding.evidence.id == "evi_durability_01"
        assert persisted_finding.evidence.evidence_sha256 is not None
        assert "confidential contract" in persisted_finding.evidence.sanitized_response_body

        history = repo2.get_retest_history("fnd_durability_01")
        assert len(history) == 1
        assert history[0].id == "ret_durability_01"
        assert history[0].is_vulnerable is False

        mgr2.close()

    # -------------------------------------------------------------------------
    # Scenario 8: Failed module execution -> No corrupted or partially committed records
    # -------------------------------------------------------------------------
    def test_failed_module_execution_transaction_atomicity(self, e2e_repo: FindingRepository):
        """Verifies that an error occurring during an atomic transaction causes complete rollback."""
        # 1. Baseline: Save a valid finding
        baseline_finding = FindingRecord(
            id="fnd_atom_01",
            target_identifier="scan_01",
            endpoint="/api/v1/healthy",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            expected_behavior="403 Forbidden",
            actual_behavior="200 OK"
        )
        e2e_repo.save_finding(baseline_finding)
        assert len(e2e_repo.get_all_findings()) == 1

        # 2. Attempt an atomic transaction block that encounters an unexpected failure
        with pytest.raises(RuntimeError):
            with e2e_repo.db.session_scope() as conn:
                conn.execute(
                    "INSERT INTO findings (id, target_identifier, scan_id, title, endpoint, target_endpoint, "
                    "http_method, vulnerability_category, vulnerability_type, affected_role, affected_roles_json, "
                    "expected_behavior, actual_behavior, confirmation_status, status, severity, "
                    "impact_explanation, description, remediation_recommendation, remediation_guidance, retest_status) "
                    "VALUES ('fnd_partial_corrupt', 'scan_01', 'scan_01', 'Partial Title', '/api/fail', '/api/fail', "
                    "'GET', 'BFLA', 'BFLA', 'user_b', '[\"user_b\"]', "
                    "'403', '200', 'confirmed', 'confirmed', 'HIGH', "
                    "'', '', '', '', 'untested')"
                )
                # Simulate critical crash before transaction commits
                raise RuntimeError("Simulated crash in middle of database operation")

        # 3. Assert partial record was rolled back cleanly and not persisted
        assert e2e_repo.get_finding("fnd_partial_corrupt") is None
        # Assert baseline finding remained intact and uncorrupted
        all_findings = e2e_repo.get_all_findings()
        assert len(all_findings) == 1
        assert all_findings[0].id == "fnd_atom_01"

    # -------------------------------------------------------------------------
    # Security & Reliability QA: Scope Boundary and Agent Confinement
    # -------------------------------------------------------------------------
    def test_ai_agent_cannot_expand_authorized_testing_scope(
        self, strict_scope_guard: ScopeGuard
    ):
        """Validates that AgentTools strictly enforces ScopeGuard boundaries and cannot bypass scope."""
        executor = RequestExecutor(scope_guard=strict_scope_guard)
        agent_tools = AgentTools(scope_guard=strict_scope_guard, executor=executor)

        # 1. Agent asks to check an in-scope URL
        in_scope_check = agent_tools.execute_tool("check_scope", {"url": "http://localhost:3000/rest/basket/1"})
        assert in_scope_check["is_allowed"] is True

        # 2. Agent asks to check an unauthorized external URL
        out_of_scope_check = agent_tools.execute_tool("check_scope", {"url": "https://evil-unauthorized.com/api"})
        assert out_of_scope_check["is_allowed"] is False
        assert "outside the authorized allowlist" in out_of_scope_check["reason"]

        # 3. Agent attempts to call executor directly with out-of-scope URL -> Hard block
        with pytest.raises(ScopeViolationError):
            executor.execute("GET", "https://evil-unauthorized.com/api")

    def test_redirect_suppression_prevents_scope_escape(
        self, strict_scope_guard: ScopeGuard
    ):
        """Verifies RequestExecutor suppresses automatic redirect following (preventing 302/301 scope escape)."""
        executor = RequestExecutor(scope_guard=strict_scope_guard)
        # follow_redirects MUST be False per AGENTS.md Section 4
        assert executor.client.follow_redirects is False
