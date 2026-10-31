"""Unit tests for RetestEngine and FindingRepository persistence."""

import pytest
from types import SimpleNamespace
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord
from backend.analysis.severity_engine import SeverityLevel
from backend.retesting.retest_engine import RetestEngine
from backend.core.session_manager import Role, SessionManager
from backend.core.scope_guard import ScopeGuard
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.models import EvidenceArtifact
from backend.utils.helpers import compute_sha256


def _signed_evidence(finding_id: str, url: str, resource_id: str | None = "1") -> EvidenceArtifact:
    body = "{}"
    digest = compute_sha256(f"GET|{url}|200|{body}")
    return EvidenceArtifact(
        finding_id=finding_id, endpoint="/rest/basket/1", http_method="GET",
        request_method="GET", request_url=url, test_role=Role.USER_B,
        authorized_role=Role.USER_A, resource_id=resource_id, response_status=200,
        response_body=body, sanitized_response_body=body, sanitized_response_evidence=body,
        actual_behavior="Signed original test response.", evidence_sha256=digest,
    )


@pytest.mark.unit
class TestRetestEngine:
    """Verifies finding storage, retrieval, and retesting workflow."""

    def test_finding_crud_in_memory(self, finding_repo: FindingRepository):
        """Verifies creating, persisting, and querying findings in SQLite."""
        finding = FindingRecord(
            id="fnd_test_1",
            scan_id="scn_test_1",
            title="Test IDOR Flaw",
            vulnerability_type="BOLA_IDOR",
            severity=SeverityLevel.HIGH,
            status="confirmed",
            target_endpoint="/rest/basket/1",
            http_method="GET",
            description="Differential test confirmed access discrepancy.",
            remediation_guidance="Verify ownership."
        )

        saved_id = finding_repo.save_finding(finding)
        assert saved_id == "fnd_test_1"

        all_findings = finding_repo.list_findings()
        assert len(all_findings) == 1
        assert all_findings[0].title == "Test IDOR Flaw"
        assert all_findings[0].severity == SeverityLevel.HIGH

    def test_missing_finding_is_not_tested(self, finding_repo: FindingRepository):
        """Missing original findings never produce a fabricated vulnerable result."""
        engine = RetestEngine(repository=finding_repo)
        retest_result = engine.retest_finding("fnd_test_1")

        assert retest_result.finding_id == "fnd_test_1"
        assert retest_result.new_status == "NOT_TESTED"
        assert retest_result.is_vulnerable is False

    def test_missing_original_evidence_is_inconclusive(self, finding_repo: FindingRepository, scope_guard, session_manager):
        finding = FindingRecord(
            id="fnd_no_evidence", scan_id="scan_no_evidence", title="No evidence",
            vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
            target_endpoint="/rest/basket/1", http_method="GET",
        )
        finding_repo.save_finding(finding)
        result = RetestEngine(repository=finding_repo, scope_guard=scope_guard, session_manager=session_manager).retest_finding(finding.id)
        assert result.new_status == "INCONCLUSIVE"
        assert "no retest request was sent" in result.summary

    def test_tampered_original_evidence_is_inconclusive(self, finding_repo: FindingRepository, scope_guard, session_manager):
        evidence = _signed_evidence("fnd_tampered", "http://localhost:3000/rest/basket/1")
        evidence.evidence_sha256 = "0" * 64
        finding = FindingRecord(
            id="fnd_tampered", scan_id="scan_tampered", title="Tampered evidence",
            vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
            target_endpoint="/rest/basket/1", http_method="GET", evidence=evidence,
        )
        finding_repo.save_finding(finding)
        fake_tester = SimpleNamespace(test_resource_access=lambda **kwargs: pytest.fail("tester must not run for tampered evidence"))
        result = RetestEngine(repository=finding_repo, tester=fake_tester, scope_guard=scope_guard, session_manager=session_manager).retest_finding(finding.id)
        assert result.new_status == "INCONCLUSIVE"
        assert "integrity validation" in result.summary

    def test_scope_violation_stops_before_tester(self, finding_repo: FindingRepository, session_manager):
        finding = FindingRecord(
            id="fnd_out_of_scope", scan_id="scan_scope", title="Out of scope",
            vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
            target_endpoint="/rest/basket/1", http_method="GET",
            evidence=_signed_evidence("fnd_out_of_scope", "http://example.com/rest/basket/1"),
        )
        finding_repo.save_finding(finding)
        fake_tester = SimpleNamespace(test_resource_access=lambda **kwargs: pytest.fail("network tester must not run"))
        guard = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_schemes=["http"], allowed_methods=["GET"])
        result = RetestEngine(repository=finding_repo, tester=fake_tester, scope_guard=guard, session_manager=session_manager).retest_finding(finding.id)
        assert result.new_status == "NOT_TESTED"

    def test_unavailable_test_sessions_are_not_tested(self, finding_repo: FindingRepository, scope_guard):
        finding = FindingRecord(
            id="fnd_no_sessions", scan_id="scan_sessions", title="Session missing",
            vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
            target_endpoint="/rest/basket/1", http_method="GET",
            evidence=_signed_evidence("fnd_no_sessions", "http://localhost:3000/rest/basket/1"),
        )
        finding_repo.save_finding(finding)
        empty_sessions = SessionManager(load_from_env=False)
        fake_tester = SimpleNamespace(test_resource_access=lambda **kwargs: pytest.fail("tester must not run without real sessions"))
        result = RetestEngine(repository=finding_repo, tester=fake_tester, scope_guard=scope_guard, session_manager=empty_sessions).retest_finding(finding.id)
        assert result.new_status == "NOT_TESTED"

    def test_verification_history_isolated_by_finding(self, finding_repo: FindingRepository):
        for finding_id in ("fnd_history_a", "fnd_history_b"):
            finding_repo.save_finding(FindingRecord(
                id=finding_id, scan_id=f"scan_{finding_id}", title="History isolation",
                vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
                target_endpoint="/rest/basket/1", http_method="GET",
            ))
            finding_repo.save_retest_result(RetestEngine._record(finding_id, "NOT_TESTED", "No session."))
        history_a = finding_repo.get_retest_history("fnd_history_a")
        assert len(history_a) == 1
        assert history_a[0].finding_id == "fnd_history_a"

    @pytest.mark.parametrize(
        ("test_verdict", "status"),
        [
            (AccessVerdict.CORRECTLY_DENIED, "FIXED"),
            (AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS, "STILL VULNERABLE"),
            (AccessVerdict.SUSPICIOUS_ACCESS, "INCONCLUSIVE"),
        ],
    )
    def test_engine_uses_differential_engine_result(
        self, finding_repo: FindingRepository, scope_guard, session_manager,
        test_verdict: AccessVerdict, status: str,
    ) -> None:
        finding = FindingRecord(
            id=f"fnd_{status.lower().replace(' ', '_')}", scan_id="scan_a",
            title="Verified authorization issue", vulnerability_type="BOLA_IDOR",
            severity=SeverityLevel.HIGH, status="confirmed", target_endpoint="/rest/basket/1",
            http_method="GET", description="Evidence-backed issue", remediation_guidance="Check owner.",
            evidence=_signed_evidence(f"fnd_{status.lower().replace(' ', '_')}", "http://localhost:3000/rest/basket/1"),
        )
        finding_repo.save_finding(finding)
        owner_probe = SimpleNamespace(verdict=AccessVerdict.ALLOWED_ACCESS, response=SimpleNamespace(status_code=200, body='{"id":1}'), evidence=None)
        test_probe = SimpleNamespace(verdict=test_verdict, response=SimpleNamespace(status_code=403 if test_verdict == AccessVerdict.CORRECTLY_DENIED else 200, body='{"id":1}'), evidence=None)
        diff = SimpleNamespace(
            probe_outcomes={Role.USER_A: owner_probe, Role.USER_B: test_probe},
            overall_verdict=test_verdict, is_confirmed=test_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS,
            resolved_url="http://localhost:3000/rest/basket/1", method="GET",
        )
        fake_tester = SimpleNamespace(
            scope_guard=scope_guard, session_manager=session_manager,
            test_resource_access=lambda **kwargs: diff,
        )
        result = RetestEngine(
            repository=finding_repo, tester=fake_tester, scope_guard=scope_guard,
            session_manager=session_manager,
        ).retest_finding(finding.id)
        assert result.new_status == status
        assert len(result.differential_result["before"]["evidence_sha256"]) == 64
        assert "after" in result.differential_result
        persisted = finding_repo.get_finding(finding.id)
        assert persisted is not None and persisted.status == "confirmed"

    def test_confirmed_related_route_regression_is_partially_fixed(
        self, finding_repo: FindingRepository, scope_guard, session_manager,
    ) -> None:
        finding = FindingRecord(
            id="fnd_partial", scan_id="scan_partial", title="Related route regression",
            vulnerability_type="BOLA_IDOR", severity=SeverityLevel.HIGH, status="confirmed",
            target_endpoint="/rest/basket/1", http_method="GET",
            evidence=_signed_evidence("fnd_partial", "http://localhost:3000/rest/basket/1"),
        )
        finding_repo.save_finding(finding)
        owner_probe = SimpleNamespace(verdict=AccessVerdict.ALLOWED_ACCESS, response=SimpleNamespace(status_code=200, body='{}'), evidence=None)
        test_probe = SimpleNamespace(verdict=AccessVerdict.CORRECTLY_DENIED, response=SimpleNamespace(status_code=403, body='{}'), evidence=None)
        diff = SimpleNamespace(
            probe_outcomes={Role.USER_A: owner_probe, Role.USER_B: test_probe},
            overall_verdict=AccessVerdict.CORRECTLY_DENIED, is_confirmed=False,
            resolved_url="http://localhost:3000/rest/basket/1", method="GET",
        )
        fake_tester = SimpleNamespace(
            scope_guard=scope_guard, session_manager=session_manager,
            test_resource_access=lambda **kwargs: diff,
        )
        engine = RetestEngine(repository=finding_repo, tester=fake_tester, scope_guard=scope_guard, session_manager=session_manager)
        engine._run_regression_checks = lambda *args: {
            "status": "COMPLETED", "checked": [{"endpoint": "/rest/basket/{id}/items", "status": "STILL VULNERABLE"}],
            "confirmed_vulnerable": True,
        }
        result = engine.retest_finding(finding.id)
        assert result.new_status == "PARTIALLY FIXED"
        assert result.differential_result["regression_checks"]["confirmed_vulnerable"] is True

