"""Unit tests for RetestEngine and FindingRepository persistence."""

import pytest
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord
from backend.analysis.severity_engine import SeverityLevel
from backend.retesting.retest_engine import RetestEngine


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

    def test_retest_engine_initialization(self, finding_repo: FindingRepository):
        """Ensures RetestEngine correctly reports retest execution."""
        engine = RetestEngine(repository=finding_repo)
        retest_result = engine.retest_finding("fnd_test_1")

        assert retest_result.finding_id == "fnd_test_1"
        assert retest_result.is_vulnerable is True

