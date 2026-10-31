"""Tests for backend/analysis/explanation_engine.py — Phase 5.3.

Coverage targets (from spec):
- test_simple_explanation_bola_idor
- test_simple_explanation_bfla
- test_technical_explanation_conversion
- test_confirmed_finding_explanation
- test_suspicious_finding_explanation
- test_unverified_finding_explanation
- test_correctly_denied_explanation
- test_missing_evidence_handling
- test_missing_source_location
- test_code_example_is_illustrative_flagged
- test_secret_redaction_in_evidence
- test_no_confirmation_without_evidence
- test_evidence_fields_preserved
- test_all_vulnerability_types_covered
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest

from backend.analysis.explanation_engine import (
    ExplanationConfidenceLevel,
    ExplanationEngine,
    ExplanationEngineError,
    ExplanationValidationStatus,
)
from backend.storage.models import (
    EvidenceArtifact,
    EvidenceValidationStatus,
    FindingRecord,
    VulnerabilityType,
)


# ==============================================================================
# Fixtures
# ==============================================================================


def _make_evidence(
    finding_id: str,
    response_status: int = 200,
    sanitized_response_evidence: str = '{"id": 1, "data": "private"}',
    validation_status: EvidenceValidationStatus = EvidenceValidationStatus.CONFIRMED,
    request_headers: Optional[dict] = None,
) -> EvidenceArtifact:
    """Build a minimal EvidenceArtifact suitable for tests."""
    return EvidenceArtifact(
        id=f"evi_{uuid.uuid4().hex[:8]}",
        finding_id=finding_id,
        endpoint="/api/test/resource/1",
        http_method="GET",
        testing_role="user_b",
        authorized_role="user_a",
        resource_id="1",
        expected_behavior="Role 'user_b' should be denied (HTTP 403).",
        actual_behavior=f"Role 'user_b' received HTTP {response_status} with private data.",
        validation_status=validation_status,
        request_method="GET",
        request_url="http://localhost:3000/api/test/resource/1",
        request_headers=request_headers or {"Accept": "application/json"},
        response_status=response_status,
        sanitized_response_body=sanitized_response_evidence,
        sanitized_response_evidence=sanitized_response_evidence,
        evidence_validation_status="valid",
    )


def _make_finding(
    vuln_type: str = "BOLA_IDOR",
    confirmation_status: str = "confirmed",
    validation_status: str = "CONFIRMED",
    severity: str = "HIGH",
    evidence: Optional[EvidenceArtifact] = None,
    endpoint: str = "/api/basket/1",
    http_method: str = "GET",
    title: str = "",
) -> FindingRecord:
    """Build a minimal FindingRecord for tests."""
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    return FindingRecord(
        id=finding_id,
        endpoint=endpoint,
        http_method=http_method,
        vulnerability_type=vuln_type,
        vulnerability_category=vuln_type,
        confirmation_status=confirmation_status,
        status=confirmation_status,
        validation_status=validation_status,
        severity=severity,
        title=title,
        impact_explanation="Unauthorized access to private basket data.",
        remediation_recommendation="Enforce ownership check on every basket endpoint.",
        expected_behavior="Role user_b should be denied access.",
        actual_behavior="Role user_b received HTTP 200 with basket contents.",
        evidence=evidence,
    )


@pytest.fixture
def engine() -> ExplanationEngine:
    """Provides a clean ExplanationEngine instance."""
    return ExplanationEngine()


@pytest.fixture
def confirmed_evidence() -> EvidenceArtifact:
    """Evidence artifact with a 2xx status and non-empty body — qualifies for CONFIRMED."""
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    return _make_evidence(
        finding_id=finding_id,
        response_status=200,
        sanitized_response_evidence='{"id": 1, "UserId": 42, "items": []}',
        validation_status=EvidenceValidationStatus.CONFIRMED,
    )


@pytest.fixture
def bola_confirmed_finding(confirmed_evidence: EvidenceArtifact) -> FindingRecord:
    """BOLA_IDOR finding with confirmed, complete evidence."""
    return _make_finding(
        vuln_type="BOLA_IDOR",
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        severity="HIGH",
        evidence=confirmed_evidence,
        endpoint="/api/basket/1",
        http_method="GET",
    )


@pytest.fixture
def bfla_confirmed_finding(confirmed_evidence: EvidenceArtifact) -> FindingRecord:
    """BFLA finding with confirmed evidence."""
    return _make_finding(
        vuln_type="BFLA",
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        severity="CRITICAL",
        evidence=confirmed_evidence,
        endpoint="/api/admin/users",
        http_method="GET",
    )


# ==============================================================================
# 1. Simple explanation — BOLA_IDOR
# ==============================================================================


def test_simple_explanation_bola_idor(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """Simple explanation for a BOLA/IDOR finding must contain beginner-readable text."""
    report = engine.generate_explanation(bola_confirmed_finding)

    simple = report.simple_explanation
    assert simple.what_happened, "what_happened must not be empty"
    assert simple.why_is_this_a_problem, "why_is_this_a_problem must not be empty"
    assert simple.what_could_an_attacker_do, "what_could_an_attacker_do must not be empty"
    assert simple.how_can_a_developer_fix_it, "how_can_a_developer_fix_it must not be empty"

    # Must contain BOLA-specific language
    combined = " ".join([
        simple.what_happened,
        simple.why_is_this_a_problem,
        simple.what_could_an_attacker_do,
    ]).upper()
    assert "BOLA" in combined or "IDOR" in combined, (
        "BOLA explanation should mention BOLA or IDOR"
    )

    # Glossary must define key terms for beginners
    assert len(simple.glossary) > 0, "BOLA explanation must include a glossary"
    assert "BOLA" in simple.glossary or "IDOR" in simple.glossary, (
        "Glossary must define BOLA or IDOR"
    )


# ==============================================================================
# 2. Simple explanation — BFLA
# ==============================================================================


def test_simple_explanation_bfla(
    engine: ExplanationEngine, bfla_confirmed_finding: FindingRecord
) -> None:
    """Simple explanation for a BFLA finding must reference function-level authorization."""
    report = engine.generate_explanation(bfla_confirmed_finding)

    simple = report.simple_explanation
    combined = " ".join([simple.what_happened, simple.why_is_this_a_problem]).upper()
    assert "BFLA" in combined or "ADMIN" in combined or "FUNCTION" in combined, (
        "BFLA explanation should mention BFLA, admin, or function-level"
    )
    assert simple.glossary, "BFLA explanation must include a glossary"


# ==============================================================================
# 3. Technical explanation conversion
# ==============================================================================


def test_technical_explanation_conversion(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """Technical explanation must be present alongside simple explanation."""
    report = engine.generate_explanation(bola_confirmed_finding)

    tech = report.technical_explanation
    assert tech.vulnerability_class, "vulnerability_class must not be empty"
    assert tech.what_happened, "technical what_happened must not be empty"
    assert tech.root_cause, "root_cause must not be empty"
    assert tech.attacker_impact, "attacker_impact must not be empty"
    assert tech.remediation_guidance, "remediation_guidance must not be empty"
    assert "CWE" in tech.cwe_reference, "CWE reference should contain 'CWE'"
    assert "OWASP" in tech.owasp_reference.upper(), "OWASP reference should contain 'OWASP'"

    # Simple explanation must ALSO be present
    assert report.simple_explanation.what_happened, "simple explanation must also be present"


# ==============================================================================
# 4. Confirmed finding
# ==============================================================================


def test_confirmed_finding_explanation(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """A CONFIRMED finding with valid 2xx evidence must produce CONFIRMED validation status."""
    report = engine.generate_explanation(bola_confirmed_finding)

    assert report.validation_status == ExplanationValidationStatus.CONFIRMED, (
        "CONFIRMED finding with valid evidence must produce CONFIRMED validation_status"
    )
    assert report.confidence == ExplanationConfidenceLevel.HIGH, (
        "CONFIRMED finding must have HIGH confidence"
    )


# ==============================================================================
# 5. Suspicious finding
# ==============================================================================


def test_suspicious_finding_explanation(engine: ExplanationEngine) -> None:
    """A SUSPICIOUS finding must NOT be promoted to CONFIRMED in the explanation."""
    finding = _make_finding(
        vuln_type="BOLA_IDOR",
        confirmation_status="suspected",
        validation_status="SUSPICIOUS",
        severity="MEDIUM",
        evidence=None,  # no evidence
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status != ExplanationValidationStatus.CONFIRMED, (
        "A SUSPICIOUS finding without valid evidence must NOT produce CONFIRMED status"
    )
    assert report.validation_status == ExplanationValidationStatus.SUSPICIOUS, (
        "A SUSPICIOUS finding must produce SUSPICIOUS validation status"
    )


# ==============================================================================
# 6. Unverified finding
# ==============================================================================


def test_unverified_finding_explanation(engine: ExplanationEngine) -> None:
    """An UNVERIFIED finding must produce UNVERIFIED validation status."""
    finding = _make_finding(
        vuln_type="MISSING_AUTH",
        confirmation_status="suspected",
        validation_status="UNVALIDATED",
        severity="LOW",
        evidence=None,
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status == ExplanationValidationStatus.UNVERIFIED, (
        "An UNVALIDATED finding without evidence must produce UNVERIFIED status"
    )
    assert report.confidence == ExplanationConfidenceLevel.LOW, (
        "Unverified finding must have LOW confidence"
    )


# ==============================================================================
# 7. Correctly denied
# ==============================================================================


def test_correctly_denied_explanation(engine: ExplanationEngine) -> None:
    """A FALSE_POSITIVE / remediated finding must produce CORRECTLY_DENIED status."""
    finding = _make_finding(
        vuln_type="BOLA_IDOR",
        confirmation_status="false_positive",
        validation_status="CONFIRMED",
        severity="MEDIUM",
        evidence=None,
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status == ExplanationValidationStatus.CORRECTLY_DENIED, (
        "false_positive finding must produce CORRECTLY_DENIED status"
    )


def test_remediated_produces_correctly_denied(engine: ExplanationEngine) -> None:
    """A remediated finding must also produce CORRECTLY_DENIED status."""
    finding = _make_finding(
        confirmation_status="remediated",
        validation_status="CONFIRMED",
    )
    report = engine.generate_explanation(finding)
    assert report.validation_status == ExplanationValidationStatus.CORRECTLY_DENIED


# ==============================================================================
# 8. Missing evidence handling
# ==============================================================================


def test_missing_evidence_handling(engine: ExplanationEngine) -> None:
    """A finding with no evidence must not crash; evidence_summary must be None."""
    finding = _make_finding(
        vuln_type="BOLA_IDOR",
        confirmation_status="suspected",
        validation_status="SUSPICIOUS",
        evidence=None,
    )
    report = engine.generate_explanation(finding)

    assert report is not None, "Report must be generated even without evidence"
    assert report.evidence_summary is None, (
        "evidence_summary must be None when finding has no evidence"
    )
    # Explanations should still be present
    assert report.simple_explanation.what_happened
    assert report.technical_explanation.what_happened


# ==============================================================================
# 9. Missing source location (no title, no technical_details)
# ==============================================================================


def test_missing_source_location(engine: ExplanationEngine) -> None:
    """A finding with no title or technical_details must not crash."""
    finding = _make_finding(
        vuln_type="PRIVILEGE_ESCALATION",
        title="",  # empty title — engine should generate one
    )
    report = engine.generate_explanation(finding)

    assert report.vulnerability_name, (
        "vulnerability_name must be auto-generated when title is absent"
    )
    assert "PRIVILEGE" in report.vulnerability_name.upper() or finding.endpoint in report.vulnerability_name, (
        "Auto-generated title should reference vulnerability type or endpoint"
    )


# ==============================================================================
# 10. Code example is_illustrative flag
# ==============================================================================


def test_code_example_is_illustrative_flagged(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """code_example.is_illustrative must always be True."""
    report = engine.generate_explanation(bola_confirmed_finding)

    assert report.code_example is not None, "BOLA finding must have a code example"
    assert report.code_example.is_illustrative is True, (
        "code_example.is_illustrative must always be True — these are educational examples"
    )
    assert "ILLUSTRATIVE" in report.code_example.vulnerable_code.upper(), (
        "Vulnerable code must contain the ILLUSTRATIVE disclaimer"
    )
    assert "ILLUSTRATIVE" in report.code_example.corrected_code.upper(), (
        "Corrected code must contain the ILLUSTRATIVE disclaimer"
    )


def test_all_vulnerability_types_have_illustrative_code_examples(
    engine: ExplanationEngine,
) -> None:
    """Every supported VulnerabilityType must produce a code example with is_illustrative=True."""
    for vuln_type in VulnerabilityType:
        finding = _make_finding(
            vuln_type=vuln_type.value,
            confirmation_status="suspected",
            validation_status="SUSPICIOUS",
        )
        report = engine.generate_explanation(finding)
        if report.code_example is not None:
            assert report.code_example.is_illustrative is True, (
                f"code_example.is_illustrative must be True for {vuln_type.value}"
            )


# ==============================================================================
# 11. Secret redaction in evidence
# ==============================================================================


def test_secret_redaction_in_evidence(engine: ExplanationEngine) -> None:
    """JWTs and Bearer tokens embedded in evidence must NOT appear in the report."""
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    raw_bearer = f"Bearer {raw_jwt}"

    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    evidence = _make_evidence(
        finding_id=finding_id,
        response_status=200,
        sanitized_response_evidence=f'{{"token": "{raw_jwt}", "user": "alice"}}',
        request_headers={"Authorization": raw_bearer},
    )
    finding = _make_finding(evidence=evidence)
    report = engine.generate_explanation(finding)

    # Check evidence_summary excerpt
    if report.evidence_summary:
        assert raw_jwt not in report.evidence_summary.sanitized_response_excerpt, (
            "Raw JWT must be redacted from evidence_summary.sanitized_response_excerpt"
        )
        assert raw_bearer not in (report.evidence_summary.sanitized_response_excerpt or ""), (
            "Bearer token must be redacted from evidence_summary"
        )


def test_bearer_token_redacted_from_evidence_headers(engine: ExplanationEngine) -> None:
    """Authorization Bearer token in evidence headers must NOT appear in the report."""
    raw_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyX2IifQ.signature"
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    evidence = _make_evidence(
        finding_id=finding_id,
        response_status=200,
        sanitized_response_evidence="{}",
        request_headers={"Authorization": f"Bearer {raw_token}"},
    )
    finding = _make_finding(evidence=evidence)
    report = engine.generate_explanation(finding)

    # The report itself should not contain the raw token anywhere in JSON form
    report_json = report.model_dump_json()
    assert raw_token not in report_json, (
        "Raw Bearer token must not appear anywhere in the serialised ExplanationReport"
    )


# ==============================================================================
# 12. No confirmation without valid evidence
# ==============================================================================


def test_no_confirmation_without_evidence(engine: ExplanationEngine) -> None:
    """A CONFIRMED finding without any evidence must NOT produce CONFIRMED status."""
    finding = _make_finding(
        vuln_type="BOLA_IDOR",
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        evidence=None,  # ← No evidence
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status != ExplanationValidationStatus.CONFIRMED, (
        "CONFIRMED finding without evidence must NOT produce CONFIRMED validation_status "
        "in the explanation"
    )


def test_no_confirmation_with_4xx_evidence(engine: ExplanationEngine) -> None:
    """A finding backed only by a 4xx response must NOT produce CONFIRMED status."""
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    bad_evidence = _make_evidence(
        finding_id=finding_id,
        response_status=403,  # Denied — not a bypass
        sanitized_response_evidence='{"error": "Access Denied"}',
        validation_status=EvidenceValidationStatus.CONFIRMED,
    )
    finding = _make_finding(
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        evidence=bad_evidence,
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status != ExplanationValidationStatus.CONFIRMED, (
        "A finding backed by a 4xx response must NOT be CONFIRMED in the explanation"
    )


def test_no_confirmation_with_empty_evidence_body(engine: ExplanationEngine) -> None:
    """A finding with 2xx but empty evidence body must NOT produce CONFIRMED status."""
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    empty_evidence = _make_evidence(
        finding_id=finding_id,
        response_status=200,
        sanitized_response_evidence="",  # empty — not sufficient
        validation_status=EvidenceValidationStatus.CONFIRMED,
    )
    finding = _make_finding(
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        evidence=empty_evidence,
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status != ExplanationValidationStatus.CONFIRMED, (
        "A finding with empty sanitized_response_evidence must NOT be CONFIRMED"
    )


# ==============================================================================
# 13. Evidence fields preserved
# ==============================================================================


def test_evidence_fields_preserved(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """All required evidence fields must be preserved in evidence_summary."""
    report = engine.generate_explanation(bola_confirmed_finding)
    ev = report.evidence_summary

    assert ev is not None, "evidence_summary must be present when evidence exists"
    assert ev.endpoint, "endpoint must be preserved"
    assert ev.http_method, "http_method must be preserved"
    assert ev.testing_role, "testing_role must be preserved"
    assert ev.expected_behavior, "expected_behavior must be preserved"
    assert ev.actual_behavior, "actual_behavior must be preserved"
    assert ev.response_status > 0, "response_status must be preserved"
    assert ev.evidence_sha256, "evidence_sha256 must be preserved"
    assert ev.timestamp, "timestamp must be preserved"


def test_evidence_resource_id_preserved(engine: ExplanationEngine) -> None:
    """resource_id from evidence must be preserved in evidence_summary."""
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    evidence = _make_evidence(finding_id=finding_id, response_status=200)
    finding = _make_finding(evidence=evidence)
    report = engine.generate_explanation(finding)

    assert report.evidence_summary is not None
    assert report.evidence_summary.resource_id == "1", (
        "resource_id '1' must be preserved from evidence to evidence_summary"
    )


# ==============================================================================
# 14. All vulnerability types covered
# ==============================================================================


def test_all_vulnerability_types_covered(engine: ExplanationEngine) -> None:
    """Every VulnerabilityType value must produce a valid ExplanationReport without errors."""
    for vuln_type in VulnerabilityType:
        finding = _make_finding(
            vuln_type=vuln_type.value,
            confirmation_status="suspected",
            validation_status="SUSPICIOUS",
        )
        report = engine.generate_explanation(finding)

        assert report is not None, f"Report must be generated for {vuln_type.value}"
        assert report.vulnerability_name, f"vulnerability_name must not be empty for {vuln_type.value}"
        assert report.simple_explanation.what_happened, (
            f"simple what_happened must not be empty for {vuln_type.value}"
        )
        assert report.technical_explanation.vulnerability_class, (
            f"technical vulnerability_class must not be empty for {vuln_type.value}"
        )
        assert report.where_was_it_found, f"where_was_it_found must not be empty for {vuln_type.value}"
        # Disclaimer must always be present
        assert "illustrative" in report.disclaimer.lower(), (
            f"disclaimer must mention illustrative for {vuln_type.value}"
        )


# ==============================================================================
# Additional edge-case tests
# ==============================================================================


def test_report_generated_at_is_utc_iso(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """generated_at must be a valid UTC ISO-8601 timestamp."""
    report = engine.generate_explanation(bola_confirmed_finding)
    # Must parse without error
    parsed = datetime.fromisoformat(report.generated_at.replace("Z", "+00:00"))
    assert parsed is not None


def test_where_was_it_found_contains_method_and_endpoint(
    engine: ExplanationEngine,
) -> None:
    """where_was_it_found must include both HTTP method and endpoint."""
    finding = _make_finding(
        endpoint="/api/users/42",
        http_method="GET",
    )
    report = engine.generate_explanation(finding)
    assert "GET" in report.where_was_it_found.upper()
    assert "/api/users/42" in report.where_was_it_found


def test_explanation_engine_error_on_empty_endpoint(engine: ExplanationEngine) -> None:
    """ExplanationEngine must raise ExplanationEngineError when endpoint is empty."""
    # Force the endpoint to empty after construction to bypass FindingRecord validation
    finding = _make_finding()
    finding.endpoint = ""  # Directly mutate to simulate a post-construction corruption
    with pytest.raises(ExplanationEngineError):
        engine.generate_explanation(finding)


def test_disclaimer_always_present(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """Disclaimer must always be present in the report."""
    report = engine.generate_explanation(bola_confirmed_finding)
    assert report.disclaimer
    assert "illustrative" in report.disclaimer.lower()


def test_report_is_serialisable(
    engine: ExplanationEngine, bola_confirmed_finding: FindingRecord
) -> None:
    """ExplanationReport must be fully serialisable to JSON via Pydantic."""
    report = engine.generate_explanation(bola_confirmed_finding)
    json_str = report.model_dump_json()
    assert json_str
    # Round-trip through dict
    data = report.model_dump()
    assert isinstance(data, dict)
    assert "vulnerability_name" in data
    assert "simple_explanation" in data
    assert "technical_explanation" in data


def test_suspicious_finding_never_upgraded_to_confirmed(engine: ExplanationEngine) -> None:
    """A SUSPICIOUS finding with 2xx evidence must remain SUSPICIOUS, not CONFIRMED.

    This is a critical safety check: AI/engine cannot independently confirm a
    finding that is marked SUSPICIOUS by the scanner.
    """
    finding_id = f"find_{uuid.uuid4().hex[:8]}"
    # Evidence looks good (2xx, non-empty) but finding is explicitly SUSPICIOUS
    evidence = _make_evidence(
        finding_id=finding_id,
        response_status=200,
        sanitized_response_evidence='{"data": "present"}',
        validation_status=EvidenceValidationStatus.SUSPICIOUS,
    )
    finding = _make_finding(
        confirmation_status="suspected",
        validation_status="SUSPICIOUS",
        evidence=evidence,
    )
    report = engine.generate_explanation(finding)

    assert report.validation_status != ExplanationValidationStatus.CONFIRMED, (
        "SUSPICIOUS finding must never be upgraded to CONFIRMED by the ExplanationEngine"
    )
