"""Unit tests for AuthScope AI Analysis Module Pydantic schemas.

Validates:
1. Instantiation and validation for all 8 required schemas.
2. Anti-hallucination guardrail: AI cannot confirm findings without validated evidence.
3. Strict enum validation and severity normalization.
4. Prevention of arbitrary AI-generated fields (extra='forbid').
5. JSON serialization and deserialization integrity.
"""

import json
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from backend.agent.schemas import (
    AffectedResource,
    AnalysisStatus,
    ConfidenceLevel,
    ConfirmationStatus,
    DataSensitivityLevel,
    EvidenceType,
    EvidenceValidation,
    ExploitabilityLevel,
    FindingAnalysis,
    FindingAnalysisInput,
    FindingAnalysisOutput,
    PrivilegeGainedLevel,
    RemediationRecommendation,
    SecurityEvidence,
    SeverityAssessment,
    SeverityLevel,
    ValidationMethod,
    ValidationStatus,
    VulnerabilityCategory,
)


@pytest.fixture
def valid_security_evidence() -> SecurityEvidence:
    """Provides a valid, verified security evidence artifact."""
    return SecurityEvidence(
        evidence_id="evi_8a4f91c2",
        evidence_type=EvidenceType.DIFFERENTIAL_RESPONSE,
        description="User B was able to view User A's private shopping basket.",
        source_component="AuthorizationTester",
        affected_endpoint="/rest/basket/1",
        http_method="GET",
        observed_behavior="HTTP 200 returned with User A's private product inventory.",
        expected_behavior="HTTP 403 Forbidden because User B does not own basket 1.",
        validation_status=ValidationStatus.VALIDATED,
        supporting_evidence_refs=["sha256_8a4f91c2b53e7f22"],
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def unvalidated_security_evidence() -> SecurityEvidence:
    """Provides an unvalidated/suspected security evidence artifact."""
    return SecurityEvidence(
        evidence_id="evi_unverified_01",
        evidence_type=EvidenceType.STATUS_MISMATCH,
        description="Endpoint responded with unexpected 200 without payload comparison.",
        source_component="EndpointDiscovery",
        affected_endpoint="/rest/basket/99",
        http_method="GET",
        observed_behavior="HTTP 200 returned.",
        expected_behavior="HTTP 401 Unauthorized expected.",
        validation_status=ValidationStatus.UNVALIDATED,
        supporting_evidence_refs=[],
    )


@pytest.fixture
def valid_affected_resource() -> AffectedResource:
    """Provides a valid affected resource."""
    return AffectedResource(
        resource_id="basket_1",
        resource_type="API_ENDPOINT",
        endpoint="/rest/basket/1",
        application_name="OWASP Juice Shop",
        parameters=["id"],
        owner_identity="user_a",
        unauthorized_accessors=["user_b", "anonymous"],
    )


@pytest.fixture
def valid_evidence_validation() -> EvidenceValidation:
    """Provides a valid evidence validation object."""
    return EvidenceValidation(
        is_validated=True,
        validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
        validation_status=ValidationStatus.VALIDATED,
        validation_notes="Verified via 3-way differential matrix between User A and User B.",
        supporting_evidence_ids=["evi_8a4f91c2"],
    )


@pytest.fixture
def valid_severity_assessment() -> SeverityAssessment:
    """Provides a valid severity assessment."""
    return SeverityAssessment(
        severity=SeverityLevel.HIGH,
        exploitability=ExploitabilityLevel.HIGH,
        data_sensitivity=DataSensitivityLevel.PII,
        privilege_gained=PrivilegeGainedLevel.HORIZONTAL_USER,
        potential_impact="Unauthorized disclosure of customer cart and order data.",
        severity_rationale="BOLA/IDOR exposing private customer data without user interaction.",
        confidence=ConfidenceLevel.CONFIRMED,
        contributing_factors=["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Exposes PII"],
    )


@pytest.fixture
def valid_remediation() -> RemediationRecommendation:
    """Provides a valid remediation recommendation."""
    return RemediationRecommendation(
        recommended_fix="Enforce server-side ownership checks on basket resources.",
        technical_implementation_guidance=(
            "Verify that req.user.id matches the owner of the requested basket record: "
            "if (req.user.id !== basket.UserId) return res.status(403).json({ error: 'Access Denied' });"
        ),
        server_side_controls=["OwnershipVerificationMiddleware", "SessionValidationFilter"],
        why_fix_works="Ensures requests are rejected before accessing unowned database records.",
        retesting_procedure="Send GET /rest/basket/1 with User B token; verify response is HTTP 403 Forbidden.",
        regression_testing_recommendations=["Add automated unit test verifying cross-tenant basket access rejection."],
    )


# ==============================================================================
# 1. SecurityEvidence Tests
# ==============================================================================


class TestSecurityEvidence:
    def test_valid_evidence_creation(self, valid_security_evidence: SecurityEvidence):
        assert valid_security_evidence.evidence_id == "evi_8a4f91c2"
        assert valid_security_evidence.http_method == "GET"
        assert valid_security_evidence.validation_status == ValidationStatus.VALIDATED

    def test_http_method_normalized_to_uppercase(self):
        evidence = SecurityEvidence(
            evidence_id="evi_test",
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            description="Test description",
            source_component="Tester",
            affected_endpoint="/api/test",
            http_method="post",  # lowercase
            observed_behavior="Observed",
            expected_behavior="Expected",
            validation_status=ValidationStatus.VALIDATED,
        )
        assert evidence.http_method == "POST"

    def test_invalid_http_method_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            SecurityEvidence(
                evidence_id="evi_test",
                evidence_type=EvidenceType.HTTP_TRANSACTION,
                description="Test description",
                source_component="Tester",
                affected_endpoint="/api/test",
                http_method="INVALID_METHOD",
                observed_behavior="Observed",
                expected_behavior="Expected",
                validation_status=ValidationStatus.VALIDATED,
            )
        assert "Unsupported HTTP method" in str(exc_info.value)

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError) as exc_info:
            SecurityEvidence(
                evidence_id="evi_test",
                evidence_type=EvidenceType.HTTP_TRANSACTION,
                description="Test description",
                source_component="Tester",
                affected_endpoint="/api/test",
                observed_behavior="Observed",
                expected_behavior="Expected",
                validation_status=ValidationStatus.VALIDATED,
                arbitrary_ai_hallucination="some text",
            )
        assert "extra_forbidden" in str(exc_info.value)


# ==============================================================================
# 2. EvidenceValidation Tests
# ==============================================================================


class TestEvidenceValidation:
    def test_valid_validation_instance(self, valid_evidence_validation: EvidenceValidation):
        assert valid_evidence_validation.is_validated is True
        assert valid_evidence_validation.validation_status == ValidationStatus.VALIDATED

    def test_inconsistent_validation_raises_error(self):
        # validation_status is 'unvalidated' but is_validated is True
        with pytest.raises(ValidationError) as exc_info:
            EvidenceValidation(
                is_validated=True,
                validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
                validation_status=ValidationStatus.UNVALIDATED,
                validation_notes="Unvalidated notes",
            )
        assert "Inconsistent validation" in str(exc_info.value)

        # validation_status is 'validated' but is_validated is False
        with pytest.raises(ValidationError) as exc_info:
            EvidenceValidation(
                is_validated=False,
                validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
                validation_status=ValidationStatus.VALIDATED,
                validation_notes="Validated notes",
            )
        assert "Inconsistent validation" in str(exc_info.value)


# ==============================================================================
# 3. FindingAnalysis & Anti-Hallucination Guardrail Tests
# ==============================================================================


class TestFindingAnalysisAntiHallucination:
    def test_cannot_confirm_finding_with_unvalidated_evidence(
        self,
        unvalidated_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
    ):
        """CRITICAL: The AI must never be able to mark an unvalidated finding as confirmed."""
        with pytest.raises(ValidationError) as exc_info:
            FindingAnalysis(
                title="BOLA in Cart Access",
                vulnerability_explanation="User B could view User A's cart contents without restriction.",
                technical_root_cause="Missing ownership check on the requested basket record.",
                affected_resources=[valid_affected_resource],
                potential_impact="Exposure of customer purchase history and address.",
                supporting_evidence=[unvalidated_security_evidence],
                confidence_level=ConfidenceLevel.HIGH,
                confirmation_status=ConfirmationStatus.CONFIRMED,  # FORBIDDEN! Evidence is UNVALIDATED
            )
        assert "AI Guardrail Violation" in str(exc_info.value)
        assert "Cannot mark finding as CONFIRMED" in str(exc_info.value)

    def test_unvalidated_finding_can_be_marked_as_suspected(
        self,
        unvalidated_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
    ):
        """Unvalidated evidence CAN be recorded as SUSPECTED or UNCONFIRMED."""
        finding = FindingAnalysis(
            title="Suspected BOLA in Cart Access",
            vulnerability_explanation="Potential IDOR detected during initial discovery crawl.",
            technical_root_cause="Endpoint returned 200 without active session token.",
            affected_resources=[valid_affected_resource],
            potential_impact="Possible unauthorized access if verified.",
            supporting_evidence=[unvalidated_security_evidence],
            confidence_level=ConfidenceLevel.LOW,
            confirmation_status=ConfirmationStatus.SUSPECTED,  # ALLOWED
            limitations_and_missing_info=["Requires differential test execution to confirm."],
        )
        assert finding.confirmation_status == ConfirmationStatus.SUSPECTED

    def test_validated_evidence_allows_confirmed_finding(
        self,
        valid_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
    ):
        """Confirmed status is accepted when supporting evidence is independently validated."""
        finding = FindingAnalysis(
            title="Broken Object Level Authorization (IDOR) on Shopping Basket",
            vulnerability_explanation="User B was able to view customer cart details belonging to User A.",
            technical_root_cause="The endpoint checks authorization only for authentication, not resource ownership.",
            affected_resources=[valid_affected_resource],
            potential_impact="Confidential customer cart disclosure and privacy violation.",
            supporting_evidence=[valid_security_evidence],
            confidence_level=ConfidenceLevel.CONFIRMED,
            confirmation_status=ConfirmationStatus.CONFIRMED,
        )
        assert finding.confirmation_status == ConfirmationStatus.CONFIRMED


# ==============================================================================
# 4. SeverityAssessment Tests
# ==============================================================================


class TestSeverityAssessment:
    def test_severity_case_insensitive_normalization(self):
        assessment = SeverityAssessment(
            severity="Informational",  # Normalized
            exploitability=ExploitabilityLevel.LOW,
            data_sensitivity=DataSensitivityLevel.PUBLIC,
            privilege_gained=PrivilegeGainedLevel.NONE,
            potential_impact="Negligible information disclosure.",
            severity_rationale="Public endpoint with minor debug information.",
            confidence=ConfidenceLevel.HIGH,
        )
        assert assessment.severity == SeverityLevel.INFORMATIONAL

    def test_unsupported_severity_rejected(self):
        with pytest.raises(ValidationError):
            SeverityAssessment(
                severity="CATASTROPHIC",  # Unsupported
                exploitability=ExploitabilityLevel.HIGH,
                data_sensitivity=DataSensitivityLevel.CREDENTIALS,
                privilege_gained=PrivilegeGainedLevel.SYSTEM_ROOT,
                potential_impact="Complete takeover.",
                severity_rationale="Root breach.",
                confidence=ConfidenceLevel.HIGH,
            )

    def test_extra_fields_in_severity_forbidden(self):
        with pytest.raises(ValidationError) as exc_info:
            SeverityAssessment(
                severity=SeverityLevel.HIGH,
                exploitability=ExploitabilityLevel.HIGH,
                data_sensitivity=DataSensitivityLevel.PII,
                privilege_gained=PrivilegeGainedLevel.HORIZONTAL_USER,
                potential_impact="Exposure of customer records.",
                severity_rationale="BOLA access.",
                confidence=ConfidenceLevel.HIGH,
                hallucinated_score=9.9,  # Arbitrary AI field
            )
        assert "extra_forbidden" in str(exc_info.value)


# ==============================================================================
# 5. FindingAnalysisInput Tests
# ==============================================================================


class TestFindingAnalysisInput:
    def test_valid_input_creation(
        self,
        valid_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
        valid_evidence_validation: EvidenceValidation,
    ):
        input_data = FindingAnalysisInput(
            finding_id="fnd_idor_001",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[valid_security_evidence],
            affected_resource=valid_affected_resource,
            user_role_context="user_b",
            testing_context={"scenario": "cross_user_basket_read"},
            scope_info={"target_base_url": "http://localhost:3000", "is_in_scope": True},
            evidence_validation=valid_evidence_validation,
        )
        assert input_data.finding_id == "fnd_idor_001"
        assert len(input_data.security_evidence) == 1

    def test_empty_evidence_in_input_rejected(self, valid_affected_resource: AffectedResource):
        with pytest.raises(ValidationError):
            FindingAnalysisInput(
                finding_id="fnd_idor_001",
                vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
                security_evidence=[],  # Empty evidence rejected
                affected_resource=valid_affected_resource,
            )


# ==============================================================================
# 6. FindingAnalysisOutput & Serialization Tests
# ==============================================================================


class TestFindingAnalysisOutput:
    def test_complete_output_serialization_roundtrip(
        self,
        valid_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
        valid_severity_assessment: SeverityAssessment,
        valid_remediation: RemediationRecommendation,
    ):
        analysis = FindingAnalysis(
            title="Broken Object Level Authorization (IDOR) on Shopping Basket",
            vulnerability_explanation="User B accessed basket data belonging to User A.",
            technical_root_cause="Missing basket.UserId == req.user.id check.",
            affected_resources=[valid_affected_resource],
            potential_impact="Unauthorized viewing of items in other users' carts.",
            supporting_evidence=[valid_security_evidence],
            confidence_level=ConfidenceLevel.CONFIRMED,
            confirmation_status=ConfirmationStatus.CONFIRMED,
        )

        output = FindingAnalysisOutput(
            analysis=analysis,
            severity_assessment=valid_severity_assessment,
            remediation_recommendation=valid_remediation,
            evidence_references=["evi_8a4f91c2"],
            overall_status=AnalysisStatus.COMPLETED,
            warnings_or_limitations=[],
        )

        # JSON Serialization
        json_str = output.model_dump_json()
        assert "evi_8a4f91c2" in json_str

        # JSON Deserialization
        restored = FindingAnalysisOutput.model_validate_json(json_str)
        assert restored.analysis.title == analysis.title
        assert restored.severity_assessment.severity == SeverityLevel.HIGH
        assert restored.overall_status == AnalysisStatus.COMPLETED

    def test_mismatched_evidence_reference_rejected(
        self,
        valid_security_evidence: SecurityEvidence,
        valid_affected_resource: AffectedResource,
        valid_severity_assessment: SeverityAssessment,
        valid_remediation: RemediationRecommendation,
    ):
        analysis = FindingAnalysis(
            title="Broken Object Level Authorization (IDOR) on Shopping Basket",
            vulnerability_explanation="User B accessed basket data belonging to User A.",
            technical_root_cause="Missing basket.UserId == req.user.id check.",
            affected_resources=[valid_affected_resource],
            potential_impact="Unauthorized viewing of items in other users' carts.",
            supporting_evidence=[valid_security_evidence],
            confidence_level=ConfidenceLevel.CONFIRMED,
            confirmation_status=ConfirmationStatus.CONFIRMED,
        )

        with pytest.raises(ValidationError) as exc_info:
            FindingAnalysisOutput(
                analysis=analysis,
                severity_assessment=valid_severity_assessment,
                remediation_recommendation=valid_remediation,
                evidence_references=["evi_nonexistent_id"],  # Mismatch!
                overall_status=AnalysisStatus.COMPLETED,
            )
        assert "is not listed in the analysis supporting_evidence list" in str(exc_info.value)


    def test_example_json_files_validate(self):
        """Verifies that the reference example JSON files strictly comply with the Pydantic schemas."""
        from pathlib import Path

        input_path = Path("data/example_analysis_input.json")
        output_path = Path("data/example_analysis_output.json")

        assert input_path.exists()
        assert output_path.exists()

        inp = FindingAnalysisInput.model_validate_json(input_path.read_text(encoding="utf-8"))
        assert inp.finding_id == "fnd_idor_basket_01"
        assert len(inp.security_evidence) == 1

        out = FindingAnalysisOutput.model_validate_json(output_path.read_text(encoding="utf-8"))
        assert out.analysis.confirmation_status == ConfirmationStatus.CONFIRMED
        assert out.severity_assessment.severity == SeverityLevel.HIGH
