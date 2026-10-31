"""Unit tests for AuthScope Deterministic Severity Engine (backend/analysis/severity_engine.py).

Verifies:
1. Accurate scoring for all 5 severity levels: Critical, High, Medium, Low, Informational.
2. Handling of missing evidence and confidence damping.
3. Inconclusive and conflicting evidence handling.
4. Boundary condition tests (all minimums, all maximums, clamped inputs).
5. Anti-inflation safeguards (no unvalidated Criticals, zero-privilege/zero-data cap).
6. Non-override of AI rationale.
7. FindingAnalysisInput integration and to_severity_assessment() schema conversion.
8. Legacy calculate_severity() backward compatibility.
"""

from datetime import datetime, timezone
import pytest

from backend.analysis.severity_engine import (
    AC_HIGH_COMPLEXITY,
    AC_LOW_COMPLEXITY,
    AC_MEDIUM_COMPLEXITY,
    DS_CONFIDENTIAL_PII,
    DS_CRITICAL_CREDENTIALS,
    DS_INTERNAL,
    DS_LIMITED_NON_SENSITIVE,
    DS_NO_SENSITIVE,
    EC_HIGH,
    EC_LOW,
    EC_MODERATE,
    EX_NONE,
    EX_REPRODUCIBLE_DIRECT,
    PG_ADMIN_VERTICAL,
    PG_HORIZONTAL_USER,
    PG_LIMITED_ACCESS,
    PG_NONE,
    PI_CRITICAL,
    PI_LOW,
    PI_MODERATE,
    PI_NEGLIGIBLE,
    DeterministicSeverityResult,
    SeverityEngine,
)
from backend.agent.schemas import (
    AffectedResource,
    ConfidenceLevel,
    EvidenceType,
    EvidenceValidation,
    FindingAnalysisInput,
    SecurityEvidence,
    SeverityAssessment,
    SeverityLevel,
    ValidationMethod,
    ValidationStatus,
    VulnerabilityCategory,
)


@pytest.fixture
def engine() -> SeverityEngine:
    """Fixture providing a SeverityEngine instance."""
    return SeverityEngine()


# ==============================================================================
# 1. Tests for All 5 Severity Levels
# ==============================================================================


class TestSeverityLevels:
    def test_critical_severity_calculation(self, engine: SeverityEngine):
        """Administrative vertical escalation with reproducible exploitability yields CRITICAL."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_CONFIDENTIAL_PII,   # 3
            privilege_gained=PG_ADMIN_VERTICAL,     # 3
            exploitability=EX_REPRODUCIBLE_DIRECT,  # 3
            potential_impact=PI_CRITICAL,           # 3
            attack_complexity=AC_LOW_COMPLEXITY,    # 2 (raw 1.0)
            evidence_confidence=EC_HIGH,            # 2
        )
        assert result.final_severity == SeverityLevel.CRITICAL
        assert result.numeric_score >= 9.0
        assert result.confidence == ConfidenceLevel.CONFIRMED

    def test_high_severity_calculation(self, engine: SeverityEngine):
        """BOLA/IDOR exposing customer PII with validated evidence yields HIGH."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_CONFIDENTIAL_PII,   # 3
            privilege_gained=PG_HORIZONTAL_USER,    # 2
            exploitability=EX_REPRODUCIBLE_DIRECT,  # 3
            potential_impact=PI_MODERATE,           # 2
            attack_complexity=AC_LOW_COMPLEXITY,    # 2 (raw 1.0)
            evidence_confidence=EC_HIGH,            # 2
        )
        # raw points = 3 + 2 + 3 + 2 + 1.0 = 11.0 -> 11/14 * 10 = 7.9
        assert result.final_severity == SeverityLevel.HIGH
        assert 7.0 <= result.numeric_score <= 8.9

    def test_medium_severity_calculation(self, engine: SeverityEngine):
        """Horizontal IDOR with non-sensitive catalogue IDs yields MEDIUM."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_LIMITED_NON_SENSITIVE, # 1
            privilege_gained=PG_HORIZONTAL_USER,       # 2
            exploitability=EX_REPRODUCIBLE_DIRECT,     # 3
            potential_impact=PI_LOW,                   # 1
            attack_complexity=AC_MEDIUM_COMPLEXITY,    # 1 (raw 0.5)
            evidence_confidence=EC_HIGH,               # 2
        )
        # raw points = 1 + 2 + 3 + 1 + 0.5 = 7.5 -> 7.5/14 * 10 = 5.4
        assert result.final_severity == SeverityLevel.MEDIUM
        assert 4.0 <= result.numeric_score <= 6.9

    def test_low_severity_calculation(self, engine: SeverityEngine):
        """Minor internal info disclosure without privilege escalation yields LOW."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_INTERNAL,           # 2
            privilege_gained=PG_NONE,               # 0
            exploitability=1,                       # 1
            potential_impact=PI_LOW,                # 1
            attack_complexity=AC_HIGH_COMPLEXITY,   # 0 (raw 0.0)
            evidence_confidence=EC_HIGH,            # 2
        )
        # raw points = 2 + 0 + 1 + 1 + 0 = 4.0 -> 4.0/14 * 10 = 2.9
        assert result.final_severity == SeverityLevel.LOW
        assert 2.0 <= result.numeric_score <= 3.9

    def test_informational_severity_calculation(self, engine: SeverityEngine):
        """Negligible observation with zero sensitive data yields INFORMATIONAL."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_NO_SENSITIVE,       # 0
            privilege_gained=PG_NONE,               # 0
            exploitability=1,                       # 1
            potential_impact=PI_NEGLIGIBLE,         # 0
            attack_complexity=AC_HIGH_COMPLEXITY,   # 0
            evidence_confidence=EC_HIGH,            # 2
        )
        # raw points = 0 + 0 + 1 + 0 + 0 = 1.0 -> 1.0/14 * 10 = 0.7
        assert result.final_severity == SeverityLevel.INFORMATIONAL
        assert result.numeric_score < 2.0


# ==============================================================================
# 2. Tests for Missing Evidence & Confidence Damping
# ==============================================================================


class TestMissingEvidenceHandling:
    def test_low_confidence_damps_score(self, engine: SeverityEngine):
        """Low evidence confidence (EC=0) reduces the score by a 0.65x multiplier."""
        high_conf_result = engine.calculate_from_factors(
            data_sensitivity=3,
            privilege_gained=2,
            exploitability=3,
            potential_impact=2,
            attack_complexity=2,
            evidence_confidence=EC_HIGH,  # 2
        )
        low_conf_result = engine.calculate_from_factors(
            data_sensitivity=3,
            privilege_gained=2,
            exploitability=3,
            potential_impact=2,
            attack_complexity=2,
            evidence_confidence=EC_LOW,   # 0
            missing_information=["Missing User A baseline"],
        )
        assert low_conf_result.numeric_score < high_conf_result.numeric_score
        assert "Missing User A baseline" in low_conf_result.missing_information

    def test_low_confidence_cannot_exceed_medium_tier(self, engine: SeverityEngine):
        """Anti-inflation safeguard: EC=0 can NEVER be rated Critical or High (capped at 6.9)."""
        result = engine.calculate_from_factors(
            data_sensitivity=4,
            privilege_gained=3,
            exploitability=3,
            potential_impact=3,
            attack_complexity=2,
            evidence_confidence=EC_LOW,  # 0
        )
        assert result.numeric_score <= 6.9
        assert result.final_severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW)


# ==============================================================================
# 3. Tests for Conflicting / Inconclusive Evidence
# ==============================================================================


class TestInconclusiveEvidenceHandling:
    def test_inconclusive_validation_meta_drops_confidence(self, engine: SeverityEngine):
        """When validation metadata is inconclusive, evaluate_finding sets EC_LOW."""
        evidence = SecurityEvidence(
            evidence_id="evi_ambiguous",
            evidence_type=EvidenceType.STATUS_MISMATCH,
            description="Ambiguous 200 OK",
            source_component="Scanner",
            affected_endpoint="/api/test",
            observed_behavior="200 returned but body was empty",
            expected_behavior="403 Forbidden",
            validation_status=ValidationStatus.INCONCLUSIVE,
        )
        resource = AffectedResource(
            resource_id="res_test",
            resource_type="API_ENDPOINT",
            endpoint="/api/test",
        )
        val_meta = EvidenceValidation(
            is_validated=False,
            validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
            validation_status=ValidationStatus.INCONCLUSIVE,
            validation_notes="Conflicting responses observed.",
        )
        input_data = FindingAnalysisInput(
            finding_id="fnd_ambiguous",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[evidence],
            affected_resource=resource,
            evidence_validation=val_meta,
        )

        result = engine.evaluate_finding(input_data)
        assert result.factor_scores.evidence_confidence == EC_LOW
        assert result.confidence == ConfidenceLevel.LOW
        assert any("inconclusive" in g.lower() for g in result.missing_information)


# ==============================================================================
# 4. Boundary Condition Tests
# ==============================================================================


class TestBoundaryConditions:
    def test_all_zeros_returns_zero_score(self, engine: SeverityEngine):
        """All zero factors produce 0.0 score and INFORMATIONAL tier."""
        result = engine.calculate_from_factors(
            data_sensitivity=0,
            privilege_gained=0,
            exploitability=0,
            potential_impact=0,
            attack_complexity=0,
            evidence_confidence=0,
        )
        assert result.numeric_score == 0.0
        assert result.final_severity == SeverityLevel.INFORMATIONAL

    def test_all_maximums_returns_ten(self, engine: SeverityEngine):
        """All maximum factors produce 10.0 score and CRITICAL tier."""
        result = engine.calculate_from_factors(
            data_sensitivity=4,
            privilege_gained=3,
            exploitability=3,
            potential_impact=3,
            attack_complexity=2,
            evidence_confidence=2,
        )
        assert result.numeric_score == 10.0
        assert result.final_severity == SeverityLevel.CRITICAL

    def test_clamped_out_of_bound_inputs(self, engine: SeverityEngine):
        """Negative numbers and excessively high numbers are safely clamped."""
        result = engine.calculate_from_factors(
            data_sensitivity=-5,  # Clamped to 0
            privilege_gained=99,  # Clamped to 3
            exploitability=-1,    # Clamped to 0
            potential_impact=100, # Clamped to 3
            attack_complexity=-2, # Clamped to 0
            evidence_confidence=5,# Clamped to 2
        )
        assert result.factor_scores.data_sensitivity == 0
        assert result.factor_scores.privilege_gained == 3
        assert result.factor_scores.exploitability == 0
        assert result.factor_scores.potential_impact == 3
        assert 0.0 <= result.numeric_score <= 10.0

    def test_zero_sensitivity_and_zero_privilege_capped_at_low(self, engine: SeverityEngine):
        """Anti-inflation safeguard: If DS=0 and PG=0, score cannot exceed 3.9 (LOW)."""
        result = engine.calculate_from_factors(
            data_sensitivity=0,
            privilege_gained=0,
            exploitability=3,
            potential_impact=3,
            attack_complexity=2,
            evidence_confidence=2,
        )
        assert result.numeric_score <= 3.9
        assert result.final_severity in (SeverityLevel.LOW, SeverityLevel.INFORMATIONAL)


# ==============================================================================
# 5. AI Rationale Non-Override Tests
# ==============================================================================


class TestAIRationaleNonOverride:
    def test_ai_rationale_does_not_override_calculated_severity(self, engine: SeverityEngine):
        """Passing an AI rationale string annotates the result without altering the score."""
        ai_opinion = "I believe this vulnerability is CRITICAL and should be an emergency fix!"
        result = engine.calculate_from_factors(
            data_sensitivity=DS_INTERNAL,      # 2
            privilege_gained=PG_NONE,          # 0
            exploitability=1,                  # 1
            potential_impact=PI_LOW,           # 1
            attack_complexity=0,
            evidence_confidence=2,
            ai_rationale=ai_opinion,
        )
        # Score is deterministic (LOW) and NOT overridden by AI's claim of CRITICAL
        assert result.final_severity == SeverityLevel.LOW
        assert "Contextual Note:" in result.severity_rationale
        assert ai_opinion in result.severity_rationale


# ==============================================================================
# 6. Schema Conversion & Integration Tests
# ==============================================================================


class TestSchemaConversion:
    def test_to_severity_assessment_conversion(self, engine: SeverityEngine):
        """Validates conversion to Pydantic SeverityAssessment model."""
        result = engine.calculate_from_factors(
            data_sensitivity=DS_CONFIDENTIAL_PII,
            privilege_gained=PG_HORIZONTAL_USER,
            exploitability=EX_REPRODUCIBLE_DIRECT,
            potential_impact=PI_MODERATE,
            attack_complexity=AC_LOW_COMPLEXITY,
            evidence_confidence=EC_HIGH,
            evidence_references=["evi_idor_01"],
        )
        assessment = result.to_severity_assessment()

        assert isinstance(assessment, SeverityAssessment)
        assert assessment.severity == SeverityLevel.HIGH
        assert len(assessment.contributing_factors) >= 5
        assert assessment.confidence == ConfidenceLevel.CONFIRMED


# ==============================================================================
# 7. Legacy Helper Compatibility Tests
# ==============================================================================


class TestLegacyHelperCompatibility:
    def test_legacy_calculate_severity(self, engine: SeverityEngine):
        """Verifies backward compatibility of calculate_severity() interface."""
        sev_cred = engine.calculate_severity("BOLA_IDOR", exposes_credentials=True)
        assert sev_cred in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)

        sev_admin = engine.calculate_severity("BFLA", allows_privilege_escalation=True)
        assert sev_admin in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)

        sev_plain = engine.calculate_severity("INFO_DISCLOSURE")
        assert sev_plain in (SeverityLevel.LOW, SeverityLevel.INFORMATIONAL)

