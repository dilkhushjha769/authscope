"""Unit tests for AuthScope FindingAnalyzer (backend/agent/finding_analyzer.py).

Tests:
1. Confirmed findings (independently validated differential evidence).
2. Suspected findings (unvalidated preliminary observations).
3. Inconclusive findings (inconclusive validation status).
4. Contradictory evidence (conflicting permitted vs blocked responses).
5. Missing evidence gaps (absence of owner baseline or wire log hashes).
6. Anti-upgrade guardrail with Mock AI client (AI cannot independently upgrade unvalidated findings).
7. Vulnerability context and category-specific root-cause mappings (BOLA, BFLA, Missing Auth).
8. Legacy dictionary input backward compatibility.
"""

from datetime import datetime, timezone
from typing import Dict, Any
import json
import pytest

from backend.agent.finding_analyzer import FindingAnalyzer, AIClientProtocol
from backend.agent.schemas import (
    AffectedResource,
    ConfidenceLevel,
    ConfirmationStatus,
    EvidenceType,
    EvidenceValidation,
    FindingAnalysis,
    FindingAnalysisInput,
    SecurityEvidence,
    ValidationMethod,
    ValidationStatus,
    VulnerabilityCategory,
)


# ==============================================================================
# Predefined Test Fixtures
# ==============================================================================


@pytest.fixture
def target_resource() -> AffectedResource:
    """Fixture providing a shopping basket resource."""
    return AffectedResource(
        resource_id="basket_1",
        resource_type="API_ENDPOINT",
        endpoint="/rest/basket/1",
        application_name="OWASP Juice Shop",
        parameters=["id"],
        owner_identity="user_a",
        unauthorized_accessors=["user_b"],
    )


@pytest.fixture
def admin_resource() -> AffectedResource:
    """Fixture providing an administrative endpoint resource."""
    return AffectedResource(
        resource_id="admin_metrics",
        resource_type="API_ENDPOINT",
        endpoint="/rest/admin/application-version",
        application_name="OWASP Juice Shop",
        parameters=[],
        owner_identity="admin",
        unauthorized_accessors=["user_a", "anonymous"],
    )


@pytest.fixture
def validated_differential_evidence() -> SecurityEvidence:
    """Verified differential evidence indicating BOLA/IDOR."""
    return SecurityEvidence(
        evidence_id="evi_diff_01",
        evidence_type=EvidenceType.DIFFERENTIAL_RESPONSE,
        description="User B accessed User A shopping basket.",
        source_component="AuthorizationTester",
        affected_endpoint="/rest/basket/1",
        http_method="GET",
        observed_behavior="HTTP 200 OK returned with User A order details.",
        expected_behavior="HTTP 403 Forbidden with Access Denied.",
        validation_status=ValidationStatus.VALIDATED,
        supporting_evidence_refs=["sha256_mock_hash_8a4f91"],
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def unvalidated_evidence() -> SecurityEvidence:
    """Unvalidated, preliminary evidence."""
    return SecurityEvidence(
        evidence_id="evi_prelim_01",
        evidence_type=EvidenceType.STATUS_MISMATCH,
        description="Preliminary observation of 200 on basket route.",
        source_component="EndpointDiscovery",
        affected_endpoint="/rest/basket/1",
        http_method="GET",
        observed_behavior="HTTP 200 OK returned without session token.",
        expected_behavior="HTTP 401 Unauthorized expected.",
        validation_status=ValidationStatus.UNVALIDATED,
        supporting_evidence_refs=[],
    )


@pytest.fixture
def trusted_validation_metadata() -> EvidenceValidation:
    """Valid evidence validation metadata."""
    return EvidenceValidation(
        is_validated=True,
        validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
        validation_status=ValidationStatus.VALIDATED,
        validation_notes="Verified via 3-way differential matrix across User A, User B, and Anon.",
        supporting_evidence_ids=["evi_diff_01"],
    )


# ==============================================================================
# Mock AI Client for Dependency Injection
# ==============================================================================


class MockAIClient:
    """Mock implementation of AIClientProtocol for unit testing."""

    def __init__(self, response_dict: Dict[str, Any]):
        self.response_dict = response_dict
        self.call_count = 0
        self.last_system_prompt = ""
        self.last_user_prompt = ""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return json.dumps(self.response_dict)


# ==============================================================================
# 1. Confirmed Findings Tests
# ==============================================================================


class TestConfirmedFindings:
    def test_confirmed_status_assigned_when_independently_validated(
        self,
        target_resource: AffectedResource,
        validated_differential_evidence: SecurityEvidence,
        trusted_validation_metadata: EvidenceValidation,
    ):
        """Findings with validated evidence and valid metadata receive CONFIRMED status."""
        analyzer = FindingAnalyzer()
        input_data = FindingAnalysisInput(
            finding_id="fnd_idor_01",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[validated_differential_evidence],
            affected_resource=target_resource,
            user_role_context="user_b",
            evidence_validation=trusted_validation_metadata,
        )

        result = analyzer.analyze(input_data)

        assert result.confirmation_status == ConfirmationStatus.CONFIRMED
        assert result.confidence_level == ConfidenceLevel.CONFIRMED
        assert "Broken Object Level Authorization" in result.title
        assert "user_b" in result.technical_root_cause
        assert "Unauthorized data access" in result.potential_impact
        assert len(result.supporting_evidence) == 1


# ==============================================================================
# 2. Suspected Findings Tests
# ==============================================================================


class TestSuspectedFindings:
    def test_suspected_status_assigned_for_unvalidated_evidence(
        self,
        target_resource: AffectedResource,
        unvalidated_evidence: SecurityEvidence,
    ):
        """Unvalidated evidence must remain SUSPECTED and cannot be CONFIRMED."""
        analyzer = FindingAnalyzer()
        input_data = FindingAnalysisInput(
            finding_id="fnd_prelim_01",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[unvalidated_evidence],
            affected_resource=target_resource,
            user_role_context="anonymous",
            evidence_validation=None,  # No independent validation
        )

        result = analyzer.analyze(input_data)

        assert result.confirmation_status == ConfirmationStatus.SUSPECTED
        assert result.confidence_level != ConfidenceLevel.CONFIRMED
        assert len(result.limitations_and_missing_info) > 0


# ==============================================================================
# 3. Inconclusive Findings Tests
# ==============================================================================


class TestInconclusiveFindings:
    def test_inconclusive_status_when_metadata_is_inconclusive(
        self,
        target_resource: AffectedResource,
        validated_differential_evidence: SecurityEvidence,
    ):
        """When validation metadata marks evidence as inconclusive, status is INCONCLUSIVE."""
        analyzer = FindingAnalyzer()
        inconclusive_meta = EvidenceValidation(
            is_validated=False,
            validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
            validation_status=ValidationStatus.INCONCLUSIVE,
            validation_notes="Target server returned generic error page disguised as 200 OK.",
            supporting_evidence_ids=["evi_diff_01"],
        )

        input_data = FindingAnalysisInput(
            finding_id="fnd_inconclusive_01",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[validated_differential_evidence],
            affected_resource=target_resource,
            evidence_validation=inconclusive_meta,
        )

        result = analyzer.analyze(input_data)

        assert result.confirmation_status == ConfirmationStatus.INCONCLUSIVE
        assert result.confidence_level == ConfidenceLevel.LOW


# ==============================================================================
# 4. Contradictory Evidence Tests
# ==============================================================================


class TestContradictoryEvidence:
    def test_contradictory_evidence_marked_inconclusive(
        self,
        target_resource: AffectedResource,
    ):
        """When evidence contains contradictory permitted and blocked results, set INCONCLUSIVE."""
        evidence_allowed = SecurityEvidence(
            evidence_id="evi_allow",
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            description="Access succeeded",
            source_component="ScannerA",
            affected_endpoint="/rest/basket/1",
            http_method="GET",
            observed_behavior="HTTP 200 OK returned data",
            expected_behavior="HTTP 403 Forbidden",
            validation_status=ValidationStatus.UNVALIDATED,
        )
        evidence_blocked = SecurityEvidence(
            evidence_id="evi_block",
            evidence_type=EvidenceType.HTTP_TRANSACTION,
            description="Access failed",
            source_component="ScannerB",
            affected_endpoint="/rest/basket/1",
            http_method="GET",
            observed_behavior="HTTP 403 Forbidden access blocked",
            expected_behavior="HTTP 403 Forbidden",
            validation_status=ValidationStatus.UNVALIDATED,
        )

        analyzer = FindingAnalyzer()
        input_data = FindingAnalysisInput(
            finding_id="fnd_contradictory_01",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[evidence_allowed, evidence_blocked],
            affected_resource=target_resource,
        )

        result = analyzer.analyze(input_data)

        assert result.confirmation_status == ConfirmationStatus.INCONCLUSIVE
        assert result.confidence_level == ConfidenceLevel.LOW
        assert any("Contradictory" in limitation for limitation in result.limitations_and_missing_info)


# ==============================================================================
# 5. Missing Evidence Gaps Tests
# ==============================================================================


class TestMissingEvidenceGaps:
    def test_missing_baseline_identified(
        self,
        target_resource: AffectedResource,
    ):
        """Single-request non-differential evidence flags absence of comparative baseline."""
        single_evidence = SecurityEvidence(
            evidence_id="evi_single",
            evidence_type=EvidenceType.HTTP_TRANSACTION,  # Not differential
            description="Single GET probe without comparison",
            source_component="Crawler",
            affected_endpoint="/rest/basket/1",
            http_method="GET",
            observed_behavior="HTTP 200 returned",
            expected_behavior="HTTP 403 Forbidden",
            validation_status=ValidationStatus.UNVALIDATED,
        )

        analyzer = FindingAnalyzer()
        input_data = FindingAnalysisInput(
            finding_id="fnd_gap_01",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[single_evidence],
            affected_resource=target_resource,
        )

        result = analyzer.analyze(input_data)

        assert any("Absence of comparative role baseline" in lim for lim in result.limitations_and_missing_info)
        assert result.confirmation_status == ConfirmationStatus.SUSPECTED


# ==============================================================================
# 6. Dependency Injection & Anti-Upgrade Rule Tests
# ==============================================================================


class TestAntiUpgradeGuardrailWithMockAI:
    def test_mock_ai_cannot_upgrade_unvalidated_finding_to_confirmed(
        self,
        target_resource: AffectedResource,
        unvalidated_evidence: SecurityEvidence,
    ):
        """CRITICAL: If mock AI attempts to return 'confirmed' on unvalidated input,

        FindingAnalyzer overrides confirmation_status to SUSPECTED.
        """
        # Malicious or hallucinating AI response trying to confirm unvalidated finding
        ai_hallucination = {
            "title": "AI Hallucinated Confirmed IDOR",
            "vulnerability_explanation": "Model claims this vulnerability is 100% verified.",
            "technical_root_cause": "Hypothetical code flaw.",
            "affected_resources": [target_resource.model_dump()],
            "potential_impact": "Massive breach.",
            "supporting_evidence": [unvalidated_evidence.model_dump()],
            "confidence_level": "CONFIRMED",
            "confirmation_status": "confirmed",  # FORBIDDEN UPGRADE ATTEMPT!
            "limitations_and_missing_info": [],
        }

        mock_client = MockAIClient(response_dict=ai_hallucination)
        analyzer = FindingAnalyzer(ai_client=mock_client)

        input_data = FindingAnalysisInput(
            finding_id="fnd_unvalidated_ai_test",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[unvalidated_evidence],
            affected_resource=target_resource,
            evidence_validation=None,  # Not validated
        )

        result = analyzer.analyze(input_data)

        # Assert AI was invoked
        assert mock_client.call_count == 1
        # Assert confirmation status was downgraded/prevented from being CONFIRMED
        assert result.confirmation_status == ConfirmationStatus.SUSPECTED
        assert result.confidence_level != ConfidenceLevel.CONFIRMED

    def test_mock_ai_accepted_when_evidence_is_validated(
        self,
        target_resource: AffectedResource,
        validated_differential_evidence: SecurityEvidence,
        trusted_validation_metadata: EvidenceValidation,
    ):
        """When evidence is validated, AI analysis is accepted with CONFIRMED status."""
        ai_valid_response = {
            "title": "Broken Object Level Authorization on Basket",
            "vulnerability_explanation": "User B can retrieve User A basket data without ownership verification.",
            "technical_root_cause": "Missing basket.UserId == req.user.id check in basket controller.",
            "affected_resources": [target_resource.model_dump()],
            "potential_impact": "Unauthorized customer PII disclosure.",
            "supporting_evidence": [validated_differential_evidence.model_dump()],
            "confidence_level": "CONFIRMED",
            "confirmation_status": "confirmed",
            "limitations_and_missing_info": [],
        }

        mock_client = MockAIClient(response_dict=ai_valid_response)
        analyzer = FindingAnalyzer(ai_client=mock_client)

        input_data = FindingAnalysisInput(
            finding_id="fnd_validated_ai_test",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[validated_differential_evidence],
            affected_resource=target_resource,
            evidence_validation=trusted_validation_metadata,
        )

        result = analyzer.analyze(input_data)

        assert mock_client.call_count == 1
        assert result.confirmation_status == ConfirmationStatus.CONFIRMED
        assert result.confidence_level == ConfidenceLevel.CONFIRMED


# ==============================================================================
# 7. Vulnerability Categories & Context Tests
# ==============================================================================


class TestVulnerabilityCategories:
    def test_bfla_vulnerability_context(
        self,
        admin_resource: AffectedResource,
    ):
        """Verifies BFLA category produces role-based failed controls and impact."""
        bfla_evidence = SecurityEvidence(
            evidence_id="evi_bfla_01",
            evidence_type=EvidenceType.ACCESS_CONTROL_BYPASS,
            description="Standard User A accessed administrative version route.",
            source_component="AuthorizationTester",
            affected_endpoint="/rest/admin/application-version",
            http_method="GET",
            observed_behavior="HTTP 200 returned internal version metrics.",
            expected_behavior="HTTP 403 Forbidden with Administrator Role Required.",
            validation_status=ValidationStatus.VALIDATED,
            supporting_evidence_refs=["ref_hash_admin_01"],
        )

        analyzer = FindingAnalyzer()
        input_data = FindingAnalysisInput(
            finding_id="fnd_bfla_01",
            vulnerability_category=VulnerabilityCategory.BFLA,
            security_evidence=[bfla_evidence],
            affected_resource=admin_resource,
            user_role_context="user_a",
        )

        result = analyzer.analyze(input_data)

        assert "Broken Function Level Authorization" in result.title
        assert "Vertical privilege escalation" in result.potential_impact
        assert "administrative" in result.technical_root_cause


# ==============================================================================
# 8. Legacy Input Compatibility Tests
# ==============================================================================


class TestLegacyCompatibility:
    def test_legacy_dictionary_analyzed_gracefully(self):
        """Pass legacy raw_evidence dictionary to analyze(); assert it produces FindingAnalysis."""
        legacy_payload = {
            "raw_evidence": {
                "endpoint": "/rest/basket/1",
                "method": "GET",
                "description": "User B saw User A basket",
                "observed": "HTTP 200 returned items",
                "expected": "HTTP 403 Forbidden",
                "resource_id": "basket_1",
            }
        }

        analyzer = FindingAnalyzer()
        result = analyzer.analyze(legacy_payload)

        assert isinstance(result, FindingAnalysis)
        assert result.affected_resources[0].endpoint == "/rest/basket/1"
        assert result.confirmation_status == ConfirmationStatus.SUSPECTED
