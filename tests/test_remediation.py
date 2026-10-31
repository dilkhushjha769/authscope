"""Unit tests for AuthScope Remediation Engine (backend/analysis/remediation.py).

Tests:
1. Category-specific remediation generation (BOLA/IDOR, BFLA, Missing Auth, Priv Escalation, Info Disclosure).
2. Framework-tailored code generation (Express / Node.js, FastAPI / Python, Spring Boot / Java).
3. Handling of incomplete, missing, or partial evidence.
4. Relevance assertions ensuring recommendations strictly address the specific flaw.
5. Injected AI client integration and graceful fallback on AI error.
6. to_remediation_recommendation() schema conversion.
7. Legacy generate_patch() backward compatibility.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
import json
import pytest

from backend.analysis.remediation import (
    DetailedRemediationPlan,
    RemediationEngine,
    AIClientProtocol,
)
from backend.agent.schemas import (
    AffectedResource,
    ConfidenceLevel,
    ConfirmationStatus,
    EvidenceType,
    FindingAnalysis,
    RemediationRecommendation,
    SecurityEvidence,
    ValidationStatus,
)


# ==============================================================================
# Test Fixtures
# ==============================================================================


@pytest.fixture
def idor_resource() -> AffectedResource:
    """Fixture providing a shopping basket resource affected by IDOR."""
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
def idor_evidence() -> SecurityEvidence:
    """Fixture providing verified IDOR evidence."""
    return SecurityEvidence(
        evidence_id="evi_idor_01",
        evidence_type=EvidenceType.DIFFERENTIAL_RESPONSE,
        description="User B accessed User A shopping basket.",
        source_component="AuthorizationTester",
        affected_endpoint="/rest/basket/1",
        http_method="GET",
        observed_behavior="HTTP 200 returned User A cart.",
        expected_behavior="HTTP 403 Forbidden.",
        validation_status=ValidationStatus.VALIDATED,
        supporting_evidence_refs=["sha256_mock_hash"],
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def idor_analysis(idor_resource: AffectedResource, idor_evidence: SecurityEvidence) -> FindingAnalysis:
    """Fixture providing a verified BOLA/IDOR FindingAnalysis model."""
    return FindingAnalysis(
        title="Broken Object Level Authorization (IDOR) on Shopping Basket",
        vulnerability_explanation="User B retrieved customer basket 1 belonging to User A without authorization.",
        technical_root_cause="Missing server-side ownership verification comparing req.user.id with basket.UserId.",
        affected_resources=[idor_resource],
        potential_impact="Unauthorized disclosure of customer cart contents and horizontal privilege escalation.",
        supporting_evidence=[idor_evidence],
        confidence_level=ConfidenceLevel.CONFIRMED,
        confirmation_status=ConfirmationStatus.CONFIRMED,
        limitations_and_missing_info=[],
    )


@pytest.fixture
def bfla_analysis() -> FindingAnalysis:
    """Fixture providing a BFLA FindingAnalysis model."""
    resource = AffectedResource(
        resource_id="admin_metrics",
        resource_type="API_ENDPOINT",
        endpoint="/rest/admin/application-version",
        application_name="OWASP Juice Shop",
        owner_identity="admin",
        unauthorized_accessors=["user_a", "anonymous"],
    )
    evidence = SecurityEvidence(
        evidence_id="evi_bfla_01",
        evidence_type=EvidenceType.ACCESS_CONTROL_BYPASS,
        description="Standard User A accessed administrative metrics.",
        source_component="AuthorizationTester",
        affected_endpoint="/rest/admin/application-version",
        http_method="GET",
        observed_behavior="HTTP 200 OK returned internal build metadata.",
        expected_behavior="HTTP 403 Forbidden with Admin Role Required.",
        validation_status=ValidationStatus.VALIDATED,
    )
    return FindingAnalysis(
        title="Broken Function Level Authorization (BFLA) on Admin Route",
        vulnerability_explanation="Unprivileged user accessed administrative configuration endpoint.",
        technical_root_cause="Endpoint lacks role verification middleware asserting caller has admin role claim.",
        affected_resources=[resource],
        potential_impact="Exposure of sensitive application configuration and vertical privilege escalation.",
        supporting_evidence=[evidence],
        confidence_level=ConfidenceLevel.CONFIRMED,
        confirmation_status=ConfirmationStatus.CONFIRMED,
    )


# ==============================================================================
# Mock AI Client for Dependency Injection
# ==============================================================================


class MockAIClient:
    """Mock AI client for remediation synthesis testing."""

    def __init__(self, response_dict: Dict[str, Any], should_fail: bool = False):
        self.response_dict = response_dict
        self.should_fail = should_fail
        self.call_count = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.call_count += 1
        if self.should_fail:
            raise RuntimeError("Injected LLM timeout or connection failure")
        return json.dumps(self.response_dict)


# ==============================================================================
# 1. Category-Specific Remediation Tests
# ==============================================================================


class TestCategoryRemediation:
    def test_bola_remediation_content(self, idor_analysis: FindingAnalysis):
        """BOLA/IDOR remediation generates ownership verification checks and 403 retest procedure."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis, target_framework="express")

        assert isinstance(plan, DetailedRemediationPlan)
        assert "ownership" in plan.recommended_fix.lower()
        assert "basket.UserId !== req.user.id" in plan.technical_implementation_guidance or "UserId" in plan.technical_implementation_guidance
        assert "ResourceOwnershipMiddleware" in plan.additional_security_controls
        assert "403" in plan.expected_secure_behavior
        assert "User B" in plan.retesting_procedure

    def test_bfla_remediation_content(self, bfla_analysis: FindingAnalysis):
        """BFLA remediation generates RBAC role verification and administrative control."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(bfla_analysis, target_framework="express")

        assert "role-based access control" in plan.recommended_fix.lower() or "rbac" in plan.recommended_fix.lower()
        assert "requireRole('admin')" in plan.technical_implementation_guidance
        assert "RequireAdminRoleMiddleware" in plan.additional_security_controls
        assert "403" in plan.expected_secure_behavior

    def test_missing_auth_remediation_content(self):
        """Missing auth generates mandatory JWT authentication middleware."""
        resource = AffectedResource(
            resource_id="api_private",
            resource_type="API_ENDPOINT",
            endpoint="/api/v1/private-data",
        )
        evidence = SecurityEvidence(
            evidence_id="evi_noauth",
            evidence_type=EvidenceType.ACCESS_CONTROL_BYPASS,
            description="Anonymous access to private data",
            source_component="Scanner",
            affected_endpoint="/api/v1/private-data",
            observed_behavior="HTTP 200 without token",
            expected_behavior="HTTP 401 Unauthorized",
            validation_status=ValidationStatus.VALIDATED,
        )
        analysis = FindingAnalysis(
            title="Missing Authentication on Private Route",
            vulnerability_explanation="Anonymous callers can view private data.",
            technical_root_cause="Missing authentication middleware on private route.",
            affected_resources=[resource],
            potential_impact="Information disclosure to unauthenticated third parties.",
            supporting_evidence=[evidence],
            confidence_level=ConfidenceLevel.CONFIRMED,
            confirmation_status=ConfirmationStatus.CONFIRMED,
        )

        engine = RemediationEngine()
        plan = engine.generate_remediation(analysis, target_framework="express")

        assert "authentication" in plan.recommended_fix.lower()
        assert "verifyJwt" in plan.technical_implementation_guidance or "jwt" in plan.technical_implementation_guidance.lower()
        assert "401" in plan.expected_secure_behavior


# ==============================================================================
# 2. Framework-Specific Code Generation Tests
# ==============================================================================


class TestFrameworkSupport:
    def test_fastapi_python_code_generation(self, idor_analysis: FindingAnalysis):
        """Targeting FastAPI generates Python typing, Depends, and HTTPException."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis, target_framework="fastapi")

        assert plan.target_framework == "fastapi"
        assert "FastAPI / Python" in plan.technical_implementation_guidance
        assert "HTTPException" in plan.technical_implementation_guidance
        assert "status.HTTP_403_FORBIDDEN" in plan.technical_implementation_guidance

    def test_spring_boot_java_code_generation(self, idor_analysis: FindingAnalysis):
        """Targeting Spring Boot generates Java annotations like @PreAuthorize."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis, target_framework="spring")

        assert plan.target_framework == "spring"
        assert "@PreAuthorize" in plan.technical_implementation_guidance

    def test_express_nodejs_code_generation(self, idor_analysis: FindingAnalysis):
        """Targeting Express generates JavaScript/Node middleware syntax."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis, target_framework="express")

        assert plan.target_framework == "express"
        assert "req.params" in plan.technical_implementation_guidance
        assert "res.status(403)" in plan.technical_implementation_guidance


# ==============================================================================
# 3. Incomplete Evidence Handling Tests
# ==============================================================================


class TestIncompleteEvidenceHandling:
    def test_empty_evidence_and_resource_handles_gracefully(self):
        """Remediation generation gracefully produces safe defaults if resource list is empty."""
        empty_analysis = FindingAnalysis(
            title="Broken Access Control Discrepancy",
            vulnerability_explanation="Access control anomaly detected during scan.",
            technical_root_cause="Authorization check failed on protected route.",
            affected_resources=[
                AffectedResource(
                    resource_id="generic_res",
                    resource_type="API_ENDPOINT",
                    endpoint="/api/endpoint",
                )
            ],
            potential_impact="Potential unauthorized access.",
            supporting_evidence=[
                SecurityEvidence(
                    evidence_id="evi_min",
                    evidence_type=EvidenceType.HTTP_TRANSACTION,
                    description="Minimal evidence",
                    source_component="Scanner",
                    affected_endpoint="/api/endpoint",
                    observed_behavior="Observed 200",
                    expected_behavior="Expected 403",
                    validation_status=ValidationStatus.UNVALIDATED,
                )
            ],
            confidence_level=ConfidenceLevel.LOW,
            confirmation_status=ConfirmationStatus.SUSPECTED,
        )

        engine = RemediationEngine()
        plan = engine.generate_remediation(empty_analysis, evidence=[], resource=None)

        assert isinstance(plan, DetailedRemediationPlan)
        assert "/api/endpoint" in plan.problem_addressed
        assert len(plan.regression_test_suggestions) > 0


# ==============================================================================
# 4. Relevance to Findings Tests
# ==============================================================================


class TestRecommendationRelevance:
    def test_remediation_strictly_relevant_to_endpoint(self, idor_analysis: FindingAnalysis):
        """Remediation explicitly names the affected endpoint and resource ID."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis)

        assert "/rest/basket/1" in plan.problem_addressed
        assert "/rest/basket/1" in plan.recommended_fix or "/rest/basket/1" in plan.technical_implementation_guidance
        assert "User B" in plan.retesting_procedure

    def test_remediation_does_not_recommend_disabling_security(self, idor_analysis: FindingAnalysis):
        """Remediation must never recommend removing or relaxing security controls."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis)

        forbidden_phrases = ["disable auth", "remove authentication", "bypass check", "allow all"]
        for phrase in forbidden_phrases:
            assert phrase not in plan.recommended_fix.lower()
            assert phrase not in plan.technical_implementation_guidance.lower()


# ==============================================================================
# 5. Dependency Injection & Mock AI Tests
# ==============================================================================


class TestAIClientInjection:
    def test_injected_ai_client_success(self, idor_analysis: FindingAnalysis):
        """Injected AI client returns custom remediation successfully."""
        mock_ai_data = {
            "recommended_fix": "Enforce strict tenant data isolation using user-bound queries.",
            "technical_implementation_guidance": "const item = await Cart.findOne({ where: { id: req.params.id, userId: req.user.id } });",
            "server_side_controls": ["CustomTenantFilter"],
            "why_fix_works": "The database query binds the session user ID directly into the WHERE clause.",
            "retesting_procedure": "Request basket 1 as User B and verify 403.",
            "regression_testing_recommendations": ["Automated multi-tenant test in pipeline."],
        }
        mock_client = MockAIClient(response_dict=mock_ai_data)
        engine = RemediationEngine(ai_client=mock_client)

        plan = engine.generate_remediation(idor_analysis)

        assert mock_client.call_count == 1
        assert "CustomTenantFilter" in plan.additional_security_controls
        assert "Cart.findOne" in plan.technical_implementation_guidance

    def test_injected_ai_client_fallback_on_failure(self, idor_analysis: FindingAnalysis):
        """If injected AI client throws an error, engine falls back to deterministic plan."""
        mock_client = MockAIClient(response_dict={}, should_fail=True)
        engine = RemediationEngine(ai_client=mock_client)

        plan = engine.generate_remediation(idor_analysis)

        assert mock_client.call_count == 1
        # Fallback was triggered deterministically
        assert isinstance(plan, DetailedRemediationPlan)
        assert "ownership" in plan.recommended_fix.lower()


# ==============================================================================
# 6. Schema Conversion & Legacy Tests
# ==============================================================================


class TestSchemaConversionAndLegacy:
    def test_to_remediation_recommendation(self, idor_analysis: FindingAnalysis):
        """DetailedRemediationPlan converts cleanly to RemediationRecommendation."""
        engine = RemediationEngine()
        plan = engine.generate_remediation(idor_analysis)
        rec = plan.to_remediation_recommendation()

        assert isinstance(rec, RemediationRecommendation)
        assert len(rec.server_side_controls) >= 1
        assert rec.recommended_fix == plan.recommended_fix
        assert rec.retesting_procedure == plan.retesting_procedure

    def test_legacy_generate_patch(self):
        """Legacy generate_patch interface continues to return code snippets."""
        engine = RemediationEngine()
        patch_idor = engine.generate_patch("BOLA_IDOR", framework="express")
        assert "req.user.id" in patch_idor

        patch_fastapi = engine.generate_patch("BOLA_IDOR", framework="fastapi")
        assert "HTTPException" in patch_fastapi

