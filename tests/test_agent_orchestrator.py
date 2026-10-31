"""Unit tests for AuthScope central AI Agent orchestrator.

Verifies the 8-step analysis workflow, Claude Messages API integration,
exponential backoff retries, error handling, and strict security guardrails.
"""

from unittest.mock import MagicMock, patch
import json
import os
import pytest

from anthropic import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AuthenticationError,
    InternalServerError,
    RateLimitError,
)

from backend.agent.agent import (
    AgentAPIError,
    AgentAuthenticationError,
    AgentConfigurationError,
    AgentValidationError,
    AuthScopeAgent,
)
from backend.agent.schemas import (
    AffectedResource,
    AnalysisStatus,
    ConfidenceLevel,
    ConfirmationStatus,
    DataSensitivityLevel,
    EvidenceType,
    EvidenceValidation,
    FindingAnalysisInput,
    FindingAnalysisOutput,
    PrivilegeGainedLevel,
    SecurityEvidence,
    SeverityLevel,
    ValidationMethod,
    ValidationStatus,
    VulnerabilityCategory,
)


# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================


@pytest.fixture
def sample_validated_evidence() -> SecurityEvidence:
    return SecurityEvidence(
        evidence_id="evi_orch_001",
        evidence_type=EvidenceType.DIFFERENTIAL_RESPONSE,
        description="Differential request revealed horizontal access to user 2 basket",
        source_component="DifferentialEngine",
        affected_endpoint="/rest/basket/2",
        http_method="GET",
        observed_behavior="HTTP 200 OK with User 2 cart items",
        expected_behavior="HTTP 403 Forbidden",
        validation_status=ValidationStatus.VALIDATED,
    )


@pytest.fixture
def sample_unvalidated_evidence() -> SecurityEvidence:
    return SecurityEvidence(
        evidence_id="evi_orch_002",
        evidence_type=EvidenceType.STATUS_MISMATCH,
        description="Status code discrepancy observed without baseline hash",
        source_component="Scanner",
        affected_endpoint="/rest/basket/3",
        http_method="GET",
        observed_behavior="HTTP 200 OK",
        expected_behavior="HTTP 403 Forbidden",
        validation_status=ValidationStatus.UNVALIDATED,
    )


@pytest.fixture
def sample_affected_resource() -> AffectedResource:
    return AffectedResource(
        resource_id="res_orch_001",
        resource_type="API_ENDPOINT",
        endpoint="/rest/basket/2",
        application_name="OWASP Juice Shop",
    )


@pytest.fixture
def sample_analysis_input(sample_validated_evidence, sample_affected_resource) -> FindingAnalysisInput:
    val_meta = EvidenceValidation(
        is_validated=True,
        validation_method=ValidationMethod.DIFFERENTIAL_ANALYSIS,
        validation_status=ValidationStatus.VALIDATED,
        validation_notes="Verified via differential replay.",
        supporting_evidence_ids=["evi_orch_001"],
    )
    return FindingAnalysisInput(
        finding_id="fnd_orch_001",
        vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
        security_evidence=[sample_validated_evidence],
        affected_resource=sample_affected_resource,
        user_role_context="user_a",
        testing_context={"framework": "express", "tool": "AuthScopeDifferential"},
        evidence_validation=val_meta,
    )


def make_mock_claude_response(content_dict: dict) -> MagicMock:
    """Helper creating a mock Anthropic Messages API response object."""
    mock_resp = MagicMock()
    mock_block = MagicMock()
    mock_block.type = "text"
    mock_block.text = json.dumps(content_dict, default=str)
    mock_resp.content = [mock_block]
    return mock_resp


# ==============================================================================
# Test Class 1: Agent Initialization & Configuration
# ==============================================================================


@pytest.mark.unit
class TestAgentInitialization:
    """Verifies agent instantiation, environment variable loading, and secret safety."""

    def test_default_initialization_without_key_operates_in_fallback_mode(self):
        """When no key is configured, agent initializes safely in deterministic mode."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=True):
            agent = AuthScopeAgent(api_key=None)
            assert agent.client is None
            assert "configured=False" in repr(agent)

    def test_initialization_with_custom_env_vars(self):
        """Verifies ANTHROPIC_MODEL, ANTHROPIC_MAX_TOKENS, and ANTHROPIC_TIMEOUT are respected."""
        env_vars = {
            "ANTHROPIC_API_KEY": "test-key-12345",
            "ANTHROPIC_MODEL": "claude-3-opus-20240229",
            "ANTHROPIC_MAX_TOKENS": "4096",
            "ANTHROPIC_TIMEOUT": "45.5",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            with patch("backend.agent.agent.Anthropic") as mock_anthropic_cls:
                mock_anthropic_cls.return_value = MagicMock()
                agent = AuthScopeAgent()
                assert agent.model == "claude-3-opus-20240229"
                assert agent.max_tokens == 4096
                assert agent.timeout == 45.5
                assert agent.api_key == "test-key-12345"
                mock_anthropic_cls.assert_called_once_with(api_key="test-key-12345", timeout=45.5)

    def test_repr_does_not_leak_raw_api_key(self):
        """Ensures __repr__ never leaks secret credentials."""
        mock_client = MagicMock()
        agent = AuthScopeAgent(client=mock_client, api_key="sk-ant-live-super-secret-key-999")
        rep = repr(agent)
        assert "super-secret" not in rep
        assert "sk-ant" not in rep
        assert "configured=True" in rep

    def test_backward_compatibility_run_scan_loop(self):
        """Verifies scaffolded run_scan_loop method functions for interface compatibility."""
        agent = AuthScopeAgent()
        result = agent.run_scan_loop("Scan target localhost:3000")
        assert result["status"] == "INITIALIZED"
        assert "Phase 5" in result["message"]


# ==============================================================================
# Test Class 2: Claude Messages API Calling & Error Resilience
# ==============================================================================


@pytest.mark.unit
class TestClaudeAPICalling:
    """Verifies API communication, retry logic, and typed exception handling."""

    def test_call_claude_success_with_mock_client(self):
        """Verifies clean message dispatch and text retrieval."""
        mock_client = MagicMock()
        mock_client.messages.create.return_value = make_mock_claude_response({"status": "ok"})

        agent = AuthScopeAgent(client=mock_client)
        resp = agent.call_claude(system_prompt="sys", user_prompt="usr")
        assert '{"status": "ok"}' in resp
        mock_client.messages.create.assert_called_once()

    def test_call_claude_raises_configuration_error_when_client_missing(self):
        """When client is None, call_claude raises AgentConfigurationError."""
        agent = AuthScopeAgent(client=None, api_key=None)
        agent.client = None
        with pytest.raises(AgentConfigurationError) as exc_info:
            agent.call_claude(system_prompt="sys", user_prompt="usr")
        assert "ANTHROPIC_API_KEY" in str(exc_info.value)

    def test_authentication_error_fails_immediately_without_retry(self):
        """AuthenticationError must not be retried and raises AgentAuthenticationError."""
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = AuthenticationError(
            message="Invalid API Key",
            response=MagicMock(status_code=401),
            body={"error": {"type": "authentication_error", "message": "Invalid API Key"}}
        )

        agent = AuthScopeAgent(client=mock_client, max_retries=3)
        with pytest.raises(AgentAuthenticationError) as exc_info:
            agent.call_claude(system_prompt="sys", user_prompt="usr")

        assert "authentication failed" in str(exc_info.value).lower()
        assert mock_client.messages.create.call_count == 1

    def test_rate_limit_error_retries_and_succeeds(self):
        """RateLimitError is retried with backoff and succeeds on subsequent try."""
        mock_client = MagicMock()
        mock_response = make_mock_claude_response({"result": "success_after_retry"})
        rate_err = RateLimitError(
            message="Rate limit exceeded",
            response=MagicMock(status_code=429),
            body={"error": {"type": "rate_limit_error"}}
        )

        mock_client.messages.create.side_effect = [rate_err, rate_err, mock_response]

        agent = AuthScopeAgent(client=mock_client, max_retries=3, retry_delay=0.01)
        resp = agent.call_claude(system_prompt="sys", user_prompt="usr")
        assert "success_after_retry" in resp
        assert mock_client.messages.create.call_count == 3

    def test_timeout_error_exhausts_retries_and_raises_agent_api_error(self):
        """APITimeoutError exhausts max_retries and raises AgentAPIError."""
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = APITimeoutError(request=MagicMock())

        agent = AuthScopeAgent(client=mock_client, max_retries=3, retry_delay=0.01)
        with pytest.raises(AgentAPIError) as exc_info:
            agent.call_claude(system_prompt="sys", user_prompt="usr")

        assert "3 attempts" in str(exc_info.value)
        assert mock_client.messages.create.call_count == 3

    def test_empty_response_raises_validation_error(self):
        """Empty response text raises AgentValidationError."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.content = []
        mock_client.messages.create.return_value = mock_resp

        agent = AuthScopeAgent(client=mock_client)
        with pytest.raises(AgentValidationError):
            agent.call_claude(system_prompt="sys", user_prompt="usr")


# ==============================================================================
# Test Class 3: 8-Step Finding Analysis Pipeline
# ==============================================================================


@pytest.mark.unit
class TestAgentWorkflowEndToEnd:
    """Verifies the complete 8-step cognitive analysis workflow."""

    def test_end_to_end_analysis_with_mock_claude(self, sample_analysis_input):
        """Tests successful end-to-end execution of all 8 steps with Claude response."""
        claude_analysis_json = {
            "title": "Broken Object Level Authorization in Basket Endpoint",
            "vulnerability_explanation": "The endpoint accepts client-provided basket IDs and queries SQLite directly without comparing session user_id against basket owner.",
            "technical_root_cause": "Absence of resource authorization check in BasketController",
            "affected_resources": [sample_analysis_input.affected_resource.model_dump(mode="json")],
            "potential_impact": "Unauthorized horizontal access to confidential shopping cart contents and customer PII",
            "supporting_evidence": [sample_analysis_input.security_evidence[0].model_dump(mode="json")],
            "confidence_level": "HIGH",
            "confirmation_status": "CONFIRMED",
            "limitations_and_missing_info": [],
        }

        mock_client = MagicMock()
        mock_client.messages.create.return_value = make_mock_claude_response(claude_analysis_json)

        agent = AuthScopeAgent(client=mock_client)
        output: FindingAnalysisOutput = agent.analyze_finding(sample_analysis_input, target_framework="express")

        # Step 7 & 8: Validate FindingAnalysisOutput structure
        assert isinstance(output, FindingAnalysisOutput)
        assert output.overall_status == AnalysisStatus.COMPLETED
        assert output.analysis.title == "Broken Object Level Authorization in Basket Endpoint"
        assert output.analysis.confirmation_status == ConfirmationStatus.CONFIRMED

        # Severity Engine output verification (Step 5)
        assert output.severity_assessment.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL, SeverityLevel.MEDIUM)
        assert "Deterministic Risk Score" in output.severity_assessment.severity_rationale

        # Remediation Engine output verification (Step 6)
        assert len(output.remediation_recommendation.recommended_fix) >= 10
        assert len(output.remediation_recommendation.server_side_controls) >= 1
        assert len(output.remediation_recommendation.technical_implementation_guidance) >= 10

        # Evidence references verification
        assert "evi_orch_001" in output.evidence_references

    def test_analyze_finding_json_returns_valid_json_string(self, sample_analysis_input):
        """Verifies analyze_finding_json serialization output."""
        agent = AuthScopeAgent(client=None)  # Use deterministic mode
        json_str = agent.analyze_finding_json(sample_analysis_input)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert "analysis" in parsed
        assert "severity_assessment" in parsed
        assert "remediation_recommendation" in parsed
        assert "evidence_references" in parsed

    def test_analyze_finding_dict_returns_dictionary(self, sample_analysis_input):
        """Verifies analyze_finding_dict dictionary output."""
        agent = AuthScopeAgent(client=None)
        res_dict = agent.analyze_finding_dict(sample_analysis_input)
        assert isinstance(res_dict, dict)
        assert res_dict["overall_status"] in ("completed", AnalysisStatus.COMPLETED)


# ==============================================================================
# Test Class 4: Anti-Upgrade Guardrail & Security Constraints
# ==============================================================================


@pytest.mark.unit
class TestAntiUpgradeGuardrail:
    """Verifies that unvalidated findings CANNOT be upgraded to CONFIRMED."""

    def test_unvalidated_evidence_cannot_be_upgraded_by_claude(
        self, sample_unvalidated_evidence, sample_affected_resource
    ):
        """Even if Claude attempts to mark an unvalidated finding CONFIRMED, the agent enforces SUSPECTED."""
        val_meta = EvidenceValidation(
            is_validated=False,
            validation_method=ValidationMethod.STATUS_CODE_ASSERTION,
            validation_status=ValidationStatus.UNVALIDATED,
            validation_notes="Raw unverified scanner observation.",
            supporting_evidence_ids=["evi_orch_002"],
        )
        input_data = FindingAnalysisInput(
            finding_id="fnd_orch_unvalidated",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[sample_unvalidated_evidence],
            affected_resource=sample_affected_resource,
            evidence_validation=val_meta,
        )

        # Mock Claude claiming CONFIRMED on unvalidated evidence
        claude_hallucination = {
            "title": "Unvalidated IDOR Flaw",
            "vulnerability_explanation": "Claiming exploit without baseline proof.",
            "technical_root_cause": "Missing access validation",
            "affected_resources": [sample_affected_resource.model_dump(mode="json")],
            "potential_impact": "Unauthorized horizontal access to records",
            "supporting_evidence": [sample_unvalidated_evidence.model_dump(mode="json")],
            "confidence_level": "HIGH",
            "confirmation_status": "CONFIRMED",  # Illegal upgrade attempt!
            "limitations_and_missing_info": [],
        }

        mock_client = MagicMock()
        mock_client.messages.create.return_value = make_mock_claude_response(claude_hallucination)

        agent = AuthScopeAgent(client=mock_client)
        output = agent.analyze_finding(input_data)

        # Strict security rule: Confirmation MUST remain SUSPECTED
        assert output.analysis.confirmation_status == ConfirmationStatus.SUSPECTED
        assert output.analysis.confirmation_status != ConfirmationStatus.CONFIRMED


# ==============================================================================
# Test Class 5: Resilience, Fallback & Input Adaptation
# ==============================================================================


@pytest.mark.unit
class TestResilienceAndFallback:
    """Verifies graceful degradation when Claude fails or returns malformed outputs."""

    def test_offline_mode_executes_pure_deterministic_pipeline(self, sample_analysis_input):
        """When no API key is present, agent completes full analysis via deterministic engines."""
        agent = AuthScopeAgent(client=None, api_key=None)
        agent.client = None

        output = agent.analyze_finding(sample_analysis_input)
        assert output.overall_status == AnalysisStatus.COMPLETED
        assert output.analysis.title != ""
        assert output.severity_assessment.severity in SeverityLevel
        assert "Operating in deterministic fallback mode" in " ".join(output.warnings_or_limitations)

    def test_malformed_json_from_claude_falls_back_deterministically(self, sample_analysis_input):
        """When Claude returns invalid JSON, agent falls back to deterministic synthesis without crashing."""
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_block = MagicMock()
        mock_block.type = "text"
        mock_block.text = "This is NOT valid JSON: { broken syntax here..."
        mock_resp.content = [mock_block]
        mock_client.messages.create.return_value = mock_resp

        agent = AuthScopeAgent(client=mock_client)
        output = agent.analyze_finding(sample_analysis_input)

        # Ensure pipeline succeeded safely
        assert output.overall_status == AnalysisStatus.COMPLETED
        assert output.analysis.title != ""

    def test_legacy_dictionary_input_adapted_automatically(self):
        """Verifies backward compatibility with legacy dictionary input structures."""
        legacy_input = {
            "raw_evidence": {
                "endpoint": "/rest/basket/5",
                "method": "GET",
                "description": "Legacy basket access discrepancy",
                "observed": "Status 200 with basket items",
                "expected": "Status 403 Forbidden",
            }
        }

        agent = AuthScopeAgent(client=None)
        output = agent.analyze_finding(legacy_input)
        assert output.overall_status == AnalysisStatus.COMPLETED
        assert "/rest/basket/5" in output.analysis.affected_resources[0].endpoint

    def test_invalid_input_type_raises_validation_error(self):
        """Passing completely invalid data type raises AgentValidationError."""
        agent = AuthScopeAgent()
        with pytest.raises(AgentValidationError):
            agent.analyze_finding(12345)  # type: ignore
