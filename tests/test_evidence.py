"""Unit tests for EvidenceValidator, secret redaction, completeness checks, and SHA-256 signing."""

import pytest
from backend.analysis.evidence_validator import (
    EvidenceValidationStatus,
    EvidenceValidator,
)
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.utils.helpers import compute_sha256, EvidenceValidationError


@pytest.mark.unit
class TestEvidenceValidation:
    """Verifies evidence sanitization, required fields, and cryptographic hashing."""

    def test_evidence_sanitizes_bearer_tokens_and_cookies(self):
        """Ensures Authorization Bearer tokens and cookies are redacted prior to artifact creation."""
        validator = EvidenceValidator()
        response = HttpResponseModel(status_code=200, body='{"status":"ok"}')

        raw_headers = {
            "Authorization": "Bearer sensitive_secret_jwt_token_12345",
            "Cookie": "session_id=secret_cookie_999",
        }
        artifact = validator.create_and_sign_evidence(
            finding_id="fnd_123",
            test_role=Role.USER_B,
            authorized_role=Role.USER_A,
            method="GET",
            url="http://localhost:3000/rest/basket/1",
            headers=raw_headers,
            response=response,
            endpoint="/rest/basket/{id}",
            resource_id="1",
            expected_behavior="HTTP 403 Forbidden",
            actual_behavior="HTTP 200 OK with basket data",
            validation_status=EvidenceValidationStatus.CONFIRMED,
        )

        assert artifact.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"
        assert artifact.request_headers["Cookie"] == "[REDACTED_COOKIE]"
        assert "sensitive_secret_jwt_token" not in str(artifact.request_headers)
        assert "secret_cookie_999" not in str(artifact.request_headers)
        assert "Authorization" in artifact.redacted_tokens
        assert "Cookie" in artifact.redacted_tokens
        assert artifact.endpoint == "/rest/basket/{id}"
        assert artifact.resource_id == "1"
        assert artifact.validation_status == EvidenceValidationStatus.CONFIRMED
        assert validator.validate_artifact_completeness(artifact) is True

    def test_evidence_redacts_jwts_and_secrets_in_response_body(self):
        """Ensures JWTs and password/totpSecret fields inside response bodies are scrubbed."""
        validator = EvidenceValidator()
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        raw_body = f'{{"data": {{"id": 1, "password": "my_hashed_password_123", "token": "{fake_jwt}"}}}}'
        response = HttpResponseModel(status_code=200, body=raw_body)

        artifact = validator.create_and_sign_evidence(
            finding_id="fnd_body_redact",
            test_role=Role.USER_B,
            authorized_role=Role.USER_A,
            method="GET",
            url="http://localhost:3000/api/Users/1",
            headers={},
            response=response,
            endpoint="/api/Users/{id}",
            resource_id="1",
        )

        assert fake_jwt not in artifact.sanitized_response_evidence
        assert "my_hashed_password_123" not in artifact.sanitized_response_evidence
        assert "[REDACTED" in artifact.sanitized_response_evidence
        assert validator.validate_artifact_completeness(artifact) is True

    def test_evidence_completeness_rejects_non_2xx_confirmed_claim(self):
        """Ensures a 403 Denied response cannot be marked as CONFIRMED evidence."""
        validator = EvidenceValidator()
        denied_response = HttpResponseModel(status_code=403, body='{"error": "Forbidden"}')

        artifact = validator.create_and_sign_evidence(
            finding_id="fnd_invalid",
            test_role=Role.USER_B,
            authorized_role=Role.USER_A,
            method="GET",
            url="http://localhost:3000/rest/basket/1",
            headers={},
            response=denied_response,
            validation_status=EvidenceValidationStatus.CONFIRMED,
        )

        assert validator.validate_artifact_completeness(artifact) is False

    def test_evidence_sha256_reproducibility(self):
        """Ensures cryptographic hash generation is deterministic."""
        canonical_input = "GET|http://localhost:3000/rest/basket/1|200|{\"data\": 1}"
        hash1 = compute_sha256(canonical_input)
        hash2 = compute_sha256(canonical_input)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_missing_required_arguments_raises_error(self):
        """Verifies EvidenceValidationError is raised if mandatory identifiers are empty."""
        validator = EvidenceValidator()
        response = HttpResponseModel(status_code=200, body="{}")
        with pytest.raises(EvidenceValidationError):
            validator.create_and_sign_evidence(
                finding_id="",
                test_role=Role.USER_B,
                authorized_role=Role.USER_A,
                method="GET",
                url="",
                headers={},
                response=response,
            )
