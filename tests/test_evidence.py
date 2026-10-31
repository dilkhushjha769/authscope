"""Unit tests for EvidenceValidator, secret redaction, and SHA-256 signing."""

import pytest
from backend.analysis.evidence_validator import EvidenceValidator
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.utils.helpers import compute_sha256


@pytest.mark.unit
class TestEvidenceValidation:
    """Verifies evidence sanitization and cryptographic hashing."""

    def test_evidence_sanitizes_bearer_tokens(self):
        """Ensures Authorization Bearer tokens are redacted prior to artifact creation."""
        validator = EvidenceValidator()
        response = HttpResponseModel(status_code=200, body='{"status":"ok"}')

        raw_headers = {"Authorization": "Bearer sensitive_secret_jwt_token_12345"}
        artifact = validator.create_and_sign_evidence(
            finding_id="fnd_123",
            test_role=Role.USER_B,
            authorized_role=Role.USER_A,
            method="GET",
            url="http://localhost:3000/rest/basket/1",
            headers=raw_headers,
            response=response
        )

        assert artifact.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"
        assert "sensitive_secret_jwt_token" not in artifact.request_headers["Authorization"]
        assert "Authorization" in artifact.redacted_tokens

    def test_evidence_sha256_reproducibility(self):
        """Ensures cryptographic hash generation is deterministic."""
        canonical_input = "GET|http://localhost:3000/rest/basket/1|200|{\"data\": 1}"
        hash1 = compute_sha256(canonical_input)
        hash2 = compute_sha256(canonical_input)

        assert hash1 == hash2
        assert len(hash1) == 64

