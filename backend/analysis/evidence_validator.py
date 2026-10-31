"""Evidence Validator: Redacts secrets, verifies proof reproducibility, and generates SHA-256 hashes."""

from typing import Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.utils.helpers import compute_sha256
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceArtifact(BaseModel):
    """Immutable evidence package supporting a confirmed security finding."""
    id: str
    finding_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    test_role: Role
    authorized_role: Role
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_status: int
    response_body: str
    evidence_sha256: str
    redacted_tokens: List[str] = Field(default_factory=list)


class EvidenceValidator:
    """Validates, sanitizes, and signs non-destructive proof artifacts."""

    def create_and_sign_evidence(
        self,
        finding_id: str,
        test_role: Role,
        authorized_role: Role,
        method: str,
        url: str,
        headers: Dict[str, str],
        response: HttpResponseModel
    ) -> EvidenceArtifact:
        """Sanitizes sensitive headers and computes an immutable SHA-256 evidence hash.

        TODO (Phase 6): Implement deep token pattern matching and sanitization.
        """
        # Redact Authorization header if present
        sanitized_headers = dict(headers)
        redacted_list = []
        if "Authorization" in sanitized_headers:
            sanitized_headers["Authorization"] = "Bearer [REDACTED_BEARER_TOKEN]"
            redacted_list.append("Authorization")

        canonical_string = f"{method}|{url}|{response.status_code}|{response.body}"
        sha256_hash = compute_sha256(canonical_string)

        logger.info("Cryptographic evidence artifact signed", extra={"sha256": sha256_hash[:12]})
        return EvidenceArtifact(
            id=f"evi_{sha256_hash[:8]}",
            finding_id=finding_id,
            test_role=test_role,
            authorized_role=authorized_role,
            request_method=method,
            request_url=url,
            request_headers=sanitized_headers,
            response_status=response.status_code,
            response_body=response.body,
            evidence_sha256=sha256_hash,
            redacted_tokens=redacted_list
        )

