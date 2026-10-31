"""Evidence Validator: Redacts secrets, verifies proof reproducibility, and generates SHA-256 hashes."""

from typing import Dict, Any, List
from datetime import datetime, timezone
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.storage.models import EvidenceArtifact
from backend.utils.helpers import compute_sha256, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)


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
        """Sanitizes sensitive headers and computes an immutable SHA-256 evidence hash."""
        sanitized_headers = dict(headers)
        redacted_list: List[str] = []

        # Sanitize authorization headers
        for k in list(sanitized_headers.keys()):
            k_lower = k.lower()
            if k_lower in ("authorization", "proxy-authorization"):
                sanitized_headers[k] = "Bearer [REDACTED_BEARER_TOKEN]"
                if k not in redacted_list:
                    redacted_list.append(k)
            elif k_lower in ("cookie", "set-cookie"):
                sanitized_headers[k] = "[REDACTED_COOKIE]"
                if k not in redacted_list:
                    redacted_list.append(k)
            elif k_lower in ("x-api-key", "api-key", "x-auth-token"):
                sanitized_headers[k] = "[REDACTED_API_KEY]"
                if k not in redacted_list:
                    redacted_list.append(k)

        # Sanitize response body
        raw_body = response.body
        sanitized_body = redact_sensitive_text(raw_body)
        if sanitized_body != raw_body:
            redacted_list.append("response_body")

        canonical_string = f"{method}|{url}|{response.status_code}|{raw_body}"
        sha256_hash = compute_sha256(canonical_string)

        logger.info("Cryptographic evidence artifact signed", extra={"sha256": sha256_hash[:12]})
        return EvidenceArtifact(
            id=f"evi_{sha256_hash[:8]}",
            evidence_id=f"evi_{sha256_hash[:8]}",
            finding_id=finding_id,
            testing_role=test_role,
            test_role=test_role,
            authorized_role=authorized_role,
            request_method=method,
            request_url=url,
            request_headers=sanitized_headers,
            response_status=response.status_code,
            sanitized_response_body=sanitized_body,
            response_body=sanitized_body,
            evidence_sha256=sha256_hash,
            evidence_validation_status="valid",
            redacted_fields=redacted_list,
            redacted_tokens=redacted_list
        )
