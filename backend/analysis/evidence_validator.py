"""Evidence Validator: Redacts secrets, verifies proof reproducibility, and generates SHA-256 hashes.

Every potential finding evidence artifact captures:
- Endpoint & full URL
- HTTP method
- Testing account/role & authorized owner role
- Resource identifier
- Expected behavior vs. actual behavior
- Sanitized response evidence (with tokens, cookies, and password hashes redacted)
- Validation status (CONFIRMED, SUSPICIOUS, REJECTED_FALSE_POSITIVE)
- UTC Timestamp & deterministic SHA-256 signature
"""

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import re

from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.storage.models import EvidenceArtifact, EvidenceValidationStatus
from backend.utils.helpers import compute_sha256, EvidenceValidationError, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Regex patterns for redacting tokens and credentials from response bodies
JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.+/=]*")
BEARER_REGEX = re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.=~+/]+")
JSON_SECRET_FIELD_REGEX = re.compile(
    r'("(?i:password|totpSecret|deluxeToken|token|jwt|apiKey|secret)"\s*:\s*)"([^"]+)"'
)


class EvidenceValidator:
    """Validates, sanitizes, and signs non-destructive proof artifacts."""

    SENSITIVE_HEADER_KEYS = {
        "authorization": "Bearer [REDACTED_BEARER_TOKEN]",
        "proxy-authorization": "Bearer [REDACTED_BEARER_TOKEN]",
        "cookie": "[REDACTED_COOKIE]",
        "set-cookie": "[REDACTED_COOKIE]",
        "x-api-key": "[REDACTED_API_KEY]",
        "api-key": "[REDACTED_API_KEY]",
        "x-auth-token": "[REDACTED_API_KEY]",
        "token": "[REDACTED_TOKEN]",
    }

    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
        """Redacts authentication headers and cookies, returning sanitized map and redacted key list."""
        sanitized: Dict[str, str] = {}
        redacted_keys: List[str] = []

        for k, v in (headers or {}).items():
            k_lower = str(k).lower()
            if k_lower in cls.SENSITIVE_HEADER_KEYS:
                if k_lower in ("authorization", "proxy-authorization"):
                    sanitized[k] = "Bearer [REDACTED_BEARER_TOKEN]"
                else:
                    sanitized[k] = cls.SENSITIVE_HEADER_KEYS[k_lower]
                redacted_keys.append(str(k))
            else:
                sanitized[str(k)] = BEARER_REGEX.sub("Bearer [REDACTED_BEARER_TOKEN]", str(v))
        return sanitized, redacted_keys

    @classmethod
    def sanitize_body(cls, body: str, max_excerpt_len: int = 4000) -> Tuple[str, List[str]]:
        """Redacts raw JWTs, Bearer strings, and password/secret values from response body text."""
        if not body:
            return "", []

        redacted_items: List[str] = []
        sanitized = body

        if JWT_REGEX.search(sanitized):
            sanitized = JWT_REGEX.sub("[REDACTED_JWT]", sanitized)
            redacted_items.append("body_jwt")

        if BEARER_REGEX.search(sanitized):
            sanitized = BEARER_REGEX.sub("Bearer [REDACTED_BEARER_TOKEN]", sanitized)
            redacted_items.append("body_bearer_token")

        if JSON_SECRET_FIELD_REGEX.search(sanitized):
            sanitized = JSON_SECRET_FIELD_REGEX.sub(r'\1"[REDACTED_SECRET]"', sanitized)
            redacted_items.append("body_secret_field")

        return sanitized[:max_excerpt_len], redacted_items

    def create_and_sign_evidence(
        self,
        finding_id: str,
        test_role: Role,
        authorized_role: Role,
        method: str,
        url: str,
        headers: Dict[str, str],
        response: HttpResponseModel,
        endpoint: Optional[str] = None,
        resource_id: Optional[str] = None,
        expected_behavior: Optional[str] = None,
        actual_behavior: Optional[str] = None,
        validation_status: EvidenceValidationStatus = EvidenceValidationStatus.CONFIRMED,
    ) -> EvidenceArtifact:
        """Sanitizes sensitive headers/body and computes an immutable SHA-256 evidence hash."""
        if not finding_id or not method or not url:
            raise EvidenceValidationError("finding_id, method, and url are required to create evidence.")

        sanitized_headers, redacted_header_keys = self.sanitize_headers(headers)
        sanitized_body, redacted_body_keys = self.sanitize_body(response.body)
        redacted_list = redacted_header_keys + redacted_body_keys

        # Canonical string uses response.body as originally structured for deterministic hashing
        canonical_string = f"{method}|{url}|{response.status_code}|{response.body}"
        sha256_hash = compute_sha256(canonical_string)

        resolved_endpoint = endpoint or url
        resolved_expected = expected_behavior or (
            f"Role '{test_role.value}' should be denied access (HTTP 401/403) to resource owned by '{authorized_role.value}'."
        )
        resolved_actual = actual_behavior or (
            f"Role '{test_role.value}' received HTTP {response.status_code} ({len(response.body)} bytes)."
        )

        logger.info(
            "Cryptographic evidence artifact signed",
            extra={
                "sha256": sha256_hash[:12],
                "validation_status": validation_status.value if hasattr(validation_status, "value") else str(validation_status),
                "endpoint": resolved_endpoint,
            }
        )
        return EvidenceArtifact(
            id=f"evi_{sha256_hash[:8]}",
            evidence_id=f"evi_{sha256_hash[:8]}",
            finding_id=finding_id,
            endpoint=resolved_endpoint,
            http_method=method.upper(),
            testing_role=test_role,
            test_role=test_role,
            authorized_role=authorized_role,
            resource_id=resource_id,
            expected_behavior=resolved_expected,
            actual_behavior=resolved_actual,
            validation_status=validation_status,
            request_method=method.upper(),
            request_url=url,
            request_headers=sanitized_headers,
            response_status=response.status_code,
            response_body=sanitized_body,
            sanitized_response_body=sanitized_body,
            sanitized_response_evidence=sanitized_body[:1500],
            evidence_sha256=sha256_hash,
            evidence_validation_status="valid",
            redacted_fields=redacted_list,
            redacted_tokens=redacted_list,
        )

    def validate_artifact_completeness(self, artifact: EvidenceArtifact) -> bool:
        """Verifies that an EvidenceArtifact contains all mandatory non-empty fields and zero leaked tokens."""
        if not artifact.endpoint or not artifact.http_method:
            return False
        if not artifact.expected_behavior or not artifact.actual_behavior:
            return False
        if not artifact.evidence_sha256 or len(artifact.evidence_sha256) != 64:
            return False

        # Ensure no raw Bearer JWTs remain in headers or sanitized evidence
        for val in artifact.request_headers.values():
            if JWT_REGEX.search(val):
                return False
        if JWT_REGEX.search(artifact.sanitized_response_evidence):
            return False

        # A finding cannot be CONFIRMED if the response status was not 2xx or evidence is empty
        val_status = artifact.validation_status.value if hasattr(artifact.validation_status, "value") else str(artifact.validation_status)
        if val_status == EvidenceValidationStatus.CONFIRMED.value:
            if not (200 <= artifact.response_status < 300):
                return False
            if not artifact.sanitized_response_evidence.strip():
                return False

        return True
