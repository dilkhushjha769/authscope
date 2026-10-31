"""Custom exceptions and common helper routines for AuthScope."""

from typing import Any, Dict
import hashlib
import re


class AuthScopeException(Exception):
    """Base exception for all AuthScope errors."""
    pass


class ScopeViolationError(AuthScopeException):
    """Raised when an out-of-scope or unpermitted network target is requested."""
    pass


class UnsupportedMethodError(ScopeViolationError):
    """Raised when an HTTP method outside the allowed initial list is requested."""
    pass


class InvalidTargetURLError(ScopeViolationError):
    """Raised when a URL is malformed, ambiguous, or contains prohibited syntax."""
    pass


class HumanApprovalRequiredError(ScopeViolationError):
    """Raised when expanding test scope or executing sensitive actions without operator approval."""
    pass


class TargetUnreachableError(AuthScopeException):
    """Raised when the target web application fails to respond or times out."""
    pass


class SessionAuthenticationError(AuthScopeException):
    """Raised when persona authentication fails against the target."""
    pass


class MissingSessionError(AuthScopeException):
    """Raised when a requested role session is unconfigured or not found."""
    pass


class EvidenceValidationError(AuthScopeException):
    """Raised when raw test evidence cannot be verified or normalized."""
    pass


def compute_sha256(data: str | bytes) -> str:
    """Compute SHA-256 hexadecimal hash string for data verification."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sanitize_headers_for_logging(headers: Dict[str, Any]) -> Dict[str, str]:
    """Sanitize and redact authorization tokens, cookies, and sensitive headers for logging.

    Never logs or persists raw authentication tokens or cookies.
    """
    sanitized: Dict[str, str] = {}
    sensitive_keys = {"authorization", "cookie", "set-cookie", "x-api-key", "token", "jwt", "session"}

    for key, value in headers.items():
        key_str = str(key)
        val_str = str(value)
        if key_str.lower() in sensitive_keys:
            if "bearer" in val_str.lower():
                sanitized[key_str] = "Bearer [REDACTED_TOKEN]"
            else:
                sanitized[key_str] = "[REDACTED]"
        else:
            sanitized[key_str] = val_str
    return sanitized
