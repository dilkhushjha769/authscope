"""Custom exceptions and common helper routines for AuthScope."""

from typing import Any, Dict
import hashlib
import json


class AuthScopeException(Exception):
    """Base exception for all AuthScope errors."""
    pass


class ScopeViolationError(AuthScopeException):
    """Raised when an out-of-scope or unpermitted network target is requested."""
    pass


class TargetUnreachableError(AuthScopeException):
    """Raised when the target web application fails to respond."""
    pass


class SessionAuthenticationError(AuthScopeException):
    """Raised when persona authentication fails against the target."""
    pass


class EvidenceValidationError(AuthScopeException):
    """Raised when raw test evidence cannot be verified or normalized."""
    pass


def compute_sha256(data: str | bytes) -> str:
    """Compute SHA-256 hexadecimal hash string for data verification."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def redact_sensitive_text(text: str) -> str:
    """Redact tokens, bearer strings, and common credential patterns.

    TODO (Phase 6): Expand regex patterns to automatically scrub JWTs and passwords.
    """
    # Basic baseline redaction placeholder
    # Full implementation planned for Phase 6 Evidence Validator
    return text

