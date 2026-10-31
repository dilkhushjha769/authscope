"""Custom exceptions and common helper routines for AuthScope."""

from typing import Any, Dict
import hashlib
import json
import re


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


class StorageError(AuthScopeException):
    """Base exception for storage and persistence layer errors."""
    pass


class RecordNotFoundError(StorageError):
    """Raised when a requested database record is not found."""
    pass


class DuplicateRecordError(StorageError):
    """Raised when an attempt is made to insert a record with an existing unique ID."""
    pass


class InvalidDataError(StorageError):
    """Raised when data fails validation or violates storage constraints."""
    pass


def compute_sha256(data: str | bytes) -> str:
    """Compute SHA-256 hexadecimal hash string for data verification."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.+/=]*")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.=~+/]+")
_COOKIE_PATTERN = re.compile(r"(?i)\b(connect\.sid|sessionid|session_id|jwt|token|PHPSESSID)=([^;\s&\"']+)")
_JSON_SECRET_PATTERN = re.compile(
    r'("(?i:(?:password|access_token|refresh_token|secret|api_key|apikey|auth_token|authorization|token))"\s*:\s*)"(?:[^"\\]|\\.)*"'
)
_QUERY_SECRET_PATTERN = re.compile(
    r'(?i)\b(password|access_token|secret|api_key|apikey|auth_token)=([^&\s"\']+)'
)
_PROSE_PASSWORD_PATTERN = re.compile(
    r'(?i)\b(password|passwd|pwd)\s*[:= ]\s*([^\s,;"\'\]}]+)'
)


def redact_sensitive_text(text: str) -> str:
    """Redact tokens, bearer strings, passwords, cookies, and credential patterns.

    Enforces Enforcement Point 4 (Data Redaction) across strings and JSON payloads.
    """
    if not text:
        return text

    sanitized = _BEARER_PATTERN.sub("Bearer [REDACTED_BEARER_TOKEN]", text)
    sanitized = _JWT_PATTERN.sub("[REDACTED_JWT]", sanitized)
    sanitized = _JSON_SECRET_PATTERN.sub(r'\1"[REDACTED_SECRET]"', sanitized)
    sanitized = _QUERY_SECRET_PATTERN.sub(r'\1=[REDACTED_SECRET]', sanitized)
    sanitized = _COOKIE_PATTERN.sub(r'\1=[REDACTED_COOKIE]', sanitized)
    sanitized = _PROSE_PASSWORD_PATTERN.sub(r'\1 [REDACTED_PASSWORD]', sanitized)
    return sanitized
