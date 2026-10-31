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


_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-\.+/=]*")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.=~+/]+")
_BASIC_AUTH_PATTERN = re.compile(r"(?i)\bbasic\s+[a-zA-Z0-9+/=]{8,}")
_COOKIE_PATTERN = re.compile(r"(?i)\b(connect\.sid|sessionid|session_id|jwt|token|PHPSESSID)=([^;\s&\"']+)")
_JSON_SECRET_PATTERN = re.compile(
    r'("(?i:[a-zA-Z0-9_\-]*(?:password|passwd|secret|token|api_key|apikey|auth_token|authorization|credential|privkey|private_key)[a-zA-Z0-9_\-]*)"\s*:\s*)"(?:[^"\\]|\\.)*"'
)
_QUERY_SECRET_PATTERN = re.compile(
    r'(?i)([?&;](?:password|passwd|access_token|refresh_token|token|jwt|session_id|sessionid|sid|secret|api_key|apikey|auth_token|cookie)=)([^&\s"\']+)'
)
_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PROSE_PASSWORD_PATTERN = re.compile(
    r'(?i)\b(password|passwd|pwd)\s*[:= ]\s*([^\s,;"\'\]}]+)'
)

_SENSITIVE_KEY_NAMES = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "secret", "api_key", "apikey", "auth_token", "authorization", "cookie"
}


def redact_sensitive_text(text: str) -> str:
    """Redact tokens, bearer strings, passwords, cookies, and credential patterns.

    Enforces Enforcement Point 4 (Data Redaction) across strings and JSON payloads.
    """
    if not text:
        return text

    sanitized = _BEARER_PATTERN.sub("Bearer [REDACTED_BEARER_TOKEN]", text)
    sanitized = _BASIC_AUTH_PATTERN.sub("Basic [REDACTED_BASIC_AUTH]", sanitized)
    sanitized = _JWT_PATTERN.sub("[REDACTED_JWT]", sanitized)
    sanitized = _JSON_SECRET_PATTERN.sub(r'\1"[REDACTED_SECRET]"', sanitized)
    sanitized = _QUERY_SECRET_PATTERN.sub(r'\1[REDACTED_SECRET]', sanitized)
    sanitized = _COOKIE_PATTERN.sub(r'\1=[REDACTED_COOKIE]', sanitized)
    sanitized = _PROSE_PASSWORD_PATTERN.sub(r'\1 [REDACTED_PASSWORD]', sanitized)
    sanitized = _EMAIL_PATTERN.sub("[REDACTED_EMAIL]", sanitized)
    return sanitized


def sanitize_dict_or_list(data: Any) -> Any:
    """Recursively sanitizes nested dictionaries, lists, and strings."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_str = str(k).lower()
            if any(s in k_str for s in _SENSITIVE_KEY_NAMES):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_dict_or_list(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict_or_list(item) for item in data]
    elif isinstance(data, str):
        return redact_sensitive_text(data)
    return data
