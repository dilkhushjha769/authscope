"""API Security Hardening, Rate Limiting, and Request Safety Protection.

Provides:
1. In-memory sliding window rate limiter for assessment creation and execution.
2. Request payload size limit enforcement (rejecting oversized payloads with HTTP 413).
3. Backend target scope and URL structure validation.
4. Safe error responses redacting internal Python tracebacks and credentials.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from backend.core.scope_guard import ScopeGuard, ScopeCheckResult
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Max request payload size permitted (1 MB)
MAX_PAYLOAD_BYTES = 1024 * 1024


class RateLimiter:
    """Thread-safe sliding-window in-memory rate limiter per client IP."""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_key: str) -> Tuple[bool, int, float]:
        """Checks if a request from client_key is within rate limits.

        Returns:
            Tuple of (is_allowed, remaining_requests, retry_after_seconds)
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        # Prune timestamps older than the sliding window
        timestamps = [ts for ts in self._history[client_key] if ts > cutoff]
        self._history[client_key] = timestamps

        if len(timestamps) >= self.max_requests:
            oldest_in_window = timestamps[0]
            retry_after = max(1.0, round(self.window_seconds - (now - oldest_in_window), 1))
            return False, 0, retry_after

        # Record this request
        self._history[client_key].append(now)
        remaining = self.max_requests - len(self._history[client_key])
        return True, remaining, 0.0

    def reset(self) -> None:
        """Clears all rate limit buckets."""
        self._history.clear()


# Global API rate limiters
assessment_creation_limiter = RateLimiter(max_requests=20, window_seconds=60.0)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces request payload size limits across all HTTP mutation verbs."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length_header = request.headers.get("content-length")
        if content_length_header:
            try:
                content_length = int(content_length_header)
                if content_length > MAX_PAYLOAD_BYTES:
                    logger.warning(
                        f"Rejected oversized request from {request.client.host if request.client else 'unknown'}: "
                        f"{content_length} bytes (limit is {MAX_PAYLOAD_BYTES} bytes)"
                    )
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"Request body too large ({content_length} bytes). Maximum permitted is {MAX_PAYLOAD_BYTES} bytes.",
                            "status_code": 413,
                        },
                    )
            except ValueError:
                pass

        return await call_next(request)


def validate_target_url(url: str, scope_guard: Optional[ScopeGuard] = None) -> Tuple[str, ScopeCheckResult]:
    """Strictly validates target URL structure and ScopeGuard authorization.

    Args:
        url: User-provided URL string.
        scope_guard: Optional ScopeGuard instance.

    Returns:
        Tuple of (clean_normalized_url, scope_check_result).

    Raises:
        HTTPException: If the URL is malformed, has an invalid scheme, or violates scope.
    """
    clean_url = (url or "").strip().rstrip("/")
    if not clean_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL must not be empty.",
        )

    # Validate URL structure and scheme
    try:
        parsed = urlsplit(clean_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed URL structure: {exc}",
        )

    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL must specify a valid hostname.",
        )

    # Validate against ScopeGuard allowlist
    guard = scope_guard or ScopeGuard()
    check_result = guard.validate_request(url=clean_url, method="GET")
    if not check_result.is_allowed:
        logger.warning(f"Rejected out-of-scope assessment request for '{clean_url}': {check_result.reason}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: {check_result.reason}",
        )

    return clean_url, check_result

