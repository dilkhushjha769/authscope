"""Request Executor: Low-Level HTTP Client with Hard Scope Controls.

Wraps httpx to enforce:
1. Strict ScopeGuard validation before socket connection.
2. Disabled automatic redirects (follow_redirects=False).
3. Enforced connection and read timeouts.
4. Response body truncation according to max limits.
5. Structured logging with token and cookie redaction.
6. Structured, typed response models.
"""

from typing import Any, Dict, Optional
from datetime import datetime, timezone
import time
import httpx
from pydantic import BaseModel, Field

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.utils.helpers import (
    TargetUnreachableError,
    MissingSessionError,
    sanitize_headers_for_logging,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class RequestMetadata(BaseModel):
    """Metadata describing the executed request."""
    method: str
    url: str
    role: str
    sanitized_headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    timestamp_utc: str


class HttpResponseModel(BaseModel):
    """Structured response representation returned by the request executor."""
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="")
    json_data: Optional[Dict[str, Any]] = None
    response_time_ms: float = 0.0
    content_length: int = 0
    is_truncated: bool = False
    request_metadata: Optional[RequestMetadata] = None


class RequestExecutor:
    """Executes safe, scope-enforced HTTP requests across authenticated personas."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        session_manager: Optional[SessionManager] = None,
        timeout: Optional[float] = None,
        client: Optional[httpx.Client] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager()
        self.timeout = timeout if timeout is not None else settings.request_timeout_seconds
        self.max_response_bytes = settings.max_response_size_bytes
        self.max_body_display_chars = settings.max_body_display_chars

        # Initialize httpx client with strict redirect suppression and timeouts
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=5.0),
            follow_redirects=False,  # CRITICAL: Suppress automatic redirect following
            headers={"User-Agent": "AuthScope-Security-Engine/0.1"}
        )

    def execute(
        self,
        method: str = "GET",
        url: str = "",
        role: Role | str = Role.ANONYMOUS,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        **kwargs,
    ) -> HttpResponseModel:
        """Alias for send_request for general execution."""
        return self.send_request(
            role=role,
            method=method,
            url=url,
            params=params,
            custom_headers=headers,
            json_body=json_body,
        )

    def send_request(
        self,
        role: Role | str = Role.ANONYMOUS,
        method: str = "GET",
        url: str = "",
        params: Optional[Dict[str, Any]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
    ) -> HttpResponseModel:
        """Executes an authorized HTTP request under the specified role's session.

        Steps:
        1. Validates method and URL using ScopeGuard.
        2. Retrieves the role's session and constructs authentication headers.
        3. Executes the request using httpx with follow_redirects=False.
        4. Truncates response body if it exceeds configured size boundaries.
        5. Returns structured HttpResponseModel with execution telemetry.
        """
        # Step 1: Enforce hard boundary scope check
        self.scope_guard.assert_in_scope(url=url, method=method)

        # Step 2: Retrieve role session and merge headers (raises MissingSessionError if invalid)
        session = self.session_manager.get_session(role)
        session_headers = session.get_headers()

        effective_headers: Dict[str, str] = dict(session_headers)
        if custom_headers:
            effective_headers.update(custom_headers)

        # Build sanitized metadata for audit logging
        sanitized_headers = sanitize_headers_for_logging(effective_headers)
        metadata = RequestMetadata(
            method=method.upper(),
            url=url,
            role=session.role.value,
            sanitized_headers=sanitized_headers,
            params=params or {},
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )

        logger.info(
            "Executing scoped HTTP request [%s %s, role=%s, headers=%s]",
            metadata.method,
            metadata.url,
            metadata.role,
            metadata.sanitized_headers,
            extra={
                "method": metadata.method,
                "url": metadata.url,
                "role": metadata.role,
                "headers": metadata.sanitized_headers
            }
        )

        # Step 3: Execute network request with precise timing and error handling
        start_time = time.perf_counter()
        try:
            resp = self.client.request(
                method=method.upper(),
                url=url,
                headers=effective_headers,
                params=params or {},
                json=json_body
            )
            # Ensure full response content is read
            resp.read()
        except httpx.TimeoutException as exc:
            logger.error("Request timed out", extra={"url": url, "timeout_seconds": self.timeout})
            raise TargetUnreachableError(
                f"Connection to target '{url}' timed out after {self.timeout}s: {exc}"
            ) from exc
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            logger.error("Network connection failure", extra={"url": url, "error": str(exc)})
            raise TargetUnreachableError(
                f"Failed to connect to target '{url}': {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            logger.error("HTTP protocol error", extra={"url": url, "error": str(exc)})
            raise TargetUnreachableError(f"HTTP protocol error for '{url}': {exc}") from exc

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 4: Capture status, headers, and bounded body
        raw_content = resp.content
        content_length = len(raw_content)
        is_truncated = False

        if content_length > self.max_response_bytes:
            truncated_bytes = raw_content[:self.max_response_bytes]
            body_text = truncated_bytes.decode("utf-8", errors="replace")
            is_truncated = True
        else:
            body_text = resp.text

        if len(body_text) > self.max_body_display_chars:
            body_text = body_text[:self.max_body_display_chars]
            is_truncated = True

        # Attempt JSON decoding if response appears to be JSON
        json_data = None
        try:
            json_data = resp.json()
        except Exception:
            pass

        response_headers = dict(resp.headers)

        return HttpResponseModel(
            status_code=resp.status_code,
            headers=response_headers,
            body=body_text,
            json_data=json_data,
            response_time_ms=elapsed_ms,
            content_length=content_length,
            is_truncated=is_truncated,
            request_metadata=metadata
        )

    def close(self) -> None:
        """Closes the underlying httpx client."""
        self.client.close()

    def __enter__(self) -> "RequestExecutor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def send_request(
    role: Role | str = Role.ANONYMOUS,
    method: str = "GET",
    url: str = "",
    params: Optional[Dict[str, Any]] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Any] = None,
    timeout: Optional[float] = None,
    scope_guard: Optional[ScopeGuard] = None,
    session_manager: Optional[SessionManager] = None,
) -> HttpResponseModel:
    """Convenience top-level function for executing a scoped HTTP request."""
    executor = RequestExecutor(
        scope_guard=scope_guard,
        session_manager=session_manager,
        timeout=timeout
    )
    try:
        return executor.send_request(
            role=role,
            method=method,
            url=url,
            params=params,
            custom_headers=custom_headers,
            json_body=json_body
        )
    finally:
        executor.close()
