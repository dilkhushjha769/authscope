"""Request Executor: Low-Level HTTP Client with Hard Scope Controls.

Wraps httpx to enforce:
1. Strict ScopeGuard validation before socket connection.
2. Disabled automatic redirects (follow_redirects=False).
3. Enforced connection & read timeouts.
4. Structured logging of request/response metrics.
"""

from typing import Any, Dict, Optional
import httpx
from pydantic import BaseModel, Field
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class HttpResponseModel(BaseModel):
    """Normalized response representation."""
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="")
    json_data: Optional[Dict[str, Any]] = None
    response_time_ms: float = 0.0


class RequestExecutor:
    """Executes safe in-scope HTTP requests."""

    def __init__(self, scope_guard: Optional[ScopeGuard] = None, timeout: float = 10.0):
        self.scope_guard = scope_guard or ScopeGuard()
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=5.0),
            follow_redirects=False,  # CRITICAL: Suppress automatic redirect following
            headers={"User-Agent": "AuthScope-Agent/0.1"}
        )

    def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
    ) -> HttpResponseModel:
        """Executes a request after asserting it is strictly in-scope.

        TODO (Phase 3): Full implementation with connection retry policies and audit logging.
        """
        # 1. Enforce hard boundary scope check
        self.scope_guard.assert_in_scope(url)

        logger.info("Executing safe in-scope HTTP request", extra={"method": method, "url": url})
        try:
            resp = self.client.request(
                method=method,
                url=url,
                headers=headers or {},
                params=params or {},
                json=json_body
            )
            json_payload = None
            try:
                json_payload = resp.json()
            except Exception:
                pass

            return HttpResponseModel(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:5000],  # Truncate excessive bodies
                json_data=json_payload,
                response_time_ms=resp.elapsed.total_seconds() * 1000.0
            )
        except Exception as exc:
            logger.error("HTTP request failed", extra={"url": url, "error": str(exc)})
            raise

