"""Scope Guard: Strict Boundary and Target Allowlist Enforcement.

This module acts as the authoritative gatekeeper for all network traffic.
Every candidate URL must be evaluated and approved by ScopeGuard before
any HTTP connection can be established.
"""

from urllib.parse import urlparse
from typing import List, Optional
from pydantic import BaseModel, Field
from backend.utils.helpers import ScopeViolationError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ScopeCheckResult(BaseModel):
    """Result of a scope check evaluation."""
    is_allowed: bool = Field(..., description="Whether the URL is strictly permitted")
    target_url: str = Field(..., description="Normalized URL checked")
    reason: str = Field(..., description="Approval or rejection explanation")
    normalized_host: str = Field(default="")
    normalized_port: int = Field(default=80)


class ScopeGuard:
    """Evaluates target URLs against hard boundary allowlists."""

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_schemes: Optional[List[str]] = None,
    ):
        self.allowed_hosts = allowed_hosts or ["localhost", "127.0.0.1"]
        self.allowed_ports = allowed_ports or [3000]
        self.allowed_schemes = allowed_schemes or ["http", "https"]
        self.blocked_ips = [
            "169.254.169.254",       # AWS/GCP instance metadata
            "metadata.google.internal"
        ]

    def validate_url(self, url: str) -> ScopeCheckResult:
        """Validates if a URL conforms to authorized boundaries.

        Args:
            url: The absolute target URL string.

        Returns:
            ScopeCheckResult with decision and details.

        Raises:
            ScopeViolationError: If url is invalid or rejected.
        """
        # TODO (Phase 3): Implement full RFC 3986 normalization and DNS rebinding protections.
        try:
            parsed = urlparse(url)
        except Exception as exc:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Failed to parse URL: {exc}"
            )

        if parsed.scheme.lower() not in self.allowed_schemes:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Scheme '{parsed.scheme}' not allowed. Permitted: {self.allowed_schemes}"
            )

        host = parsed.hostname or ""
        if host.lower() in self.blocked_ips:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Access to cloud metadata endpoints is prohibited."
            )

        if host.lower() not in self.allowed_hosts:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Host '{host}' is outside the authorized allowlist."
            )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.allowed_ports:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Port '{port}' is outside the authorized allowlist."
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url=url,
            reason="Target is within authorized testing boundaries.",
            normalized_host=host,
            normalized_port=port
        )

    def assert_in_scope(self, url: str) -> None:
        """Convenience method that raises ScopeViolationError if url is not in scope."""
        result = self.validate_url(url)
        if not result.is_allowed:
            logger.error("Scope violation attempt blocked", extra={"url": url, "reason": result.reason})
            raise ScopeViolationError(f"Target outside authorized scope: {result.reason}")

