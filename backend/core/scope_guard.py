"""Scope Guard: Strict Boundary and Target Allowlist Enforcement.

This module acts as the authoritative gatekeeper for all network traffic.
Every candidate URL and HTTP method must be evaluated and approved by ScopeGuard
before any HTTP connection can be established.
"""

from urllib.parse import urlsplit
from typing import List, Optional
import ipaddress
import re
from pydantic import BaseModel, Field

from backend.config import settings
from backend.utils.helpers import (
    ScopeViolationError,
    UnsupportedMethodError,
    InvalidTargetURLError,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ScopeCheckResult(BaseModel):
    """Result of a scope check evaluation."""
    is_allowed: bool = Field(..., description="Whether the request is strictly permitted")
    target_url: str = Field(..., description="Normalized URL checked")
    method: str = Field(default="GET", description="HTTP method evaluated")
    reason: str = Field(..., description="Approval or rejection explanation")
    normalized_host: str = Field(default="")
    normalized_port: int = Field(default=80)
    normalized_scheme: str = Field(default="http")


class ScopeGuard:
    """Evaluates target URLs and methods against strict allowlists."""

    # Prohibited dangerous endpoints and cloud metadata services
    BLOCKED_HOSTS_AND_IPS = {
        "169.254.169.254",         # AWS / GCP / Azure metadata
        "metadata.google.internal", # GCP metadata DNS
        "100.100.100.200",         # Alibaba Cloud metadata
        "0.0.0.0",                 # All interfaces wildcard
        "::",                      # IPv6 unspecified
        "::1",                     # IPv6 localhost unless explicitly allowlisted
    }

    # Prohibited protocols that must never be handled
    DANGEROUS_SCHEMES = {
        "file", "gopher", "ftp", "ftps", "ldap", "ldaps", "dict", "tftp", "telnet",
        "ssh", "javascript", "data", "vbscript", "mailto"
    }

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_schemes: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
    ):
        """Initializes ScopeGuard with configurable or default settings."""
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or settings.allowed_hosts)]
        self.allowed_ports = allowed_ports or settings.allowed_ports
        self.allowed_schemes = [s.lower() for s in (allowed_schemes or settings.allowed_schemes)]
        self.allowed_methods = [m.upper() for m in (allowed_methods or settings.allowed_methods)]

    def validate_method(self, method: str) -> ScopeCheckResult:
        """Validates that the HTTP method is allowed.

        During initial phases, only GET is permitted to guarantee non-destructive operation.
        """
        normalized_method = method.strip().upper()
        if normalized_method not in self.allowed_methods:
            reason = (
                f"HTTP method '{normalized_method}' is not permitted. "
                f"Initially allowed methods: {self.allowed_methods}"
            )
            return ScopeCheckResult(
                is_allowed=False,
                target_url="",
                method=normalized_method,
                reason=reason
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url="",
            method=normalized_method,
            reason="Method is permitted."
        )

    def validate_url(self, url: str) -> ScopeCheckResult:
        """Validates if a URL conforms strictly to authorized boundaries.

        Checks:
        - Absolute URL formatting with non-empty scheme and host.
        - Absence of control characters, null bytes, and embedded credentials (`user:pass@`).
        - Scheme strictly in allowed_schemes.
        - Hostname strictly in allowed_hosts (rejects external domains and unlisted IPs).
        - Port strictly in allowed_ports.
        - Prohibits cloud metadata addresses and wildcard interfaces.
        """
        if not url or not isinstance(url, str):
            return ScopeCheckResult(
                is_allowed=False,
                target_url=str(url),
                reason="Target URL must be a non-empty string."
            )

        # Check for control characters or null bytes
        if any(ord(c) < 32 or ord(c) == 127 for c in url):
            return ScopeCheckResult(
                is_allowed=False,
                target_url=repr(url),
                reason="URL contains prohibited control characters or null bytes."
            )

        # Parse URL using urlsplit
        try:
            split_url = urlsplit(url.strip())
        except Exception as exc:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Malformed URL could not be parsed: {exc}"
            )

        scheme = split_url.scheme.lower()
        if not scheme:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Validation failed: URL is missing an explicit scheme (e.g. 'http://')."
            )

        if scheme in self.DANGEROUS_SCHEMES or scheme not in self.allowed_schemes:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Scheme '{scheme}' is prohibited and not allowed. Permitted schemes: {self.allowed_schemes}"
            )

        # Disallow embedded credentials in URL (user:pass@host)
        if split_url.username or split_url.password:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Embedded userinfo / credentials in URL authority are strictly prohibited and not allowed."
            )

        raw_hostname = split_url.hostname
        if not raw_hostname:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Validation failed: URL authority is missing a valid hostname."
            )

        normalized_host = raw_hostname.lower().rstrip(".")

        # Check against explicitly blocked hosts and cloud metadata services
        if normalized_host in self.BLOCKED_HOSTS_AND_IPS:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Target '{normalized_host}' matches a prohibited internal or cloud metadata service (not allowed)."
            )

        # Validate that host is in allowed_hosts
        if normalized_host not in self.allowed_hosts:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Host '{normalized_host}' is outside the authorized allowlist {self.allowed_hosts}."
            )

        # Determine effective port
        effective_port = split_url.port
        if effective_port is None:
            if scheme == "http":
                effective_port = 80
            elif scheme == "https":
                effective_port = 443
            else:
                effective_port = 80

        if effective_port not in self.allowed_ports:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Port '{effective_port}' is outside the authorized allowlist {self.allowed_ports}."
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url=url,
            reason="Target URL is strictly within authorized testing boundaries.",
            normalized_host=normalized_host,
            normalized_port=effective_port,
            normalized_scheme=scheme
        )

    def validate_request(self, url: str, method: str = "GET") -> ScopeCheckResult:
        """Validates both URL and HTTP method in a single evaluation."""
        method_result = self.validate_method(method)
        if not method_result.is_allowed:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                method=method_result.method,
                reason=method_result.reason
            )

        url_result = self.validate_url(url)
        if not url_result.is_allowed:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                method=method_result.method,
                reason=url_result.reason
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url=url,
            method=method_result.method,
            reason="Request target and method are in authorized scope.",
            normalized_host=url_result.normalized_host,
            normalized_port=url_result.normalized_port,
            normalized_scheme=url_result.normalized_scheme
        )

    def assert_in_scope(self, url: str, method: str = "GET") -> None:
        """Asserts that both target URL and method are in-scope.

        Raises:
            UnsupportedMethodError: If method is not permitted.
            InvalidTargetURLError: If URL is malformed or invalid.
            ScopeViolationError: If target is out-of-scope.
        """
        method_res = self.validate_method(method)
        if not method_res.is_allowed:
            logger.error("Method blocked by ScopeGuard", extra={"method": method, "reason": method_res.reason})
            raise UnsupportedMethodError(method_res.reason)

        url_res = self.validate_url(url)
        if not url_res.is_allowed:
            logger.error("Target URL blocked by ScopeGuard", extra={"url": url, "reason": url_res.reason})
            if "malformed" in url_res.reason.lower() or "missing" in url_res.reason.lower() or "control" in url_res.reason.lower():
                raise InvalidTargetURLError(url_res.reason)
            raise ScopeViolationError(f"Target outside authorized scope: {url_res.reason}")
