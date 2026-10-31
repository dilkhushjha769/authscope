"""Scope Guard: Strict Boundary, Anti-SSRF, and Target Allowlist Enforcement.

Authoritative gatekeeper for all network traffic.
Every candidate URL and HTTP method must be evaluated and approved by ScopeGuard
before any HTTP connection can be established.

Supports:
1. Static allowlists (from settings or custom lists).
2. Dynamic Server-Side Authorized Target Profiles (from TargetRegistry).
3. Anti-SSRF, Cloud Metadata (169.254.169.254, metadata.google.internal), and DNS Rebinding protections.
4. Exact-host match boundaries (subdomains never automatically authorized).
"""

from urllib.parse import urlsplit
from typing import Any, List, Optional
import ipaddress
import re
import socket
from pydantic import BaseModel, Field

from backend.config import settings
from backend.storage.models import TargetProfileRecord
from backend.utils.helpers import (
    ScopeViolationError,
    UnsupportedMethodError,
    InvalidTargetURLError,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Cloud metadata endpoints and forbidden interfaces
BLOCKED_HOSTS_AND_IPS = {
    "169.254.169.254",          # AWS / GCP / Azure metadata
    "metadata.google.internal",  # GCP metadata DNS
    "100.100.100.200",          # Alibaba Cloud metadata
    "fd00:ec2::254",            # AWS IPv6 metadata
    "0.0.0.0",                  # Wildcard bind
    "::",                       # IPv6 unspecified
    "::1",                      # IPv6 localhost unless explicitly allowlisted
}

PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def _is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return True
        for net in PRIVATE_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


def _resolve_ips(hostname: str) -> List[str]:
    ips = set()
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ips.add(item[4][0])
    except Exception:
        pass
    return sorted(ips)


class ScopeCheckResult(BaseModel):
    """Result of a scope check evaluation."""
    is_allowed: bool = Field(..., description="Whether the request is strictly permitted")
    target_url: str = Field(..., description="Normalized URL checked")
    method: str = Field(default="GET", description="HTTP method evaluated")
    reason: str = Field(..., description="Approval or rejection explanation")
    normalized_host: str = Field(default="")
    normalized_port: int = Field(default=80)
    normalized_scheme: str = Field(default="http")
    matched_profile_id: Optional[str] = None


class ScopeGuard:
    """Evaluates target URLs and methods against strict allowlists and dynamic target profiles."""

    BLOCKED_HOSTS_AND_IPS = BLOCKED_HOSTS_AND_IPS
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
        target_profile: Optional[TargetProfileRecord] = None,
        target_registry: Optional[Any] = None,
        enable_dynamic_registry: bool = True,
    ):
        """Initializes ScopeGuard with configurable settings and optional profile binding."""
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or settings.allowed_hosts)]
        self.allowed_ports = allowed_ports or settings.allowed_ports
        self.allowed_schemes = [s.lower() for s in (allowed_schemes or settings.allowed_schemes)]
        self.allowed_methods = [m.upper() for m in (allowed_methods or settings.allowed_methods)]
        self.target_profile = target_profile
        self.target_registry = target_registry
        self.enable_dynamic_registry = enable_dynamic_registry

    def bind_target_profile(self, profile: TargetProfileRecord) -> None:
        """Binds an approved target profile directly to this ScopeGuard instance."""
        self.target_profile = profile

    def validate_method(self, method: str) -> ScopeCheckResult:
        """Validates that the HTTP method is allowed."""
        normalized_method = method.strip().upper()
        if self.target_profile is not None:
            prof_methods = [m.upper() for m in self.target_profile.allowed_methods]
            if normalized_method not in prof_methods:
                reason = (
                    f"HTTP method '{normalized_method}' is not permitted for target profile "
                    f"'{self.target_profile.id}'. Permitted methods: {prof_methods}"
                )
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url="",
                    method=normalized_method,
                    reason=reason,
                    matched_profile_id=self.target_profile.id,
                )
            return ScopeCheckResult(
                is_allowed=True,
                target_url="",
                method=normalized_method,
                reason="Method is permitted for target profile.",
                matched_profile_id=self.target_profile.id,
            )

        if normalized_method not in self.allowed_methods:
            reason = (
                f"HTTP method '{normalized_method}' is not permitted. "
                f"Initially allowed methods: {self.allowed_methods}"
            )
            return ScopeCheckResult(
                is_allowed=False,
                target_url="",
                method=normalized_method,
                reason=reason,
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url="",
            method=normalized_method,
            reason="Method is permitted.",
        )

    def validate_url(self, url: str) -> ScopeCheckResult:
        """Validates if a URL conforms strictly to authorized boundaries."""
        if not url or not isinstance(url, str):
            return ScopeCheckResult(
                is_allowed=False,
                target_url=str(url),
                reason="Target URL must be a non-empty string.",
            )

        # Check for control characters or null bytes
        if any(ord(c) < 32 or ord(c) == 127 for c in url):
            return ScopeCheckResult(
                is_allowed=False,
                target_url=repr(url),
                reason="URL contains prohibited control characters or null bytes.",
            )

        # Parse URL
        try:
            split_url = urlsplit(url.strip())
        except Exception as exc:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Malformed URL could not be parsed: {exc}",
            )

        scheme = split_url.scheme.lower()
        if not scheme:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Validation failed: URL is missing an explicit scheme (e.g. 'http://').",
            )

        if scheme in self.DANGEROUS_SCHEMES:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Scheme '{scheme}' is prohibited and dangerous.",
            )

        # Disallow embedded userinfo / credentials
        if split_url.username or split_url.password:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Embedded userinfo / credentials in URL authority are strictly prohibited and not allowed.",
            )

        raw_hostname = split_url.hostname
        if not raw_hostname:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason="Validation failed: URL authority is missing a valid hostname.",
            )

        normalized_host = raw_hostname.lower().rstrip(".")

        # Check against explicitly blocked cloud metadata endpoints
        if normalized_host in self.BLOCKED_HOSTS_AND_IPS:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Target '{normalized_host}' matches a prohibited internal or cloud metadata service (not allowed).",
            )

        effective_port = split_url.port
        if effective_port is None:
            effective_port = 443 if scheme == "https" else 80

        req_path = split_url.path or "/"

        # ----------------------------------------------------------------------
        # Case 1: Bound to an explicit TargetProfileRecord
        # ----------------------------------------------------------------------
        if self.target_profile is not None:
            prof = self.target_profile
            # Check if profile is active (not revoked, not expired)
            if not prof.is_active():
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=f"Target profile '{prof.id}' is not active (status: {prof.approval_status}).",
                    matched_profile_id=prof.id,
                )

            # Exact hostname match (no wildcarding subdomains)
            if normalized_host != prof.hostname.lower():
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=(
                        f"Exact hostname match required. Bound profile is for '{prof.hostname}', "
                        f"but request attempted '{normalized_host}'."
                    ),
                    matched_profile_id=prof.id,
                )

            # Scheme check
            if scheme not in [s.lower() for s in prof.allowed_schemes]:
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=f"Scheme '{scheme}' is prohibited and not allowed for target profile '{prof.id}'. Permitted schemes: {prof.allowed_schemes}",
                    matched_profile_id=prof.id,
                )

            # Port check
            if effective_port not in prof.allowed_ports:
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=f"Port '{effective_port}' is outside the authorized allowlist {prof.allowed_ports} for profile '{prof.id}'.",
                    matched_profile_id=prof.id,
                )

            # Path boundaries check
            if prof.allowed_paths:
                path_allowed = any(
                    req_path == p or req_path.startswith(p if p.endswith("/") else f"{p}/")
                    for p in prof.allowed_paths
                )
                if not path_allowed:
                    return ScopeCheckResult(
                        is_allowed=False,
                        target_url=url,
                        reason=f"Path '{req_path}' is outside approved boundaries {prof.allowed_paths} for profile '{prof.id}'.",
                        matched_profile_id=prof.id,
                    )

            # Anti-SSRF / DNS rebinding check for non-local targets
            if not prof.is_local_test and normalized_host not in ("localhost", "127.0.0.1", "::1"):
                resolved_ips = _resolve_ips(normalized_host)
                for ip in resolved_ips:
                    if _is_private_or_reserved(ip) or ip in self.BLOCKED_HOSTS_AND_IPS:
                        return ScopeCheckResult(
                            is_allowed=False,
                            target_url=url,
                            reason=f"Target '{normalized_host}' resolved to prohibited/private IP '{ip}' (SSRF/DNS rebinding blocked).",
                            matched_profile_id=prof.id,
                        )

            return ScopeCheckResult(
                is_allowed=True,
                target_url=url,
                reason="Target URL is strictly within authorized profile testing boundaries.",
                normalized_host=normalized_host,
                normalized_port=effective_port,
                normalized_scheme=scheme,
                matched_profile_id=prof.id,
            )

        # ----------------------------------------------------------------------
        # Case 2: Static allowlist evaluation
        # ----------------------------------------------------------------------
        host_in_static = normalized_host in self.allowed_hosts
        port_in_static = effective_port in self.allowed_ports
        scheme_in_static = scheme in self.allowed_schemes

        if host_in_static:
            if not scheme_in_static:
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=f"Scheme '{scheme}' is prohibited and not allowed. Permitted schemes: {self.allowed_schemes}",
                )
            if not port_in_static:
                return ScopeCheckResult(
                    is_allowed=False,
                    target_url=url,
                    reason=f"Port '{effective_port}' is outside the authorized allowlist {self.allowed_ports}.",
                )
            # Check for private IP destination if not loopback
            if normalized_host not in ("localhost", "127.0.0.1", "::1"):
                resolved = _resolve_ips(normalized_host)
                for ip in resolved:
                    if _is_private_or_reserved(ip) or ip in self.BLOCKED_HOSTS_AND_IPS:
                        return ScopeCheckResult(
                            is_allowed=False,
                            target_url=url,
                            reason=f"Target '{normalized_host}' resolved to private IP '{ip}' (SSRF blocked).",
                        )
            return ScopeCheckResult(
                is_allowed=True,
                target_url=url,
                reason="Target URL is strictly within authorized testing boundaries.",
                normalized_host=normalized_host,
                normalized_port=effective_port,
                normalized_scheme=scheme,
            )

        # ----------------------------------------------------------------------
        # Case 3: Dynamic TargetRegistry evaluation
        # ----------------------------------------------------------------------
        if self.enable_dynamic_registry:
            try:
                from backend.core.target_registry import TargetRegistry

                registry = self.target_registry or TargetRegistry()
                is_auth, auth_reason, matched_prof = registry.evaluate_target_authorization(url, method="GET")
                if is_auth and matched_prof is not None:
                    return ScopeCheckResult(
                        is_allowed=True,
                        target_url=url,
                        reason="Target URL is authorized by an approved server-side target profile.",
                        normalized_host=normalized_host,
                        normalized_port=effective_port,
                        normalized_scheme=scheme,
                        matched_profile_id=matched_prof.id,
                    )
                elif matched_prof is not None:
                    # Target has a registered profile, but it is pending, expired, or revoked
                    return ScopeCheckResult(
                        is_allowed=False,
                        target_url=url,
                        reason=auth_reason,
                        matched_profile_id=matched_prof.id,
                    )
            except Exception as exc:
                logger.debug(f"Dynamic target registry check failed: {exc}")

        # If not authorized by either static or dynamic profiles, build clear explanation
        if scheme not in self.allowed_schemes:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Scheme '{scheme}' is prohibited and not allowed. Permitted schemes: {self.allowed_schemes}",
            )

        if normalized_host not in self.allowed_hosts:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Host '{normalized_host}' is outside the authorized allowlist {self.allowed_hosts}.",
            )

        if effective_port not in self.allowed_ports:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                reason=f"Port '{effective_port}' is outside the authorized allowlist {self.allowed_ports}.",
            )

        return ScopeCheckResult(
            is_allowed=False,
            target_url=url,
            reason=f"Target '{normalized_host}' is not approved for assessment.",
        )

    def validate_request(self, url: str, method: str = "GET") -> ScopeCheckResult:
        """Validates both URL and HTTP method in a single evaluation."""
        method_result = self.validate_method(method)
        if not method_result.is_allowed:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                method=method_result.method,
                reason=method_result.reason,
                matched_profile_id=method_result.matched_profile_id,
            )

        url_result = self.validate_url(url)
        if not url_result.is_allowed:
            return ScopeCheckResult(
                is_allowed=False,
                target_url=url,
                method=method_result.method,
                reason=url_result.reason,
                matched_profile_id=url_result.matched_profile_id,
            )

        return ScopeCheckResult(
            is_allowed=True,
            target_url=url,
            method=method_result.method,
            reason="Request target and method are in authorized scope.",
            normalized_host=url_result.normalized_host,
            normalized_port=url_result.normalized_port,
            normalized_scheme=url_result.normalized_scheme,
            matched_profile_id=url_result.matched_profile_id,
        )

    def assert_in_scope(self, url: str, method: str = "GET") -> None:
        """Asserts that both target URL and method are in-scope."""
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
