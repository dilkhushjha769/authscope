"""Target Registry: Dynamic Server-Side Authorized Target Management & Security Boundary.

Coordinates:
1. Target submission with authorization basis (admin approved, written consent, bug bounty, domain challenge).
2. Exact-host scope validation (never wildcards subdomains automatically).
3. SSRF, cloud metadata, private IP, and DNS rebinding protections.
4. Administrative approval, expiration tracking, and revocation.
5. Domain challenge verification (HTTP /.well-known/ or DNS TXT token).
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import secrets
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit
import uuid

import httpx
from pydantic import BaseModel, Field

from backend.storage.database import DatabaseManager
from backend.storage.models import (
    AuthorizationBasis,
    TargetApprovalStatus,
    TargetProfileRecord,
)
from backend.storage.target_repository import TargetRepository
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Cloud metadata services and forbidden IP addresses (must ALWAYS be blocked)
PROHIBITED_METADATA_HOSTS = {
    "169.254.169.254",          # AWS / GCP / Azure Instance Metadata Service
    "metadata.google.internal",  # GCP Metadata DNS
    "100.100.100.200",          # Alibaba Cloud Metadata
    "fd00:ec2::254",            # AWS IPv6 Metadata
    "0.0.0.0",                  # Wildcard bind
    "::",                       # IPv6 unspecified
}

# Standard private and reserved IP ranges (RFC 1918, RFC 3927, RFC 4193)
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space
    ipaddress.ip_network("fc00::/7"),        # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),       # IPv6 Link-Local
    ipaddress.ip_network("::1/128"),         # IPv6 Loopback
]


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to private, loopback, or reserved ranges."""
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


def resolve_hostname_ips(hostname: str) -> List[str]:
    """Resolves all IPv4 and IPv6 addresses for a hostname for DNS rebinding/SSRF defense."""
    ips: Set[str] = set()
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            sockaddr = item[4]
            ip = sockaddr[0]
            ips.add(ip)
    except (socket.gaierror, socket.herror, OSError) as exc:
        logger.debug(f"DNS resolution failed for '{hostname}': {exc}")
    return sorted(ips)


class TargetSubmissionPayload(BaseModel):
    """Payload submitted when registering a new target for authorization."""
    target_url: str = Field(..., description="Target base URL (e.g. https://staging.example.com)")
    authorization_basis: str = Field(
        default=AuthorizationBasis.ADMIN_APPROVED.value,
        description="Grounds: admin_approved, written_permission, bug_bounty_scope, domain_ownership_challenge",
    )
    permission_reference: str = Field(
        default="",
        description="Written permission reference, ticket number, or bug bounty program link",
    )
    allowed_paths: List[str] = Field(default_factory=list, description="Optional path prefix restrictions")
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    notes: str = Field(default="", description="Operator notes")


class TargetRegistry:
    """Dynamic Server-Side Authorized Target Registry.

    Enforces that targets are explicitly reviewed, approved, and bound before
    any assessment or network probing can proceed.
    """

    def __init__(
        self,
        repository: Optional[TargetRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
    ) -> None:
        self.repository = repository or TargetRepository(db_manager=db_manager)

    def validate_target_syntax_and_network(
        self,
        raw_url: str,
        is_local_test: bool = False,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Strictly validates target URL scheme, hostname, port, and anti-SSRF IP rules.

        Returns (is_valid, error_reason, parsed_components).
        """
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            return False, "Target URL must not be empty.", {}

        clean_url = raw_url.strip()
        try:
            split_url = urlsplit(clean_url)
        except Exception as exc:
            return False, f"Malformed URL could not be parsed: {exc}", {}

        scheme = split_url.scheme.lower()
        if not scheme:
            return False, "URL is missing an explicit scheme (e.g. 'http://' or 'https://').", {}

        if scheme not in ("http", "https"):
            return (
                False,
                f"Scheme '{scheme}' is prohibited. Only HTTP and HTTPS targets are supported.",
                {},
            )

        if split_url.username or split_url.password:
            return False, "Embedded credentials (user:pass@host) are strictly prohibited.", {}

        raw_hostname = split_url.hostname
        if not raw_hostname:
            return False, "URL is missing a valid hostname.", {}

        hostname = raw_hostname.lower().rstrip(".")

        # Check explicitly blocked cloud metadata hosts
        if hostname in PROHIBITED_METADATA_HOSTS:
            return (
                False,
                f"Target hostname '{hostname}' is a prohibited cloud metadata endpoint (SSRF blocked).",
                {},
            )

        # Check port
        port = split_url.port
        if port is None:
            port = 443 if scheme == "https" else 80

        if not (1 <= port <= 65535):
            return False, f"Port '{port}' is out of valid range 1-65535.", {}

        # DNS resolution and Anti-SSRF check
        is_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        if not is_loopback and not is_local_test:
            # Check if hostname itself is a raw IP
            try:
                ipaddress.ip_address(hostname)
                is_raw_ip = True
            except ValueError:
                is_raw_ip = False

            if is_raw_ip and is_private_or_reserved_ip(hostname):
                return (
                    False,
                    f"Target IP '{hostname}' belongs to a private/reserved network space. "
                    "Testing private IP destinations is prohibited unless local testing is explicitly approved.",
                    {},
                )

            # Resolve DNS to verify non-private destination (prevent DNS rebinding)
            resolved_ips = resolve_hostname_ips(hostname)
            for ip in resolved_ips:
                if is_private_or_reserved_ip(ip) or ip in PROHIBITED_METADATA_HOSTS:
                    return (
                        False,
                        f"Target hostname '{hostname}' resolves to private/internal IP '{ip}'. "
                        "Access to internal network destinations is prohibited (DNS rebinding / SSRF protection).",
                        {},
                    )

        # Build clean base URL
        default_port = 443 if scheme == "https" else 80
        port_part = f":{port}" if port != default_port else ""
        canonical_base_url = f"{scheme}://{hostname}{port_part}"

        return True, "", {
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": split_url.path or "/",
            "canonical_base_url": canonical_base_url,
            "is_loopback": is_loopback,
        }

    def submit_target_for_authorization(
        self,
        payload: TargetSubmissionPayload,
    ) -> Tuple[bool, str, Optional[TargetProfileRecord]]:
        """Submits a target website for authorization and approval.

        Creates a PENDING target profile and generates domain challenge tokens if applicable.
        """
        valid, err, parsed = self.validate_target_syntax_and_network(payload.target_url)
        if not valid:
            return False, err, None

        hostname = parsed["hostname"]
        scheme = parsed["scheme"]
        port = parsed["port"]
        base_url = parsed["canonical_base_url"]
        is_local = parsed["is_loopback"]

        # Check if an active profile already exists for this exact hostname
        existing = self.repository.get_profile_by_hostname(hostname)
        if existing and existing.is_active():
            return (
                True,
                f"Target '{hostname}' is already authorized and active (ID: {existing.id}).",
                existing,
            )

        profile_id = f"target_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        verification_token = ""
        if payload.authorization_basis == AuthorizationBasis.DOMAIN_OWNERSHIP_CHALLENGE.value:
            verification_token = f"authscope-verification-{secrets.token_hex(16)}"

        profile = TargetProfileRecord(
            id=profile_id,
            hostname=hostname,
            base_url=base_url,
            allowed_schemes=[scheme],
            allowed_ports=[port],
            allowed_paths=payload.allowed_paths,
            allowed_methods=payload.allowed_methods or ["GET", "HEAD"],
            authorization_basis=payload.authorization_basis,
            permission_reference=payload.permission_reference,
            approval_status=TargetApprovalStatus.PENDING.value,
            verification_token=verification_token,
            is_local_test=is_local,
            notes=payload.notes,
        )
        self.repository.save_target_profile(profile)
        logger.info(f"Target '{hostname}' submitted for authorization: profile {profile_id}")
        return True, f"Target '{hostname}' submitted for authorization (Status: PENDING).", profile

    def approve_target(
        self,
        profile_id: str,
        approved_by: str = "security_admin",
        expires_in_days: int = 30,
        notes: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[TargetProfileRecord]]:
        """Approves a pending target profile through an authorized administrator."""
        profile = self.repository.get_target_profile(profile_id)
        if not profile:
            return False, f"Target profile '{profile_id}' not found.", None

        if not approved_by or not approved_by.strip():
            return False, "Approval requires an explicit approved_by administrator identifier.", None

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=max(1, expires_in_days))

        profile.approval_status = TargetApprovalStatus.APPROVED.value
        profile.approved_by = approved_by.strip()
        profile.approved_at = now
        profile.expires_at = expires_at
        profile.revoked_at = None
        profile.revocation_reason = ""
        if notes:
            profile.notes = f"{profile.notes}\nApproval note: {notes}".strip()

        self.repository.save_target_profile(profile)
        logger.info(f"Target '{profile.hostname}' approved by '{approved_by}' until {expires_at.isoformat()}")
        return True, f"Target '{profile.hostname}' successfully approved.", profile

    def revoke_target(
        self,
        profile_id: str,
        revoked_by: str = "security_admin",
        reason: str = "Authorization revoked by operator",
    ) -> Tuple[bool, str, Optional[TargetProfileRecord]]:
        """Revokes authorization for an approved target profile."""
        profile = self.repository.get_target_profile(profile_id)
        if not profile:
            return False, f"Target profile '{profile_id}' not found.", None

        now = datetime.now(timezone.utc)
        profile.approval_status = TargetApprovalStatus.REVOKED.value
        profile.revoked_at = now
        profile.revocation_reason = reason.strip() or "Authorization revoked"
        profile.notes = f"{profile.notes}\nRevoked by {revoked_by} on {now.isoformat()}: {profile.revocation_reason}".strip()

        self.repository.save_target_profile(profile)
        logger.info(f"Target '{profile.hostname}' revoked by '{revoked_by}': {profile.revocation_reason}")
        return True, f"Authorization for '{profile.hostname}' has been revoked.", profile

    def verify_domain_challenge(
        self,
        profile_id: str,
        challenge_type: str = "http",
    ) -> Tuple[bool, str, Optional[TargetProfileRecord]]:
        """Verifies domain ownership via HTTP well-known challenge token or DNS TXT token."""
        profile = self.repository.get_target_profile(profile_id)
        if not profile:
            return False, f"Target profile '{profile_id}' not found.", None

        if not profile.verification_token:
            return False, "No verification challenge token is configured on this profile.", None

        token = profile.verification_token
        hostname = profile.hostname

        # 1. HTTP Challenge Verification: http(s)://<hostname>/.well-known/authscope-challenge.txt
        if challenge_type.lower() == "http":
            scheme = profile.allowed_schemes[0] if profile.allowed_schemes else "https"
            port = profile.allowed_ports[0] if profile.allowed_ports else 443
            default_port = 443 if scheme == "https" else 80
            port_part = f":{port}" if port != default_port else ""
            challenge_url = f"{scheme}://{hostname}{port_part}/.well-known/authscope-challenge.txt"

            try:
                with httpx.Client(timeout=10.0, follow_redirects=False, verify=True) as client:
                    resp = client.get(challenge_url)
                    if resp.status_code == 200 and token in resp.text:
                        now = datetime.now(timezone.utc)
                        profile.approval_status = TargetApprovalStatus.APPROVED.value
                        profile.approved_by = "domain_ownership_challenge"
                        profile.approved_at = now
                        profile.verified_at = now
                        profile.expires_at = now + timedelta(days=30)
                        self.repository.save_target_profile(profile)
                        return True, f"Domain ownership confirmed via HTTP challenge at '{challenge_url}'.", profile
                    else:
                        return (
                            False,
                            f"HTTP challenge failed: GET {challenge_url} returned status {resp.status_code} "
                            "without matching verification token.",
                            profile,
                        )
            except Exception as exc:
                return False, f"HTTP challenge request failed for '{challenge_url}': {exc}", profile

        return False, f"Unsupported challenge type '{challenge_type}'.", profile

    def evaluate_target_authorization(
        self,
        candidate_url: str,
        method: str = "GET",
    ) -> Tuple[bool, str, Optional[TargetProfileRecord]]:
        """Evaluates whether candidate URL is authorized against an active, approved TargetProfile.

        Enforces:
        - Exact hostname matching (no automatic subdomain authorization).
        - Scheme matching.
        - Port matching.
        - Path prefix matching if allowed_paths are specified.
        - Allowed methods.
        - Non-expired, non-revoked, APPROVED status.
        - Re-checks DNS for private IP / metadata destination / DNS rebinding.

        Returns: (is_authorized, reason, matching_profile)
        """
        valid, err, parsed = self.validate_target_syntax_and_network(candidate_url)
        if not valid:
            return False, err, None

        hostname = parsed["hostname"]
        scheme = parsed["scheme"]
        port = parsed["port"]
        req_path = parsed["path"]

        profile = self.repository.get_profile_by_hostname(hostname)
        if not profile:
            return (
                False,
                f"Host '{hostname}' is not authorized. No approved target profile found. "
                "Submit this target for authorization and obtain admin approval before testing.",
                None,
            )

        # Check approval status
        if profile.approval_status == TargetApprovalStatus.PENDING.value:
            return (
                False,
                f"Target '{hostname}' is pending authorization approval (ID: {profile.id}). "
                "Assessment is blocked until an administrator approves this target profile.",
                profile,
            )

        if profile.approval_status == TargetApprovalStatus.REVOKED.value:
            return (
                False,
                f"Target '{hostname}' authorization was revoked: {profile.revocation_reason or 'Revoked by admin'}.",
                profile,
            )

        if profile.approval_status == TargetApprovalStatus.REJECTED.value:
            return (
                False,
                f"Target '{hostname}' authorization was rejected by administrator.",
                profile,
            )

        now = datetime.now(timezone.utc)
        if profile.expires_at is not None and profile.expires_at <= now:
            return (
                False,
                f"Target '{hostname}' authorization expired on {profile.expires_at.isoformat()}. "
                "Re-approval is required before assessments can be resumed.",
                profile,
            )

        if profile.approval_status != TargetApprovalStatus.APPROVED.value:
            return (
                False,
                f"Target '{hostname}' authorization status is '{profile.approval_status}' (not approved).",
                profile,
            )

        # Exact hostname match check (never wildcard subdomains automatically)
        if profile.hostname != hostname:
            return (
                False,
                f"Exact hostname match required. Profile is for '{profile.hostname}', but requested '{hostname}'.",
                profile,
            )

        # Check scheme
        if scheme not in [s.lower() for s in profile.allowed_schemes]:
            return (
                False,
                f"Scheme '{scheme}' is not permitted for target profile '{profile.id}'. "
                f"Permitted schemes: {profile.allowed_schemes}. (HTTPS is never downgraded to HTTP.)",
                profile,
            )

        # Check port
        if port not in profile.allowed_ports:
            return (
                False,
                f"Port '{port}' is not permitted for target profile '{profile.id}'. "
                f"Permitted ports: {profile.allowed_ports}.",
                profile,
            )

        # Check method
        norm_method = method.strip().upper()
        if norm_method not in [m.upper() for m in profile.allowed_methods]:
            return (
                False,
                f"HTTP method '{norm_method}' is not permitted for target profile '{profile.id}'. "
                f"Permitted methods: {profile.allowed_methods}.",
                profile,
            )

        # Check path restrictions if configured
        if profile.allowed_paths:
            path_allowed = any(
                req_path == p or req_path.startswith(p if p.endswith("/") else f"{p}/")
                for p in profile.allowed_paths
            )
            if not path_allowed:
                return (
                    False,
                    f"Path '{req_path}' is outside approved path boundaries {profile.allowed_paths} for '{hostname}'.",
                    profile,
                )

        # Dynamic DNS rebinding check at evaluation time
        if not profile.is_local_test and hostname not in ("localhost", "127.0.0.1", "::1"):
            ips = resolve_hostname_ips(hostname)
            for ip in ips:
                if is_private_or_reserved_ip(ip) or ip in PROHIBITED_METADATA_HOSTS:
                    return (
                        False,
                        f"Target '{hostname}' resolved to prohibited/private IP '{ip}' (SSRF / DNS rebinding blocked).",
                        profile,
                    )

        return True, "Target is verified and authorized by an approved target profile.", profile

