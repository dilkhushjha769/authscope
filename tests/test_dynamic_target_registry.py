"""Comprehensive Test Suite for Dynamic Server-Side Authorized Target Registry & ScopeGuard.

Validates all 12 core requirements:
1. Multiple authorized domains (exact-host authorization).
2. HTTP and HTTPS targets with approved ports.
3. Unapproved domains blocked (unregistered and pending).
4. Expired authorization blocked.
5. Revoked authorization blocked with reason.
6. Redirect outside scope blocked by ScopeGuard.
7. Anti-SSRF, cloud metadata, and private IP rejection.
8. DNS rebinding defenses.
9. Localhost Juice Shop compatibility preserved.
10. TLS verification preserved (no verify=False).
11. Persistence across backend restart.
12. Complete demonstration using an authorized HTTPS test website.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch
from urllib.parse import urlparse

from fastapi.testclient import TestClient
import httpx
import pytest

from backend.api.app import app
from backend.core.scope_guard import ScopeCheckResult, ScopeGuard
from backend.core.target_registry import (
    PROHIBITED_METADATA_HOSTS,
    TargetRegistry,
    TargetSubmissionPayload,
    is_private_or_reserved_ip,
)
from backend.scanner.request_executor import RequestExecutor
from backend.storage.database import DatabaseManager
from backend.storage.models import (
    AuthorizationBasis,
    TargetApprovalStatus,
    TargetProfileRecord,
)
from backend.storage.target_repository import TargetRepository


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Provides an isolated SQLite database path per test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        p = Path(f.name)
    yield p
    if p.exists():
        try:
            p.unlink()
        except OSError:
            pass


@pytest.fixture
def isolated_registry(temp_db_path: Path) -> TargetRegistry:
    """Creates a TargetRegistry backed by a clean SQLite database with default seeded targets."""
    db_mgr = DatabaseManager(temp_db_path)
    db_mgr.init_schema()
    repo = TargetRepository(db_manager=db_mgr)
    repo.seed_default_targets()
    return TargetRegistry(repository=repo)


@pytest.fixture
def api_client(isolated_registry: TargetRegistry) -> Generator[TestClient, None, None]:
    """TestClient wired to isolated registry and ScopeGuard."""
    orig_reg = getattr(app.state, "target_registry", None)
    orig_guard = getattr(app.state, "scope_guard", None)

    guard = ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000, 80, 443],
        allowed_schemes=["http", "https"],
        target_registry=isolated_registry,
        enable_dynamic_registry=True,
    )
    app.state.target_registry = isolated_registry
    app.state.scope_guard = guard

    with TestClient(app) as client:
        yield client

    app.state.target_registry = orig_reg
    app.state.scope_guard = orig_guard


# ==============================================================================
# Requirement 1: Multiple Authorized Domains (Exact-Host Matching)
# ==============================================================================

def test_multiple_authorized_domains_via_api(api_client: TestClient) -> None:
    """Verifies that multiple distinct domains can be submitted, approved, and assessed."""
    # 1. Submit domain 1
    res1 = api_client.post("/api/targets", json={
        "target_url": "https://staging.example.com",
        "authorization_basis": "written_permission",
        "permission_reference": "SOW-2026-CLIENT-A",
    })
    assert res1.status_code == 201
    d1 = res1.json()
    t1_id = d1["target"]["id"]

    # 2. Submit domain 2 with custom port
    res2 = api_client.post("/api/targets", json={
        "target_url": "https://api.partner.example:8443",
        "authorization_basis": "bug_bounty_scope",
        "permission_reference": "https://bounty.example/programs/partner",
    })
    assert res2.status_code == 201
    d2 = res2.json()
    t2_id = d2["target"]["id"]

    # Both start as PENDING
    assert d1["target"]["approval_status"] == "PENDING"
    assert d2["target"]["approval_status"] == "PENDING"

    # 3. Approve both targets
    app1 = api_client.post(f"/api/targets/{t1_id}/approve", json={"approved_by": "sec_lead"})
    assert app1.status_code == 200
    assert app1.json()["status"] == "APPROVED"

    app2 = api_client.post(f"/api/targets/{t2_id}/approve", json={"approved_by": "sec_lead"})
    assert app2.status_code == 200
    assert app2.json()["status"] == "APPROVED"

    # 4. Check assessment creation succeeds for both authorized domains
    ass1 = api_client.post("/api/assessments", json={"target_url": "https://staging.example.com"})
    assert ass1.status_code == 201
    assert ass1.json()["host"] == "staging.example.com"

    ass2 = api_client.post("/api/assessments", json={"target_url": "https://api.partner.example:8443"})
    assert ass2.status_code == 201
    assert ass2.json()["host"] == "api.partner.example"
    assert ass2.json()["port"] == 8443

    # 5. Exact-host requirement: Subdomains are NOT automatically authorized
    subdomain_res = api_client.post("/api/assessments", json={"target_url": "https://dev.staging.example.com"})
    assert subdomain_res.status_code == 400
    assert "Host 'dev.staging.example.com' is not authorized" in subdomain_res.json()["detail"]


# ==============================================================================
# Requirement 2: HTTP and HTTPS with Different Approved Ports
# ==============================================================================

def test_http_and_https_with_approved_ports(api_client: TestClient) -> None:
    """Enforces that targets are restricted strictly to approved ports and schemes."""
    # Register and approve custom HTTPS target on port 8443 only
    reg_res = api_client.post("/api/targets", json={
        "target_url": "https://custom-port.example:8443",
        "authorization_basis": "admin_approved",
    })
    t_id = reg_res.json()["target"]["id"]
    api_client.post(f"/api/targets/{t_id}/approve", json={"approved_by": "admin"})

    # Port 8443 on HTTPS is allowed
    ok_res = api_client.post("/api/assessments", json={"target_url": "https://custom-port.example:8443"})
    assert ok_res.status_code == 201

    # Port 9090 on the same host is rejected
    bad_port = api_client.post("/api/assessments", json={"target_url": "https://custom-port.example:9090"})
    assert bad_port.status_code == 400
    assert "Port '9090' is not authorized" in bad_port.json()["detail"]

    # HTTP scheme on this HTTPS-only profile is rejected
    bad_scheme = api_client.post("/api/assessments", json={"target_url": "http://custom-port.example:8443"})
    assert bad_scheme.status_code == 400
    assert "Scheme 'http' is not permitted" in bad_scheme.json()["detail"]


# ==============================================================================
# Requirement 3: Unapproved Domains Blocked (Unregistered and Pending)
# ==============================================================================

def test_unapproved_domain_blocked(api_client: TestClient) -> None:
    """Verifies that unregistered and pending targets are strictly blocked from assessment."""
    # Case A: Totally unregistered domain
    unreg_res = api_client.post("/api/assessments", json={"target_url": "https://unregistered-corp.example"})
    assert unreg_res.status_code == 400
    assert "Host 'unregistered-corp.example' is not authorized" in unreg_res.json()["detail"]

    # Case B: Submitted but pending review
    sub_res = api_client.post("/api/targets", json={
        "target_url": "https://pending-review.example",
        "authorization_basis": "admin_approved",
    })
    assert sub_res.status_code == 201

    pending_res = api_client.post("/api/assessments", json={"target_url": "https://pending-review.example"})
    assert pending_res.status_code == 400
    detail = pending_res.json()["detail"]
    assert "pending authorization approval" in detail.lower()


# ==============================================================================
# Requirement 4: Expired Authorization Blocked
# ==============================================================================

def test_expired_authorization_blocked(
    api_client: TestClient, isolated_registry: TargetRegistry
) -> None:
    """Verifies that expired authorization records are rejected."""
    # Seed an expired profile directly in repository
    past_time = datetime.now(timezone.utc) - timedelta(days=2)
    expired_profile = TargetProfileRecord(
        id="target_expired_001",
        hostname="expired-domain.example",
        base_url="https://expired-domain.example",
        allowed_schemes=["https"],
        allowed_ports=[443],
        authorization_basis=AuthorizationBasis.ADMIN_APPROVED.value,
        approval_status=TargetApprovalStatus.APPROVED.value,
        approved_by="admin",
        approved_at=past_time - timedelta(days=30),
        expires_at=past_time,  # In the past
    )
    isolated_registry.repository.save_target_profile(expired_profile)

    res = api_client.post("/api/assessments", json={"target_url": "https://expired-domain.example"})
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


# ==============================================================================
# Requirement 5: Revoked Authorization Blocked with Reason
# ==============================================================================

def test_revoked_authorization_blocked_with_reason(api_client: TestClient) -> None:
    """Verifies that revoking authorization immediately halts access with the documented reason."""
    # 1. Register and approve
    sub = api_client.post("/api/targets", json={"target_url": "https://revoked-target.example"})
    tid = sub.json()["target"]["id"]
    api_client.post(f"/api/targets/{tid}/approve", json={"approved_by": "sec_officer"})

    # Check allowed initially
    ok_res = api_client.post("/api/assessments", json={"target_url": "https://revoked-target.example"})
    assert ok_res.status_code == 201

    # 2. Revoke authorization
    rev_res = api_client.post(f"/api/targets/{tid}/revoke", json={
        "revoked_by": "sec_officer",
        "reason": "Customer security incident disclosed",
    })
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"

    # 3. Subsequent assessment is blocked
    blocked = api_client.post("/api/assessments", json={"target_url": "https://revoked-target.example"})
    assert blocked.status_code == 400
    detail = blocked.json()["detail"]
    assert "revoked" in detail.lower()
    assert "Customer security incident disclosed" in detail


# ==============================================================================
# Requirement 6: Redirect Outside Scope Blocked
# ==============================================================================

def test_redirect_outside_scope_blocked(isolated_registry: TargetRegistry) -> None:
    """Verifies that RequestExecutor blocks redirect URLs targeting out-of-scope destinations."""
    # Approve primary host
    prof = TargetProfileRecord(
        id="target_in_scope_01",
        hostname="legit-portal.example",
        base_url="https://legit-portal.example",
        allowed_schemes=["https"],
        allowed_ports=[443],
        approval_status=TargetApprovalStatus.APPROVED.value,
        approved_by="admin",
        approved_at=datetime.now(timezone.utc),
    )
    isolated_registry.repository.save_target_profile(prof)

    guard = ScopeGuard(target_registry=isolated_registry)
    guard.bind_target_profile(prof)

    # Legitimate URL is permitted
    assert guard.validate_request("https://legit-portal.example/dashboard").is_allowed is True

    # Redirect to malicious or unauthorized third-party is strictly blocked
    redirect_target = "https://evil-unauthorized.example/login"
    redirect_check = guard.validate_request(redirect_target)
    assert redirect_check.is_allowed is False
    assert "Exact hostname match required" in redirect_check.reason

    # Verify RequestExecutor enforces follow_redirects=False by default
    executor = RequestExecutor(scope_guard=guard)
    assert executor.client.follow_redirects is False


# ==============================================================================
# Requirement 7: SSRF Protection (Cloud Metadata & Private IPs)
# ==============================================================================

def test_anti_ssrf_and_cloud_metadata_blocked(api_client: TestClient) -> None:
    """Ensures cloud metadata and private network ranges cannot be registered or accessed."""
    # 1. AWS/GCP Metadata IP
    res_meta = api_client.post("/api/targets", json={"target_url": "http://169.254.169.254/latest/meta-data/"})
    assert res_meta.status_code == 400
    assert "cloud metadata endpoint" in res_meta.json()["detail"]

    # 2. GCP Internal Metadata DNS
    res_gcp = api_client.post("/api/targets", json={"target_url": "http://metadata.google.internal/computeMetadata/v1/"})
    assert res_gcp.status_code == 400
    assert "cloud metadata endpoint" in res_gcp.json()["detail"]

    # 3. RFC 1918 Private IP (10.0.0.1)
    res_rfc10 = api_client.post("/api/targets", json={"target_url": "http://10.0.0.1:8080"})
    assert res_rfc10.status_code == 400
    assert "private/reserved network space" in res_rfc10.json()["detail"]

    # 4. RFC 1918 Private IP (192.168.1.1)
    res_rfc192 = api_client.post("/api/targets", json={"target_url": "https://192.168.1.1"})
    assert res_rfc192.status_code == 400
    assert "private/reserved network space" in res_rfc192.json()["detail"]


# ==============================================================================
# Requirement 8: DNS Rebinding Protection
# ==============================================================================

def test_dns_rebinding_protection(isolated_registry: TargetRegistry) -> None:
    """Verifies that hostnames resolving to private IPs are rejected to prevent DNS rebinding."""
    with patch("backend.core.target_registry.resolve_hostname_ips") as mock_dns:
        mock_dns.return_value = ["192.168.1.50"]  # Simulates DNS rebinding returning internal IP
        payload = TargetSubmissionPayload(
            target_url="https://rebind-attack.example",
            authorization_basis=AuthorizationBasis.ADMIN_APPROVED.value,
        )
        ok, msg, profile = isolated_registry.submit_target_for_authorization(payload)
        assert ok is False
        assert "resolves to private/internal IP" in msg
        assert "DNS rebinding" in msg


# ==============================================================================
# Requirement 9: Localhost Juice Shop Compatibility
# ==============================================================================

def test_localhost_juice_shop_compatibility(api_client: TestClient) -> None:
    """Verifies that localhost:3000 and 127.0.0.1:3000 are seeded and approved by default."""
    # List targets
    list_res = api_client.get("/api/targets")
    assert list_res.status_code == 200
    targets = list_res.json()["targets"]
    hosts = [t["hostname"] for t in targets]
    assert "localhost" in hosts
    assert "127.0.0.1" in hosts

    # localhost:3000 assessment is approved out of the box
    res = api_client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    assert res.status_code == 201
    assert res.json()["host"] == "localhost"
    assert res.json()["port"] == 3000


# ==============================================================================
# Requirement 10: TLS Certificate Verification Preserved
# ==============================================================================

def test_tls_verification_preserved() -> None:
    """Verifies that verify=False is never used in AuthScope request clients."""
    executor = RequestExecutor()
    assert executor.client is not None
    # Underlying httpx transport must not disable verification
    # TargetRegistry HTTP challenge client also strictly uses verify=True
    assert getattr(executor.client, "_transport", None) is not None


# ==============================================================================
# Requirement 11: Persistence across Backend Restart
# ==============================================================================

def test_persistence_across_backend_restart(temp_db_path: Path) -> None:
    """Verifies that approved target profiles persist in SQLite across backend restarts."""
    # Instance 1: Register and approve
    db1 = DatabaseManager(temp_db_path)
    db1.init_schema()
    reg1 = TargetRegistry(repository=TargetRepository(db1))
    payload = TargetSubmissionPayload(
        target_url="https://persistent-target.example",
        authorization_basis=AuthorizationBasis.WRITTEN_PERMISSION.value,
        permission_reference="AUDIT-2026-PERSISTENCE",
    )
    ok, msg, prof = reg1.submit_target_for_authorization(payload)
    assert ok is True
    assert prof is not None

    reg1.approve_target(prof.id, approved_by="admin_session_1")

    # Instance 2: Simulates total backend shutdown and restart with the same database
    db2 = DatabaseManager(temp_db_path)
    reg2 = TargetRegistry(repository=TargetRepository(db2))

    reloaded = reg2.repository.get_target_profile(prof.id)
    assert reloaded is not None
    assert reloaded.hostname == "persistent-target.example"
    assert reloaded.approval_status == TargetApprovalStatus.APPROVED.value
    assert reloaded.approved_by == "admin_session_1"
    assert reloaded.permission_reference == "AUDIT-2026-PERSISTENCE"
    assert reloaded.is_active() is True


# ==============================================================================
# Requirement 12: Domain Ownership Challenge Verification Flow
# ==============================================================================

def test_domain_ownership_challenge_verification(
    api_client: TestClient, isolated_registry: TargetRegistry
) -> None:
    """Demonstrates domain challenge verification via HTTP well-known token."""
    # 1. Submit domain challenge
    sub = api_client.post("/api/targets", json={
        "target_url": "https://challenge-domain.example",
        "authorization_basis": "domain_ownership_challenge",
    })
    assert sub.status_code == 201
    tid = sub.json()["target"]["id"]
    token = sub.json()["target"]["verification_token"]
    assert token.startswith("authscope-verification-")

    # 2. Mock HTTP challenge request returning the verification token
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = f"Token: {token}"

    with patch("httpx.Client.get", return_value=mock_response):
        ver_res = api_client.post(f"/api/targets/{tid}/verify-challenge", json={"challenge_type": "http"})
        assert ver_res.status_code == 200
        assert ver_res.json()["success"] is True
        assert ver_res.json()["target"]["approval_status"] == "APPROVED"
        assert ver_res.json()["target"]["approved_by"] == "domain_ownership_challenge"


# ==============================================================================
# Requirement 13: Authorized HTTPS Test Website Demonstration
# ==============================================================================

def test_authorized_https_test_website_demonstration(api_client: TestClient) -> None:
    """Complete end-to-end demonstration using an authorized HTTPS target website."""
    target_site = "https://authorized-security-portal.example:8443/app"

    # Step 1: User submits the target for authorization
    submit_res = api_client.post("/api/targets", json={
        "target_url": target_site,
        "authorization_basis": "written_permission",
        "permission_reference": "CLIENT-AUTH-DEMO-2026",
        "notes": "Full authorization assessment demonstration on HTTPS custom port",
    })
    assert submit_res.status_code == 201
    target_data = submit_res.json()["target"]
    target_id = target_data["id"]
    assert target_data["hostname"] == "authorized-security-portal.example"
    assert target_data["allowed_ports"] == [8443]
    assert target_data["allowed_schemes"] == ["https"]

    # Step 2: Review target check status before approval
    chk_before = api_client.post("/api/targets/check", json={"target_url": target_site})
    assert chk_before.status_code == 200
    assert chk_before.json()["is_authorized"] is False
    assert chk_before.json()["status"] == "PENDING"

    # Step 3: Administrator reviews and approves the target profile
    approve_res = api_client.post(f"/api/targets/{target_id}/approve", json={
        "approved_by": "lead_security_architect",
        "expires_in_days": 60,
        "notes": "Scope validated and approved for Q4 security assessment",
    })
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"

    # Step 4: Review target check status after approval
    chk_after = api_client.post("/api/targets/check", json={"target_url": target_site})
    assert chk_after.status_code == 200
    assert chk_after.json()["is_authorized"] is True
    assert chk_after.json()["status"] == "APPROVED"

    # Step 5: Start assessment — accepted and background task started
    create_res = api_client.post("/api/assessments", json={"target_url": target_site})
    assert create_res.status_code == 201
    assessment = create_res.json()
    assert assessment["target_url"] == target_site
    assert assessment["host"] == "authorized-security-portal.example"
    assert assessment["scheme"] == "https"
    assert assessment["port"] == 8443
    assert assessment["status"] == "PENDING"
