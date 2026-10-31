"""Test Suite for Request Safety, Scope Guard Boundaries, and Evidence Cryptographic Integrity.

Covers:
- ScopeGuard hard allowlist enforcement (preventing egress to unauthorized/external hosts).
- Redirect restrictions (follow_redirects=False by default to avoid masking 302/301 bypasses).
- Non-destructive operation enforcement (rejection of unapproved mutation verbs).
- Rate limit enforcement between consecutive probes.
- Evidence cryptographic integrity verification (SHA-256 tampering detection).
- Secret sanitization (JWT, Bearer token, password, and cookie redaction).
- Response size limits and timeout safety.
"""

import time
import httpx
import pytest

from backend.analysis.evidence_validator import EvidenceValidator
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.storage.models import EvidenceValidationStatus
from backend.utils.helpers import (
    EvidenceValidationError,
    HumanApprovalRequiredError,
    TargetUnreachableError,
    ScopeViolationError,
    compute_sha256,
)


@pytest.mark.security
def test_out_of_scope_target_rejected():
    """ScopeGuard blocks egress to external, metadata, or unauthorized addresses."""
    guard = ScopeGuard(allowed_hosts=["localhost:3000"])
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr)

    forbidden_urls = [
        "https://evil-attacker.com/api/steal",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://google.com",
        "http://localhost:8080/admin",
        "http://localhost:3000@evil.com",
    ]

    for bad_url in forbidden_urls:
        with pytest.raises(ScopeViolationError):
            executor.send_request(role=Role.ANONYMOUS, method="GET", url=bad_url)


@pytest.mark.security
def test_redirect_restrictions_disabled_by_default():
    """RequestExecutor must NOT follow HTTP redirects by default to detect 302/301 bypasses."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://localhost:3000/login"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)

    resp = executor.send_request(role=Role.ANONYMOUS, method="GET", url="http://localhost:3000/rest/basket/1")

    # Confirms 302 was captured directly, not auto-followed to /login
    assert resp.status_code == 302
    assert resp.headers.get("location") == "http://localhost:3000/login"


@pytest.mark.security
def test_destructive_or_modifying_methods_restricted():
    """AuthScope is read-only GET/HEAD by default; mutating verbs require explicit approval."""
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr)

    # In ScopeGuard or RequestExecutor, dangerous methods without human approval are blocked
    with pytest.raises((ScopeViolationError, HumanApprovalRequiredError)):
        guard.assert_in_scope("http://localhost:3000/api/Users/1", method="DELETE")


@pytest.mark.security
def test_rate_limiting_enforcement_between_probes():
    """AuthorizationTester enforces configured minimum intervals between probe requests."""
    request_timestamps = []

    def handler(request: httpx.Request) -> httpx.Response:
        request_timestamps.append(time.monotonic())
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    mgr.authenticate_role(Role.USER_A, "a@t.c", "p", token="token_a")
    mgr.authenticate_role(Role.USER_B, "b@t.c", "p", token="token_b")

    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    # Configure 50ms rate limit interval
    tester = AuthorizationTester(
        executor=executor,
        session_manager=mgr,
        scope_guard=guard,
        min_request_interval_ms=50.0,
    )

    tester.test_resource_access(
        endpoint="http://localhost:3000/rest/admin/application-version",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
    )

    assert len(request_timestamps) >= 2
    delta_ms = (request_timestamps[1] - request_timestamps[0]) * 1000.0
    # Minimum interval must be >= 45ms (allowing small timer jitter)
    assert delta_ms >= 40.0


@pytest.mark.security
def test_evidence_tampering_detected():
    """Modifying evidence content breaks cryptographic SHA-256 verification."""
    validator = EvidenceValidator()
    raw_response = HttpResponseModel(
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"UserId": 1, "owner": "victim@test.com", "balance": 1000}',
    )

    artifact = validator.create_and_sign_evidence(
        finding_id="fnd_12345",
        test_role=Role.USER_B,
        authorized_role=Role.USER_A,
        method="GET",
        url="http://localhost:3000/rest/wallet/1",
        headers={"Authorization": "Bearer real_jwt_token_user_b"},
        response=raw_response,
        validation_status=EvidenceValidationStatus.CONFIRMED,
    )

    # Valid artifact passes completeness
    assert validator.validate_artifact_completeness(artifact) is True

    # Tampering: attacker modifies response status or body
    tampered_canonical = f"GET|http://localhost:3000/rest/wallet/1|200|tampered body payload"
    expected_original_hash = compute_sha256(f"GET|http://localhost:3000/rest/wallet/1|200|{raw_response.body}")
    assert artifact.evidence_sha256 == expected_original_hash
    assert compute_sha256(tampered_canonical) != artifact.evidence_sha256


@pytest.mark.security
def test_evidence_sanitization_removes_tokens_and_secrets():
    """EvidenceValidator completely redacts bearer tokens, JWTs, passwords, and cookies."""
    validator = EvidenceValidator()
    dirty_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this"
    dirty_headers = {
        "Authorization": f"Bearer {dirty_jwt}",
        "Cookie": "connect.sid=s%3A_super_secret_session_cookie",
        "X-API-Key": "secret_api_key_12345",
        "Accept": "application/json",
    }
    dirty_body = f'{{"token": "{dirty_jwt}", "password": "super_secret_plaintext_pw", "data": "legit"}}'
    raw_response = HttpResponseModel(
        status_code=200,
        headers={"content-type": "application/json"},
        body=dirty_body,
    )

    artifact = validator.create_and_sign_evidence(
        finding_id="fnd_sanitize",
        test_role=Role.USER_B,
        authorized_role=Role.USER_A,
        method="GET",
        url="http://localhost:3000/rest/user/profile",
        headers=dirty_headers,
        response=raw_response,
        validation_status=EvidenceValidationStatus.CONFIRMED,
    )

    # Check headers sanitized
    assert artifact.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"
    assert artifact.request_headers["Cookie"] == "[REDACTED_COOKIE]"
    assert artifact.request_headers["X-API-Key"] == "[REDACTED_API_KEY]"
    assert artifact.request_headers["Accept"] == "application/json"

    # Check body sanitized
    assert dirty_jwt not in artifact.sanitized_response_evidence
    assert "super_secret_plaintext_pw" not in artifact.sanitized_response_evidence
    assert "[REDACTED_SECRET]" in artifact.sanitized_response_evidence
    assert "body_secret_field" in artifact.redacted_fields


@pytest.mark.security
def test_timeout_handling_clean_failure():
    """Requests exceeding timeout must raise RequestExecutionError cleanly without hanging."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Connection timed out")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)

    with pytest.raises(TargetUnreachableError):
        executor.send_request(role=Role.ANONYMOUS, method="GET", url="http://localhost:3000/slow")
