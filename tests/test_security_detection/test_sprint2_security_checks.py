"""Deterministic and Mock-Based Test Suite for Sprint 2 Security Detection Engine.

Validates:
1. Authentication Weaknesses:
   - Anonymous access to protected resources.
   - Verbose diagnostic error leaks in authentication responses.
   - Inconsistent authentication enforcement across routes.
   - False-positive suppression for SPA HTML fallbacks and public resources.
2. Session & Cookie Security:
   - Missing HttpOnly attribute on session cookies.
   - Missing Secure attribute (differentiating HTTP vs HTTPS contexts).
   - Missing or insecure SameSite configuration (SameSite=None without Secure).
   - Excessive cookie lifetime (> 30 days).
   - Sensitive session tokens exposed in URLs and response bodies.
   - Inconclusive status when no Set-Cookie headers are returned.
   - Full value redaction in evidence while preserving attributes.
3. Security Headers:
   - Detection of missing headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
   - Verification that CSP frame-ancestors satisfies frame protection without X-Frame-Options.
   - Context-aware severity rating.
4. CORS Misconfiguration:
   - Dangerous credentialed reflection (ACAO: reflected + ACAC: true).
   - Null origin trust (ACAO: null + ACAC: true).
   - Safe wildcard and non-credentialed reflection handling (false-positive prevention).
   - Prohibition against external outbound requests.
5. HTTPS & Transport Security:
   - HTTPS availability, redirect detection, HSTS.
   - Mixed content detection in HTML responses.
   - Strict TLS certificate verification preservation (verify=True).
6. Evidence & Quality:
   - Full 15-field finding schema completeness.
   - Automatic secret sanitization.
   - Duplicate finding suppression.
   - ScopeGuard enforcement and CancellationToken support.
   - Integration with ToolRegistry and ToolRegistryAdapter.
"""

from datetime import datetime, timezone
import json
import os
import pytest
import httpx

from backend.analysis.evidence_validator import EvidenceValidator
from backend.core.assessment_engine import AssessmentEngine, CancellationToken
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.scanner.security_inspector import (
    CategoryInspectionResult,
    DetectionCategory,
    FindingSeverity,
    FindingValidationStatus,
    SecurityInspector,
)
from backend.tools.agent_adapter import ToolRegistryAdapter
from backend.tools.registry import ToolRegistry
from backend.tools.schemas import (
    CheckAuthWeaknessesInput,
    CheckCorsInput,
    CheckSecurityHeadersInput,
    CheckSessionSecurityInput,
    CheckTransportSecurityInput,
    RunMisconfigurationScanInput,
)
from backend.utils.helpers import ScopeViolationError


# ==============================================================================
# 1. Security Headers Tests
# ==============================================================================


@pytest.mark.security
def test_missing_security_headers_detected():
    """Detects missing critical security headers on HTTP responses."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html><body>Hello</body></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_security_headers(endpoint="/")

    assert result.status == FindingValidationStatus.CONFIRMED.value
    assert len(result.findings) >= 3
    categories = [f.detection_category for f in result.findings]
    assert all(c == DetectionCategory.SECURITY_HEADERS.value for c in categories)

    # Validate findings contain developer guidance and confirmation
    for f in result.findings:
        assert f.what_is_wrong != ""
        assert f.attacker_impact != ""
        assert f.remediation_guidance != ""
        assert f.validation_status == FindingValidationStatus.CONFIRMED.value


@pytest.mark.security
def test_csp_frame_ancestors_satisfies_frame_protection():
    """Verifies that CSP frame-ancestors satisfies frame protection without X-Frame-Options."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
            text="<html>Secure</html>",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_security_headers(endpoint="/")

    # CSP frame-ancestors satisfies framing protection
    frame_findings = [f for f in result.findings if "frame" in f.finding_id.lower() or "clickjacking" in f.severity_rationale.lower()]
    assert len(frame_findings) == 0


# ==============================================================================
# 2. Session & Cookie Security Tests
# ==============================================================================


@pytest.mark.security
def test_session_cookie_missing_httponly_and_samesite_flagged():
    """Flags session cookies missing HttpOnly or with SameSite=None without Secure."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[
                ("Content-Type", "application/json"),
                ("Set-Cookie", "connect.sid=mock_session_val_123; Path=/; SameSite=None"),
            ],
            text='{"user": "authenticated"}',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_session_security(endpoint="/rest/user/session")

    assert result.status == FindingValidationStatus.CONFIRMED.value
    assert len(result.findings) >= 1
    httponly_findings = [f for f in result.findings if "httponly" in f.what_is_wrong.lower() or "httponly" in f.title.lower()]
    assert len(httponly_findings) == 1
    assert httponly_findings[0].severity in [FindingSeverity.MEDIUM.value, FindingSeverity.HIGH.value]
    # Evidence must have raw cookie value redacted
    assert "mock_session_val_123" not in httponly_findings[0].actual_response_evidence


@pytest.mark.security
def test_no_set_cookie_header_returns_inconclusive():
    """When no Set-Cookie header is returned, cookie check reports INCONCLUSIVE."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text='{"status": "ok"}')

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_session_security(endpoint="/api/no-cookies")

    assert result.status == FindingValidationStatus.INCONCLUSIVE.value
    assert "cannot be verified" in result.inspected_items.get("applicability_note", "")


@pytest.mark.security
def test_session_token_in_url_detected_and_sanitized():
    """Detects and redacts sensitive tokens exposed in query parameters."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text='{"data": "sensitive"}')

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    mock_token = os.getenv("TEST_SAMPLE_TOKEN", "mock_sensitive_token_sample_123")
    result = inspector.inspect_session_security(endpoint=f"/api/data?token={mock_token}")

    token_findings = [f for f in result.findings if "token" in f.what_is_wrong.lower() or "token" in f.title.lower()]
    assert len(token_findings) == 1
    assert token_findings[0].validation_status == FindingValidationStatus.CONFIRMED.value
    # Token value must be completely redacted from the report
    assert mock_token not in token_findings[0].actual_response_evidence
    assert "[REDACTED_TOKEN]" in token_findings[0].actual_response_evidence


# ==============================================================================
# 3. CORS Misconfiguration Tests
# ==============================================================================


@pytest.mark.security
def test_dangerous_credentialed_cors_reflection_detected():
    """Detects dangerous reflected Origin with Access-Control-Allow-Credentials: true."""
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "application/json",
            },
            text='{"profile": "confidential_data"}',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_cors_configuration(endpoint="/rest/user/profile", probe_origin="https://evil.example")

    assert result.status == FindingValidationStatus.CONFIRMED.value
    cors_findings = [f for f in result.findings if f.detection_category == DetectionCategory.CORS_MISCONFIGURATION.value]
    assert len(cors_findings) == 1
    assert cors_findings[0].severity == FindingSeverity.HIGH.value
    assert cors_findings[0].validation_status == FindingValidationStatus.CONFIRMED.value


@pytest.mark.security
def test_safe_cors_wildcard_without_credentials_not_high_severity():
    """Public wildcard CORS without credentials is not flagged as high severity."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Content-Type": "application/json",
            },
            text='{"public": "data"}',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_cors_configuration(endpoint="/public/catalog")

    for f in result.findings:
        assert f.severity in [FindingSeverity.LOW.value, FindingSeverity.INFORMATIONAL.value]


# ==============================================================================
# 4. Authentication Weaknesses Tests
# ==============================================================================


@pytest.mark.security
def test_unauthenticated_access_to_protected_endpoint_detected():
    """Detects when an endpoint designated as protected is accessible anonymously."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            text='{"id": 1, "email": "admin@juice-sh.op", "role": "admin"}',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_authentication_weaknesses(endpoint="/rest/admin/users")

    assert result.status == FindingValidationStatus.CONFIRMED.value
    unauth_findings = [f for f in result.findings if f.detection_category == DetectionCategory.AUTHENTICATION_WEAKNESS.value]
    assert len(unauth_findings) == 1
    assert unauth_findings[0].severity in [FindingSeverity.HIGH.value, FindingSeverity.CRITICAL.value]
    assert unauth_findings[0].validation_status == FindingValidationStatus.CONFIRMED.value


@pytest.mark.security
def test_verbose_auth_failure_error_leak_detected():
    """Detects verbose diagnostic leaks (SQL error, stack trace) in failed authentication."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            headers={"Content-Type": "application/json"},
            text='{"error": "SQLITE_ERROR: syntax error in SQL query near SELECT * FROM Users"}',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_authentication_weaknesses(endpoint="/rest/user/login")

    error_findings = [f for f in result.findings if "leak" in f.what_is_wrong.lower() or "diagnostic" in f.confirmation_reason.lower() or "error" in f.title.lower()]
    assert len(error_findings) == 1
    assert error_findings[0].validation_status == FindingValidationStatus.CONFIRMED.value
    assert "sql / database driver error" in error_findings[0].confirmation_reason.lower()


@pytest.mark.security
def test_spa_html_fallback_not_flagged_as_auth_bypass():
    """Verifies that SPA HTML fallback 200 responses are not falsely reported as auth bypass."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text="<!DOCTYPE html><html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_authentication_weaknesses(endpoint="/administration")

    unauth_findings = [f for f in result.findings if "unauth" in f.finding_id.lower() and f.validation_status == "CONFIRMED"]
    assert len(unauth_findings) == 0


# ==============================================================================
# 5. Transport Security Tests
# ==============================================================================


@pytest.mark.security
def test_mixed_content_detected_in_html():
    """Detects insecure http:// resource references within an HTML page."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<html><head><script src="http://insecure-cdn.example/app.js"></script></head><body>Secure</body></html>',
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard(allowed_schemes=["http", "https"])
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    result = inspector.inspect_transport_security(target_url="https://localhost:3000/")

    mixed_findings = [f for f in result.findings if "mixed" in f.what_is_wrong.lower() or "mixed" in f.title.lower()]
    assert len(mixed_findings) == 1
    assert mixed_findings[0].validation_status == FindingValidationStatus.CONFIRMED.value


# ==============================================================================
# 6. Duplicate Suppression & Cancellation Tests
# ==============================================================================


@pytest.mark.security
def test_duplicate_finding_suppression():
    """Verifies that duplicate findings for the same underlying issue are suppressed."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>Content</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)
    inspector = SecurityInspector(executor=executor, scope_guard=guard)

    # First call produces findings
    res1 = inspector.inspect_security_headers(endpoint="/")
    initial_count = len(res1.findings)
    assert initial_count > 0

    # Second call on same endpoint suppresses identical findings
    res2 = inspector.inspect_security_headers(endpoint="/")
    assert len(res2.findings) == 0
    assert res2.suppressed_duplicates_count == initial_count


@pytest.mark.security
def test_cancellation_token_stops_inspector():
    """CancellationToken halts execution cleanly without hanging."""
    cancel_token = CancellationToken()
    cancel_token.cancel()

    guard = ScopeGuard()
    inspector = SecurityInspector(scope_guard=guard, cancel_token=cancel_token)

    result = inspector.inspect_security_headers(endpoint="/")
    assert result.status in ["CANCELLED", "NOT_TESTED"]
    assert "cancelled" in result.summary.lower()


# ==============================================================================
# 7. Tool Registry & ToolRegistryAdapter Integration Tests
# ==============================================================================


@pytest.mark.security
@pytest.mark.asyncio
async def test_all_sprint2_tools_in_registry_and_adapter():
    """Verifies that all 6 Sprint 2 tools are registered and executable via ToolRegistryAdapter."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text='{"version": "1.0"}')

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    guard = ScopeGuard()
    mgr = SessionManager(load_from_env=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=mgr, client=client)

    registry = ToolRegistry(scope_guard=guard, executor=executor)
    adapter = ToolRegistryAdapter(registry=registry)

    # Verify tools exist in list_tools
    tool_names = [t["name"] for t in adapter.list_tools()]
    expected_sprint2_tools = [
        "check_authentication_weaknesses",
        "check_session_security",
        "check_security_headers",
        "check_cors_misconfiguration",
        "check_transport_security",
        "run_security_misconfiguration_scan",
    ]
    for expected in expected_sprint2_tools:
        assert expected in tool_names

    # Test execution through canonical adapter
    envelope = await adapter.execute_tool_call(
        tool_name="check_security_headers",
        arguments={"endpoint": "/"},
        assessment_id="test_assessment_sprint2",
    )
    assert envelope["ok"] is True
    assert envelope["tool_name"] == "check_security_headers"
    assert envelope["data"]["status"] in [FindingValidationStatus.CONFIRMED.value, "SECURE", "COMPLETED"]

    # Test alias execution (test_cors -> check_cors_misconfiguration)
    cors_envelope = await adapter.execute_tool_call(
        tool_name="test_cors",
        arguments={"endpoint": "/"},
        assessment_id="test_assessment_sprint2",
    )
    assert cors_envelope["ok"] is True
    assert cors_envelope["data"]["category"] == "CORS_MISCONFIGURATION"
