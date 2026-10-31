"""Unit and integration tests for API Security Hardening, Rate Limiting, and CORS.

Covers:
1. Request body size limit enforcement (HTTP 413 for payloads > 1MB).
2. Sliding-window rate limiter per client IP (HTTP 429 Too Many Requests).
3. Backend target URL structure and ScopeGuard validation (HTTP 400 Bad Request).
4. Safe error response masking preventing internal stack trace disclosure.
5. Strict CORS header enforcement against untrusted origins.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.api.security import assessment_creation_limiter, validate_target_url, RateLimiter
from backend.core.scope_guard import ScopeGuard


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_limiter():
    assessment_creation_limiter.reset()
    yield
    assessment_creation_limiter.reset()


@pytest.mark.security
def test_payload_size_limit_rejection(client):
    """Payloads exceeding 1MB (1,048,576 bytes) are rejected with HTTP 413 Request Entity Too Large."""
    # Send a request with Content-Length > 1MB
    oversized_headers = {
        "Content-Length": "1048577",
        "Content-Type": "application/json",
    }
    # Using low-level client request
    res = client.post(
        "/api/assessments",
        headers=oversized_headers,
        content=b"x" * 1048577,
    )
    assert res.status_code == 413
    assert "too large" in res.json()["detail"].lower()


@pytest.mark.security
def test_sliding_window_rate_limiter_logic():
    """Unit test for RateLimiter sliding window tracking."""
    limiter = RateLimiter(max_requests=3, window_seconds=10.0)
    key = "test_client_ip"

    ok1, rem1, retry1 = limiter.is_allowed(key)
    assert ok1 is True
    assert rem1 == 2

    ok2, rem2, retry2 = limiter.is_allowed(key)
    assert ok2 is True
    assert rem2 == 1

    ok3, rem3, retry3 = limiter.is_allowed(key)
    assert ok3 is True
    assert rem3 == 0

    # 4th request exceeds max
    ok4, rem4, retry4 = limiter.is_allowed(key)
    assert ok4 is False
    assert rem4 == 0
    assert retry4 > 0


@pytest.mark.security
def test_api_rate_limiter_triggers_429(client):
    """Rapid assessment submissions exceeding rate limit trigger HTTP 429."""
    limiter_key = "testclient"
    # Exhaust rate limit quota
    for _ in range(assessment_creation_limiter.max_requests):
        assessment_creation_limiter.is_allowed(limiter_key)

    res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
    assert res.status_code == 429
    assert "rate limit exceeded" in res.json()["detail"].lower()
    assert "retry-after" in res.headers


@pytest.mark.security
def test_target_url_validation_structure_and_scope():
    """Validates URL parsing and ScopeGuard authorization enforcement."""
    # Valid allowlisted URL
    clean, check = validate_target_url("http://localhost:3000/")
    assert clean == "http://localhost:3000"
    assert check.is_allowed is True

    # Out of scope domain raises HTTPException 400
    with pytest.raises(Exception) as exc_info:
        validate_target_url("http://external-bank.com")
    assert "scope violation" in str(exc_info.value).lower()

    # Invalid scheme (javascript / ftp) raises HTTPException 400
    with pytest.raises(Exception) as exc_info2:
        validate_target_url("ftp://localhost:3000")
    assert "invalid url scheme" in str(exc_info2.value).lower()


@pytest.mark.security
def test_api_rejects_malformed_url(client):
    """Submitting malformed or non-http URLs returns HTTP 400."""
    res = client.post("/api/assessments", json={"target_url": "javascript:alert(1)"})
    assert res.status_code == 400
    assert "invalid url" in res.json()["detail"].lower()


@pytest.mark.security
def test_safe_error_masking_without_tracebacks(client):
    """Querying non-existent assessment returns 404 JSON detail without Python traceback."""
    res = client.get("/api/assessments/non_existent_scan_id_999")
    assert res.status_code == 404
    data = res.json()
    assert "detail" in data
    assert "Traceback (most recent call last)" not in json.dumps(data)


@pytest.mark.security
def test_cors_headers_restricted_to_allowlisted_origins(client):
    """Untrusted origins do not receive permissive Access-Control-Allow-Origin headers."""
    untrusted_origin = "https://malicious-attacker-website.com"
    res = client.options(
        "/api/assessments",
        headers={
            "Origin": untrusted_origin,
            "Access-Control-Request-Method": "POST",
        },
    )
    # The untrusted origin must NOT be reflected
    allow_origin = res.headers.get("access-control-allow-origin")
    assert allow_origin != untrusted_origin
