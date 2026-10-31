"""Mocked integration coverage for GitHub App authorization and scans."""

from __future__ import annotations

import base64
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend.api.app import _GitHubCallbackAccessLogFilter, app
from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.config import settings
from backend.core.scope_guard import ScopeCheckResult
from backend.github_integration import GitHubAppService, GitHubIntegrationError, GitHubSourceReview
from backend.scanner.source_analyzer import SourceFinding, SupportedLanguage
from backend.storage.database import DatabaseManager
from backend.storage.github_repository import GitHubRepository


class _AllowedProviderScope:
    def validate_request(self, url: str, method: str = "GET") -> ScopeCheckResult:
        return ScopeCheckResult(is_allowed=True, target_url=url, method=method, reason="mock allowed")


class _FakeGemini:
    is_configured = True

    async def agenerate_structured(self, prompt: str, response_schema: Any, **kwargs: Any) -> GitHubSourceReview:
        assert "untrusted data" in prompt
        assert "private-token-must-never-leak" not in prompt
        assert "ghu_" not in prompt
        return GitHubSourceReview(
            simple_title="Possible unsafe database query",
            what_is_the_problem="The code builds a query from a request value.",
            what_attacker_can_do="An attacker may change the input to alter the query if the value is not safely bound.",
            affected_data_or_users="Records returned by this query could be affected.",
            why_it_happens="The request value is interpolated into SQL.",
            how_to_fix=["Use a parameterized query."],
            recommended_code_change="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            tests_to_add=["Assert user input is passed as a query parameter."],
            limitations=["Static analysis does not prove runtime exploitability."],
        )


def _github_handler(method: str, url: str, body: bytes, headers: httpx.Headers) -> httpx.Response:
    parsed = urlparse(url)
    path = parsed.path
    query = parse_qs(parsed.query)
    if parsed.hostname == "github.com" and path == "/login/oauth/access_token":
        return httpx.Response(200, json={"access_token": "mock_access_token", "refresh_token": "mock_refresh_token", "expires_in": 28800})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/user":
        return httpx.Response(200, json={"id": 77, "login": "example-dev", "avatar_url": "https://avatars.example.invalid/77"})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/user/installations":
        return httpx.Response(200, json={"installations": [{
            "id": 81,
            "account": {"login": "sample-org", "type": "Organization"},
            "permissions": {"contents": "read", "metadata": "read"},
        }]})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/user/installations/81/repositories":
        if query.get("page") == ["2"]:
            return httpx.Response(200, json={"total_count": 1, "repositories": []})
        return httpx.Response(200, json={"total_count": 1, "repositories": [{
            "id": 901, "name": "demo", "full_name": "sample-org/demo", "owner": {"login": "sample-org"},
            "private": True, "description": "Test repository", "default_branch": "main", "html_url": "https://github.com/sample-org/demo",
        }]})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/repos/sample-org/demo/branches":
        return httpx.Response(200, json=[{"name": "main", "commit": {"sha": "a" * 40}}])
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/repos/sample-org/demo/git/commits/" + "a" * 40:
        return httpx.Response(200, json={"sha": "a" * 40, "tree": {"sha": "c" * 40}})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/repos/sample-org/demo/git/trees/" + "c" * 40:
        code = b"def load_user(request, db):\n    user_id = request.query_params.get('id')\n    return db.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        return httpx.Response(200, json={"truncated": False, "tree": [{"path": "app.py", "mode": "100644", "type": "blob", "sha": "b" * 40, "size": len(code)}]})
    if parsed.hostname == "api.github.com" and method == "GET" and path == "/repos/sample-org/demo/git/blobs/" + "b" * 40:
        code = b"def load_user(request, db):\n    user_id = request.query_params.get('id')\n    return db.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(code).decode("ascii")})
    if parsed.hostname == "api.github.com" and method == "DELETE" and path == "/applications/test-client/grant":
        return httpx.Response(204)
    return httpx.Response(404, json={"message": "not mocked"})


@pytest.fixture
def github_setup(monkeypatch: pytest.MonkeyPatch) -> tuple[GitHubRepository, GitHubAppService]:
    db = DatabaseManager(":memory:")
    db.init_schema()
    repository = GitHubRepository(db)
    transport = httpx.MockTransport(
        lambda request: _github_handler(request.method, str(request.url), request.content, request.headers)
    )
    service = GitHubAppService(
        repository=repository,
        transport=transport,
        gemini_client=_FakeGemini(),
        scope_guard=_AllowedProviderScope(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(settings, "github_client_id", "test-client")
    monkeypatch.setattr(settings, "github_client_secret", "test-secret")
    monkeypatch.setattr(settings, "github_callback_url", "http://localhost:8000/api/github/callback")
    monkeypatch.setattr(settings, "github_frontend_url", "http://localhost:3001")
    monkeypatch.setattr(settings, "github_app_slug", "authscope-test")
    monkeypatch.setattr(settings, "github_token_encryption_key", Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(settings, "github_session_cookie_secure", False)
    app.state.github_repository = repository
    app.state.github_service = service
    return repository, service


def test_oauth_state_installation_repository_branch_and_disconnect(github_setup: tuple[GitHubRepository, GitHubAppService]) -> None:
    repository, _service = github_setup
    with TestClient(app) as client:
        start = client.get("/api/github/connect", follow_redirects=False)
        assert start.status_code == 302
        authorization = parse_qs(urlparse(start.headers["location"]).query)
        state = authorization["state"][0]
        assert authorization["client_id"] == ["test-client"]
        assert start.headers["set-cookie"].lower().find("httponly") >= 0

        callback = client.get("/api/github/callback", params={"state": state, "code": "mock-code"}, follow_redirects=False)
        assert "github_status=connected" in callback.headers["location"]
        session = client.cookies.get("authscope_github_session")
        assert session
        connection = repository.get_connection("77")
        assert connection
        assert "mock_access_token" not in connection["encrypted_credentials"]

        status_response = client.get("/api/github/status")
        assert status_response.json()["connected"] is True
        assert status_response.json()["account"]["login"] == "example-dev"
        assert status_response.json()["installations"][0]["id"] == 81

        install_start = client.get("/api/github/install", follow_redirects=False)
        install_state = parse_qs(urlparse(install_start.headers["location"]).query)["state"][0]
        assert "github.com/apps/authscope-test/installations/new" in install_start.headers["location"]
        install_callback = client.get(
            "/api/github/callback",
            params={"state": install_state, "installation_id": 81, "setup_action": "install"},
            follow_redirects=False,
        )
        assert "github_status=installed" in install_callback.headers["location"]

        repositories = client.get("/api/github/installations/81/repositories").json()["repositories"]
        assert repositories == [{
            "id": 901, "name": "demo", "full_name": "sample-org/demo", "owner": "sample-org", "private": True,
            "description": "Test repository", "default_branch": "main", "html_url": "https://github.com/sample-org/demo",
        }]
        branches = client.get("/api/github/installations/81/repositories/sample-org/demo/branches").json()["branches"]
        assert branches == [{"name": "main", "commit_sha": "a" * 40}]

        replay = client.get("/api/github/callback", params={"state": state, "code": "mock-code"}, follow_redirects=False)
        assert "state_error" in replay.headers["location"]

        disconnected = client.delete("/api/github/disconnect", headers={"Origin": "http://localhost:3001"})
        assert disconnected.status_code == 200
        assert disconnected.json() == {"connected": False, "revoked": True}
        assert repository.get_connection("77") is None
        assert client.get("/api/github/status").json()["connected"] is False


@pytest.mark.asyncio
async def test_scan_fetches_only_installed_commit_and_adds_advisory_ai_review(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    repository, service = github_setup
    repository.save_connection(
        "77", "example-dev", "", service.encrypt_credentials("mock_access_token", "mock_refresh_token"), None
    )
    repository.save_installation("77", 81, "sample-org", "Organization")
    events: list[tuple[str, str]] = []
    result = await service.scan_repository(
        "77", 81, "sample-org", "demo", "main", "a" * 40, "gscan_test",
        lambda event_type, stage, message, metadata: events.append((event_type, stage)),
    )
    assert result["commit_sha"] == "a" * 40
    assert result["candidate_files"] == 1
    assert "python" in result["languages"]
    assert result["findings"]
    assert events[0] == ("activity", "repository_read")
    for finding in result["findings"]:
        assert finding["source_type"] == "SOURCE_CODE_FINDING"
        assert finding["runtime_status"] == "NOT_TESTED"
        assert finding["commit_sha"] == "a" * 40
        assert "/blob/" + "a" * 40 + "/" in finding["github_url"]
        assert finding["ai_review"]["status"] == "available"


@pytest.mark.asyncio
async def test_expiring_token_refreshes_without_exposing_secrets(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    repository, service = github_setup
    repository.save_connection(
        "77", "example-dev", "", service.encrypt_credentials("old-token", "valid-refresh"),
        "2000-01-01T00:00:00+00:00",
    )
    refreshed = await service.access_token("77")
    assert refreshed == "mock_access_token"
    updated = repository.get_connection("77")
    assert updated and "mock_access_token" not in updated["encrypted_credentials"]
    assert updated["expires_at"] > datetime.now(timezone.utc).isoformat()


@pytest.mark.asyncio
async def test_github_rate_limit_and_unexpected_redirect_are_safe_errors(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    _repository, _service = github_setup

    async def limited_request() -> None:
        limited = GitHubAppService(
            transport=httpx.MockTransport(lambda req: httpx.Response(403, headers={"X-RateLimit-Remaining": "0"})),
            scope_guard=_AllowedProviderScope(),  # type: ignore[arg-type]
        )
        await limited._request("GET", "https://api.github.com/user", token="never-log-this")

    with pytest.raises(GitHubIntegrationError) as rate_error:
        await limited_request()
    assert rate_error.value.code == "GITHUB_RATE_LIMIT"

    redirect = GitHubAppService(
        transport=httpx.MockTransport(lambda req: httpx.Response(302, headers={"Location": "https://attacker.invalid/"})),
        scope_guard=_AllowedProviderScope(),  # type: ignore[arg-type]
    )
    with pytest.raises(GitHubIntegrationError) as redirect_error:
        await redirect._request("GET", "https://api.github.com/user", token="never-log-this")
    assert redirect_error.value.code == "GITHUB_REDIRECT_REJECTED"


def test_scan_and_connection_records_are_isolated_by_github_user(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    repository, service = github_setup
    for user_id in ("user-a", "user-b"):
        repository.save_connection(user_id, user_id, "", service.encrypt_credentials(f"token-{user_id}"), None)
    now = datetime.now(timezone.utc).isoformat()
    repository.create_scan({
        "id": "gscan_user_a", "github_user_id": "user-a", "installation_id": 1,
        "repository_id": 10, "owner": "org", "repository": "repo", "branch": "main",
        "commit_sha": "c" * 40, "status": "COMPLETED", "created_at": now,
        "findings": [{"id": "finding-a"}],
    })
    assert repository.get_scan("gscan_user_a", "user-b") is None
    assert repository.list_scans("user-b") == []


@pytest.mark.asyncio
async def test_gemini_review_redacts_github_credentials_from_source_excerpt(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    _repository, service = github_setup
    finding = SourceFinding(
        finding_id="src_secret_test",
        rule_id="TEST-SECRET",
        vulnerability_category="SENSITIVE_DATA_EXPOSURE",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="app.py",
        language=SupportedLanguage.PYTHON,
        start_line=1,
        end_line=1,
        code_snippet="token = 'ghu_abcdefghijklmnopqrstuvwxyz1234567890'",
        detection_explanation="Credential-like token present in test source.",
        detection_method="test",
    )
    review = await service._review_source_finding(finding)
    assert review["status"] == "available"
    assert review["what_is_the_problem"]


def test_uvicorn_access_logs_redact_github_callback_query() -> None:
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 1, '%s - "%s %s HTTP/%s" %d',
        ("client", "GET", "/api/github/callback?code=authorization-code-secret&state=csrf-state-secret", "1.1", 302), None,
    )
    assert _GitHubCallbackAccessLogFilter().filter(record)
    message = record.getMessage()
    assert "authorization-code-secret" not in message
    assert "csrf-state-secret" not in message
    assert "/api/github/callback?[REDACTED]" in message


def test_scan_endpoint_pins_branch_commit_and_streams_real_events(
    github_setup: tuple[GitHubRepository, GitHubAppService],
) -> None:
    with TestClient(app) as client:
        start = client.get("/api/github/connect", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        client.get("/api/github/callback", params={"state": state, "code": "mock-code"}, follow_redirects=False)
        install = client.get("/api/github/install", follow_redirects=False)
        install_state = parse_qs(urlparse(install.headers["location"]).query)["state"][0]
        client.get(
            "/api/github/callback", params={"state": install_state, "installation_id": 81, "setup_action": "install"},
            follow_redirects=False,
        )
        response = client.post(
            "/api/github/scans",
            headers={"Origin": "http://localhost:3001"},
            json={"installation_id": 81, "owner": "sample-org", "repository": "demo", "branch": "main"},
        )
        assert response.status_code == 202
        created = response.json()
        assert created["commit_sha"] == "a" * 40
        scan_id = created["scan_id"]

        for _ in range(50):
            detail = client.get(f"/api/github/scans/{scan_id}").json()
            if detail["status"] in {"COMPLETED", "FAILED"}:
                break
            time.sleep(0.05)
        stream = client.get(f"/api/github/scans/{scan_id}/stream")
        assert stream.status_code == 200
        assert "event: activity" in stream.text
        assert '"stage": "repository_read"' in stream.text
        assert "event: done" in stream.text

        detail = client.get(f"/api/github/scans/{scan_id}").json()
        assert detail["status"] == "COMPLETED"
        assert detail["commit_sha"] == "a" * 40
        assert detail["findings"]

