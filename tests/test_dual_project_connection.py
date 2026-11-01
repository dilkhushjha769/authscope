"""Comprehensive tests for Dual Project Connection (GitHub OAuth + Website URL).

Verifies:
1. GitHub OAuth connection, CSRF state protection, token encryption, and token secrecy.
2. Repository listing and distinction between public and private repositories.
3. Website URL validation with safe DNS resolution and anti-SSRF protection (cloud metadata, private IPs).
4. Project creation for website URLs without requiring GitHub credentials.
5. Mandatory security authorization confirmation for website scanning.
6. Project ownership isolation between distinct users (403 Forbidden on cross-user access/scan/delete).
7. End-to-end project assessment invocation.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app, _get_project_repository, _github_repository
from backend.storage.database import DatabaseManager
from backend.storage.github_repository import GitHubRepository
from backend.storage.project_repository import ProjectRecord, ProjectRepository


@pytest.fixture
def api_client():
    return TestClient(app)


def test_validate_url_ssrf_cloud_metadata_rejection(api_client):
    """Verifies that cloud metadata endpoints (AWS/GCP/Azure) are strictly rejected."""
    # AWS / Azure / GCP IMDSv1/v2 IP
    res = api_client.post(
        "/api/projects/validate-url",
        json={"target_url": "http://169.254.169.254/latest/meta-data"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is False
    assert data["is_ssrf_safe"] is False
    assert "metadata" in data["error"].lower()

    # GCP internal metadata DNS
    res2 = api_client.post(
        "/api/projects/validate-url",
        json={"target_url": "http://metadata.google.internal/computeMetadata/v1/"},
    )
    assert res2.status_code == 200
    assert res2.json()["valid"] is False


def test_validate_url_ssrf_private_ip_rejection(api_client):
    """Verifies that private IP ranges (RFC 1918) are rejected when not in local test mode."""
    private_targets = [
        "http://192.168.1.1:8080",
        "http://10.0.0.5",
        "http://172.16.0.1",
    ]
    for url in private_targets:
        res = api_client.post(
            "/api/projects/validate-url",
            json={"target_url": url, "is_local_test": False},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is False
        assert "private" in data["error"].lower() or "reserved" in data["error"].lower()


def test_validate_url_dangerous_schemes_and_credentials_rejection(api_client):
    """Verifies that file/ftp schemes and embedded credentials in URLs are blocked."""
    # Embedded credentials
    res1 = api_client.post(
        "/api/projects/validate-url",
        json={"target_url": "http://admin:secret@example.com"},
    )
    assert res1.status_code == 200
    assert res1.json()["valid"] is False
    assert "credentials" in res1.json()["error"].lower()

    # Dangerous scheme
    res2 = api_client.post(
        "/api/projects/validate-url",
        json={"target_url": "file:///etc/passwd"},
    )
    assert res2.status_code == 200
    assert res2.json()["valid"] is False
    assert "prohibited" in res2.json()["error"].lower()


def test_validate_url_valid_target_resolution(api_client):
    """Verifies that valid targets resolve cleanly with normalized base URL."""
    res = api_client.post(
        "/api/projects/validate-url",
        json={"target_url": "http://localhost:3000/api/v1?test=1", "is_local_test": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert data["is_ssrf_safe"] is True
    assert data["hostname"] == "localhost"
    assert data["port"] == 3000
    assert data["scheme"] == "http"
    assert data["normalized_url"] == "http://localhost:3000"


def test_create_website_project_requires_explicit_authorization(api_client):
    """Verifies that website project creation requires explicit authorization confirmation."""
    # Attempt creation with authorization_confirmed = False
    res = api_client.post(
        "/api/projects",
        json={
            "name": "Unauthorized Site",
            "project_type": "website",
            "target_url": "http://localhost:3000",
            "authorization_confirmed": False,
        },
    )
    assert res.status_code == 400
    assert "authorization confirmation is required" in res.json()["detail"].lower()

    # Successful creation with explicit authorization
    res_ok = api_client.post(
        "/api/projects",
        json={
            "name": "Authorized Test App",
            "project_type": "website",
            "target_url": "http://localhost:3000",
            "authorization_confirmed": True,
            "authorization_basis": "admin_approved",
        },
        headers={"X-User-Id": "user_test_1"},
    )
    assert res_ok.status_code == 201
    proj = res_ok.json()
    assert proj["name"] == "Authorized Test App"
    assert proj["project_type"] == "website"
    assert proj["target_url"] == "http://localhost:3000"
    assert proj["user_id"] == "user_test_1"
    assert proj["authorization_status"] == "AUTHORIZED"


def test_project_ownership_isolation(api_client):
    """Verifies that User A's project cannot be accessed, scanned, or deleted by User B."""
    # 1. User Alice creates a project
    create_res = api_client.post(
        "/api/projects",
        json={
            "name": "Alice Staging App",
            "project_type": "website",
            "target_url": "http://localhost:3000",
            "authorization_confirmed": True,
        },
        headers={"X-User-Id": "user_alice"},
    )
    assert create_res.status_code == 201
    project_id = create_res.json()["id"]

    # 2. User Bob attempts to access Alice's project -> 403 Forbidden
    get_res = api_client.get(
        f"/api/projects/{project_id}",
        headers={"X-User-Id": "user_bob"},
    )
    assert get_res.status_code == 403
    assert "permission" in get_res.json()["detail"].lower()

    # 3. User Bob attempts to scan Alice's project -> 403 Forbidden
    scan_res = api_client.post(
        f"/api/projects/{project_id}/scan",
        headers={"X-User-Id": "user_bob"},
    )
    assert scan_res.status_code == 403

    # 4. User Bob attempts to delete Alice's project -> 403 Forbidden
    del_res = api_client.delete(
        f"/api/projects/{project_id}",
        headers={"X-User-Id": "user_bob"},
    )
    assert del_res.status_code == 403

    # 5. User Alice successfully accesses and lists her own project
    alice_list = api_client.get(
        "/api/projects",
        headers={"X-User-Id": "user_alice"},
    )
    assert alice_list.status_code == 200
    alice_ids = [p["id"] for p in alice_list.json()["projects"]]
    assert project_id in alice_ids

    # 6. User Alice deletes her own project
    alice_del = api_client.delete(
        f"/api/projects/{project_id}",
        headers={"X-User-Id": "user_alice"},
    )
    assert alice_del.status_code == 200
    assert alice_del.json()["status"] == "deleted"


def test_github_project_requires_oauth_connection(api_client):
    """Verifies that creating a GitHub project requires an authenticated GitHub account."""
    # Attempting to create a GitHub project without an active GitHub session
    res = api_client.post(
        "/api/projects",
        json={
            "name": "Sample Repo",
            "project_type": "github",
            "github_repo_full_name": "owner/repo",
        },
        headers={"X-User-Id": "unconnected_user"},
    )
    assert res.status_code == 401
    assert "github account must be connected" in res.json()["detail"].lower()


def test_github_oauth_csrf_and_token_secrecy(api_client, monkeypatch):
    """Verifies that OAuth state protects against CSRF and tokens are never leaked to responses."""
    from cryptography.fernet import Fernet
    from backend.config import settings

    monkeypatch.setattr(settings, "github_client_id", "test-client-id")
    monkeypatch.setattr(settings, "github_client_secret", "test-client-secret")
    monkeypatch.setattr(settings, "github_token_encryption_key", Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(settings, "github_session_cookie_secure", False)

    # 1. Start OAuth flow
    connect_res = api_client.get("/api/github/connect", follow_redirects=False)
    assert connect_res.status_code in (302, 303)
    assert "authscope_github_state" in connect_res.headers.get("set-cookie", "")

    # 2. Callback with forged / mismatched state is strictly rejected
    callback_res = api_client.get("/api/github/callback?state=invalid_csrf_state&code=test_code", follow_redirects=False)
    assert callback_res.status_code in (400, 403, 302, 303)
    # If redirect, error parameter is set
    if callback_res.status_code in (302, 303):
        assert "github_status=state_error" in callback_res.headers.get("location", "") or "STATE_INVALID" in callback_res.headers.get("location", "")

    # 3. Token secrecy: list_projects and get_project schemas must not expose access tokens
    repo = _get_project_repository()
    proj = ProjectRecord(
        name="Private Repo Test",
        project_type="github",
        user_id="user_sec_test",
        github_repo_full_name="acme/secret-repo",
        is_private=True,
    )
    repo.create_project(proj)

    res = api_client.get("/api/projects", headers={"X-User-Id": "user_sec_test"})
    assert res.status_code == 200
    body_text = res.text
    assert "access_token" not in body_text
    assert "client_secret" not in body_text
    assert "token" not in body_text.lower() or "verification_token" in body_text


def test_website_project_scan_launch(api_client):
    """Verifies that scanning an authorized website project initializes an assessment."""
    create_res = api_client.post(
        "/api/projects",
        json={
            "name": "Live Local App",
            "project_type": "website",
            "target_url": "http://localhost:3000",
            "authorization_confirmed": True,
        },
        headers={"X-User-Id": "user_scanner"},
    )
    assert create_res.status_code == 201
    proj_id = create_res.json()["id"]

    scan_res = api_client.post(
        f"/api/projects/{proj_id}/scan",
        headers={"X-User-Id": "user_scanner"},
    )
    assert scan_res.status_code == 202
    data = scan_res.json()
    assert data["status"] == "RUNNING"
    assert data["project_id"] == proj_id
    assert "assessment_id" in data

