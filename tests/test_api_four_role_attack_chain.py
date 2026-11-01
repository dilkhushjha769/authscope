"""API and Integration Tests for Four-Role Authorization Testing & Attack-Chain Execution."""

import pytest
from fastapi.testclient import TestClient
from backend.api.app import app, _get_active_session_manager, _get_repository
from backend.core.session_manager import Role
from backend.storage.models import ScanSessionRecord, DiscoveredEndpointRecord


@pytest.fixture
def api_client():
    return TestClient(app)


def test_get_roles_status_endpoint(api_client):
    """Verifies GET /api/roles returns all 4 roles with masked security previews."""
    res = api_client.get("/api/roles")
    assert res.status_code == 200
    data = res.json()
    assert "roles" in data
    assert "anonymous" in data["roles"]
    assert "user_a" in data["roles"]
    assert "user_b" in data["roles"]
    assert "admin" in data["roles"]
    assert data["anonymous_baseline_ready"] is True
    assert data["roles"]["anonymous"]["configured"] is True


def test_configure_role_endpoint(api_client):
    """Verifies POST /api/roles/configure updates credentials and resource ownership safely."""
    res = api_client.post(
        "/api/roles/configure",
        json={
            "role": "user_a",
            "token": "eyJhbGciOiJIUzI1NiJ9.user_a_secret_token_12345",
            "user_id": "101",
            "owned_resources": {"order": "101", "basket": "1"},
        },
    )
    assert res.status_code == 200
    data = res.json()
    role_a = data["roles"]["user_a"]
    assert role_a["authenticated"] is True
    assert role_a["user_id"] == "101"
    assert role_a["token_preview"] is not None
    # Token preview must be masked, not raw token
    assert "user_a_secret_token_12345" not in role_a["token_preview"]
    assert role_a["owned_resources_count"] == 2


def test_endpoint_graph_and_attack_chain_planning(api_client):
    """Verifies endpoint graph construction and multi-step candidate chain generation."""
    repo = _get_repository()
    scan_id = "scan_test_graph_api"
    session = ScanSessionRecord(
        id=scan_id,
        target_url="http://localhost:3000",
        status="COMPLETED",
    )
    repo.save_scan_session(session)

    # Save mock discovered endpoints
    ep1 = DiscoveredEndpointRecord(
        id="ep1",
        scan_id=scan_id,
        path="/api/orders",
        method="GET",
        category="RESOURCE_LIST",
        parameters=[],
        requires_auth=True,
    )
    ep2 = DiscoveredEndpointRecord(
        id="ep2",
        scan_id=scan_id,
        path="/api/orders/{id}",
        method="GET",
        category="RESOURCE_ITEM",
        parameters=["id"],
        requires_auth=True,
    )
    repo.save_discovered_endpoint(ep1)
    repo.save_discovered_endpoint(ep2)

    # 1. Test Endpoint Graph API
    graph_res = api_client.get(f"/api/assessments/{scan_id}/endpoint-graph")
    assert graph_res.status_code == 200
    graph_data = graph_res.json()
    assert graph_data["nodes_count"] >= 2
    assert "relationships" in graph_data

    # 2. Test Plan Attack Chains API
    plan_res = api_client.post(
        f"/api/assessments/{scan_id}/attack-chains/plan",
        json={"max_steps": 3, "max_candidates": 10},
    )
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert plan_data["candidates_count"] >= 1
    assert len(plan_data["candidates"]) >= 1

    # 3. Test Get Attack Chains API
    get_chains_res = api_client.get(f"/api/assessments/{scan_id}/attack-chains")
    assert get_chains_res.status_code == 200
    assert len(get_chains_res.json()["candidates"]) >= 1

    # 4. Test Role Matrix API
    matrix_res = api_client.get(f"/api/assessments/{scan_id}/role-matrix")
    assert matrix_res.status_code == 200
    matrix_data = matrix_res.json()
    assert len(matrix_data["matrix"]) >= 2


def test_execute_attack_chain_api(api_client, monkeypatch):
    """Verifies POST /api/assessments/{assessment_id}/attack-chains/execute runs sequential execution across roles."""
    import httpx
    from backend.scanner.request_executor import RequestExecutor

    repo = _get_repository()
    scan_id = "scan_test_exec_api"
    session = ScanSessionRecord(
        id=scan_id,
        target_url="http://localhost:3000",
        status="COMPLETED",
    )
    repo.save_scan_session(session)

    # Configure User A and User B
    sm = _get_active_session_manager()
    sm.set_token(Role.USER_A, "jwt_user_a_token", user_id="101")
    sm.set_token(Role.USER_B, "jwt_user_b_token", user_id="102")

    def mock_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if "/api/orders/101" in url and "jwt_user_b_token" in auth:
            # Unauthorized access succeeds (BOLA violation)
            return httpx.Response(200, json={"id": 101, "owner": "user_a", "amount": 250})
        if "/api/orders" in url:
            return httpx.Response(200, json={"orders": [{"id": 101}]})
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(mock_handler))
    orig_init = RequestExecutor.__init__

    def patched_init(self, *args, **kwargs):
        kwargs["client"] = mock_client
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(RequestExecutor, "__init__", patched_init)

    candidate = {
        "candidate_id": "chain_api_test_1",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/orders/101", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = api_client.post(
        f"/api/assessments/{scan_id}/attack-chains/execute",
        json={"chain": candidate, "save_finding": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CONFIRMED"
    assert data["is_confirmed"] is True
    assert data["steps_executed"] == 2
    assert len(data["step_results"]) == 2
    assert data["step_results"][1]["role_used"] == "user_b"
    assert data["step_results"][1]["verdict"] == "CONFIRMED_UNAUTHORIZED_ACCESS"
    assert data["finding_id"] is not None

    # Verify finding was stored in SQLite
    saved_finding = repo.get_finding(data["finding_id"])
    assert saved_finding is not None
    assert saved_finding.vulnerability_category == "MULTI_STEP_CHAIN"
    assert saved_finding.evidence is not None
    assert len(saved_finding.evidence.evidence_sha256) == 64
