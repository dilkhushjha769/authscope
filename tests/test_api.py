"""Unit and integration tests for AuthScope FastAPI Endpoints.

Covers:
1. Health check endpoint (`GET /api/health`).
2. Scope rejection on unauthorized target (`POST /api/assessments`).
3. Assessment creation on authorized target (`POST /api/assessments`).
4. Real-time Server-Sent Events stream (`GET /api/assessments/{id}/stream`).
5. Assessment retrieval (`GET /api/assessments/{id}`).
6. Safe assessment cancellation (`POST /api/assessments/{id}/stop`).
"""

import json
from fastapi.testclient import TestClient
import pytest

from backend.api.app import app


@pytest.fixture
def test_client():
    with TestClient(app) as client:
        yield client


@pytest.mark.unit
def test_api_health_check(test_client):
    response = test_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "AuthScope API"


@pytest.mark.unit
def test_api_create_assessment_rejects_unauthorized_scope(test_client):
    response = test_client.post(
        "/api/assessments",
        json={"target_url": "https://example.com"},
    )
    assert response.status_code == 400
    data = response.json()
    assert "Scope violation" in data["detail"] or "not allowlisted" in data["detail"]


@pytest.mark.unit
def test_api_create_assessment_rejects_empty_target(test_client):
    response = test_client.post(
        "/api/assessments",
        json={"target_url": "   "},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


@pytest.mark.unit
def test_api_create_and_get_assessment(test_client):
    # 1. Create assessment
    create_res = test_client.post(
        "/api/assessments",
        json={"target_url": "http://localhost:3000"},
    )
    assert create_res.status_code == 201
    created = create_res.json()
    scan_id = created["assessment_id"]
    assert scan_id.startswith("scan_")
    assert created["target_url"] == "http://localhost:3000"
    assert created["status"] == "PENDING"

    # 2. Query assessment state
    get_res = test_client.get(f"/api/assessments/{scan_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["id"] == scan_id
    assert retrieved["target_url"] == "http://localhost:3000"
    assert "stages" in retrieved
    assert len(retrieved["stages"]) == 7


@pytest.mark.unit
def test_api_stop_assessment(test_client):
    create_res = test_client.post(
        "/api/assessments",
        json={"target_url": "http://localhost:3000"},
    )
    scan_id = create_res.json()["assessment_id"]

    stop_res = test_client.post(f"/api/assessments/{scan_id}/stop")
    assert stop_res.status_code == 200
    assert "cancellation" in stop_res.json()["message"].lower() or "not actively running" in stop_res.json()["message"].lower()


@pytest.mark.unit
def test_api_stream_replay_completed_assessment(test_client):
    create_res = test_client.post(
        "/api/assessments",
        json={"target_url": "http://localhost:3000"},
    )
    scan_id = create_res.json()["assessment_id"]

    with test_client.stream("GET", f"/api/assessments/{scan_id}/stream") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        lines = []
        for line in response.iter_lines():
            if line:
                lines.append(line)
            if len(lines) >= 8:
                break
        assert any("event: activity" in l or "event: message" in l or "event: done" in l for l in lines)

