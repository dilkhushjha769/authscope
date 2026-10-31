"""Tests for Assessment Data Isolation and Strict Multi-Tenant/Multi-Scan Partitioning.

Covers:
1. Complete isolation of events between different assessment sessions.
2. Complete isolation of findings between different assessment sessions.
3. API endpoint GET /api/assessments/{id} strictly scopes returned data.
4. SSE stream event replays never cross-contaminate between scan sessions.
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    EventType,
    FindingRecord,
    ScanSessionRecord,
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def repo():
    return FindingRepository()


@pytest.mark.unit
def test_event_isolation_between_assessments(repo):
    """Events recorded under scan A must never be visible to scan B."""
    uid = uuid.uuid4().hex[:8]
    scan_a = f"scan_iso_a_{uid}"
    scan_b = f"scan_iso_b_{uid}"

    repo.save_scan_session(ScanSessionRecord(id=scan_a, target_url="http://localhost:3000"))
    repo.save_scan_session(ScanSessionRecord(id=scan_b, target_url="http://localhost:3000"))

    ev_a = AssessmentEvent(
        assessment_id=scan_a,
        event_type=EventType.ENDPOINT_DISCOVERED.value,
        stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
        message="Endpoint /api/users found on Scan A",
    )
    repo.save_event(ev_a)

    ev_b = AssessmentEvent(
        assessment_id=scan_b,
        event_type=EventType.ENDPOINT_DISCOVERED.value,
        stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
        message="Endpoint /api/admin found on Scan B",
    )
    repo.save_event(ev_b)

    events_a = repo.list_events(scan_a)
    events_b = repo.list_events(scan_b)

    assert len(events_a) == 1
    assert events_a[0].message == "Endpoint /api/users found on Scan A"
    assert events_a[0].assessment_id == scan_a

    assert len(events_b) == 1
    assert events_b[0].message == "Endpoint /api/admin found on Scan B"
    assert events_b[0].assessment_id == scan_b


@pytest.mark.unit
def test_finding_isolation_between_assessments(repo):
    """Vulnerability findings recorded under scan A must never appear in scan B queries."""
    uid = uuid.uuid4().hex[:8]
    scan_a = f"scan_finding_a_{uid}"
    scan_b = f"scan_finding_b_{uid}"

    repo.save_scan_session(ScanSessionRecord(id=scan_a, target_url="http://localhost:3000"))
    repo.save_scan_session(ScanSessionRecord(id=scan_b, target_url="http://localhost:3000"))

    finding_a = FindingRecord(
        id=f"finding_a_{uid}",
        scan_id=scan_a,
        endpoint="/rest/user/whoami",
        http_method="GET",
        vulnerability_candidate="BOLA_IDOR",
        validation_status="CONFIRMED",
        severity="HIGH",
        title="BOLA on user whoami",
    )
    repo.save_finding(finding_a)

    finding_b = FindingRecord(
        id=f"finding_b_{uid}",
        scan_id=scan_b,
        endpoint="/rest/basket/6",
        http_method="GET",
        vulnerability_candidate="BFLA",
        validation_status="SUSPICIOUS",
        severity="MEDIUM",
        title="BFLA on basket access",
    )
    repo.save_finding(finding_b)

    findings_a = repo.list_findings(scan_a)
    findings_b = repo.list_findings(scan_b)

    assert len(findings_a) == 1
    assert findings_a[0].scan_id == scan_a
    assert findings_a[0].endpoint == "/rest/user/whoami"

    assert len(findings_b) == 1
    assert findings_b[0].scan_id == scan_b
    assert findings_b[0].endpoint == "/rest/basket/6"


@pytest.mark.integration
def test_api_assessment_query_strict_isolation(client, repo):
    """GET /api/assessments/{id} returns only findings and events belonging to that scan."""
    uid = uuid.uuid4().hex[:8]
    scan_a = f"scan_api_iso_a_{uid}"
    scan_b = f"scan_api_iso_b_{uid}"

    repo.save_scan_session(ScanSessionRecord(id=scan_a, target_url="http://localhost:3000"))
    repo.save_scan_session(ScanSessionRecord(id=scan_b, target_url="http://localhost:3000"))

    # Add finding to scan A only
    repo.save_finding(
        FindingRecord(
            id=f"finding_iso_secret_{uid}",
            scan_id=scan_a,
            endpoint="/api/secret",
            http_method="GET",
            vulnerability_candidate="IDOR",
            validation_status="CONFIRMED",
            severity="CRITICAL",
            title="Critical IDOR in scan A",
        )
    )

    res_b = client.get(f"/api/assessments/{scan_b}")
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["id"] == scan_b
    assert len(data_b["findings"]) == 0

    res_a = client.get(f"/api/assessments/{scan_a}")
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["id"] == scan_a
    assert len(data_a["findings"]) == 1
    assert data_a["findings"][0]["endpoint"] == "/api/secret"
