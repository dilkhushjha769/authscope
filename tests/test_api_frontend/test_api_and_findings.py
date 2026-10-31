"""Comprehensive tests for Sprint Group 4: HTTPS Website Input, API Integration, and Real Finding Display.

Covers all 17 required verification areas:
1. Valid HTTP URL submission.
2. Valid HTTPS URL submission (including custom ports and paths).
3. Invalid URL syntax handling.
4. Unauthorized target rejection (host, port, scheme, HTTPS cert failure, unconfigured target profile, no silent HTTPS->HTTP downgrade).
5. Genuine SSE event streaming (all 14 event types).
6. Activity telemetry persistence and formatting.
7. Realistic finding schema rendering across all 6 required sections (A–F).
8. CONFIRMED finding serialization and display contract.
9. SUSPICIOUS finding serialization and display contract (never promoted to CONFIRMED).
10. INCONCLUSIVE finding and check status handling.
11. NOT_CONFIRMED and NOT_TESTED statuses + "No confirmed vulnerabilities found" summary.
12. Source code available case (verified file path, line numbers, function name, snippet).
13. Source code unavailable case (explicit black-box message, zero invented files/lines).
14. Remediation display (root cause, recommended fix, proposed fix label, verification procedure).
15. Sensitive evidence redaction (JWTs, cookies, API keys, passwords scrubbed).
16. Assessment cancellation.
17. Error handling and SSE reconnection with Last-Event-ID.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Generator
import uuid

from fastapi.testclient import TestClient
import pytest

from backend.analysis.severity_engine import SeverityLevel
from backend.api.app import (
    DEFAULT_TARGET_PROFILES,
    TargetProfileConfig,
    UNAVAILABLE_SOURCE_MESSAGE,
    _get_repository,
    _map_event_to_agent_sse,
    _serialize_detailed_finding,
    app,
    task_manager,
)
from backend.agent.gemini_agent import GeminiAgent
from backend.agent.memory import AssessmentMemory
from backend.agent.tools import ToolRegistry
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    DiscoveredEndpointRecord,
    EventType,
    EvidenceArtifact,
    FindingRecord,
    ScanSessionRecord,
)


@pytest.fixture(autouse=True)
def reset_app_state(tmp_path: Path) -> Generator[None, None, None]:
    """Resets custom ScopeGuard, target profiles, and isolated test repository on app.state."""
    db_file = tmp_path / "test_api_frontend.db"
    app.state.repository = FindingRepository(db_manager=DatabaseManager(db_path=str(db_file)))
    app.state.scope_guard = None
    app.state.target_profiles = dict(DEFAULT_TARGET_PROFILES)
    yield
    app.state.repository = None
    app.state.scope_guard = None
    app.state.target_profiles = dict(DEFAULT_TARGET_PROFILES)


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


# ==============================================================================
# 1–4. Target Website Input (HTTP, HTTPS, Syntax, ScopeGuard & Profile Errors)
# ==============================================================================


class TestTargetWebsiteInputAndAuthorization:
    """Tests HTTP and HTTPS URL submission and server-side ScopeGuard enforcement."""

    def test_valid_http_url_submission(self, client: TestClient) -> None:
        """Accepts authorized http://localhost:3000 target."""
        res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        assert res.status_code == 201
        data = res.json()
        assert data["target_url"] == "http://localhost:3000"
        assert data["scheme"] == "http"
        assert data["host"] == "localhost"
        assert data["port"] == 3000
        assert data["status"] == "PENDING"
        assert data["assessment_id"].startswith("scan_")

    def test_valid_https_url_submission_when_authorized(self, client: TestClient) -> None:
        """Accepts authorized HTTPS URLs (https://staging.example.com and custom port 8443)."""
        app.state.scope_guard = ScopeGuard(
            allowed_hosts=["localhost", "staging.example.com", "authorized-domain.example"],
            allowed_ports=[3000, 443, 8443],
            allowed_schemes=["http", "https"],
            allowed_methods=["GET", "HEAD"],
        )

        # Standard HTTPS (port 443)
        res1 = client.post(
            "/api/assessments",
            json={"target_url": "https://staging.example.com"},
        )
        assert res1.status_code == 201
        d1 = res1.json()
        assert d1["target_url"] == "https://staging.example.com"
        assert d1["scheme"] == "https"
        assert d1["host"] == "staging.example.com"
        assert d1["port"] == 443

        # HTTPS with explicit port 8443 and path /app
        res2 = client.post(
            "/api/assessments",
            json={"target_url": "https://authorized-domain.example:8443/app"},
        )
        assert res2.status_code == 201
        d2 = res2.json()
        assert d2["target_url"] == "https://authorized-domain.example:8443/app"
        assert d2["scheme"] == "https"
        assert d2["host"] == "authorized-domain.example"
        assert d2["port"] == 8443

    def test_invalid_url_syntax_rejected(self, client: TestClient) -> None:
        """Rejects empty or malformed URLs missing scheme or hostname."""
        res_empty = client.post("/api/assessments", json={"target_url": "   "})
        assert res_empty.status_code == 400
        assert "empty" in res_empty.json()["detail"].lower()

        res_no_scheme = client.post("/api/assessments", json={"target_url": "localhost:3000/api"})
        assert res_no_scheme.status_code == 400
        detail = res_no_scheme.json()["detail"]
        assert "syntax" in detail.lower() or "scheme" in detail.lower()

    def test_unauthorized_host_rejected_clearly(self, client: TestClient) -> None:
        """Displays a clear error when the host is not authorized."""
        res = client.post(
            "/api/assessments",
            json={"target_url": "http://unauthorized-corp.example:3000"},
        )
        assert res.status_code == 400
        detail = res.json()["detail"]
        assert "Scope violation" in detail
        assert "Host 'unauthorized-corp.example' is not authorized" in detail

    def test_unauthorized_port_rejected_clearly(self, client: TestClient) -> None:
        """Displays a clear error when the port is not authorized."""
        res = client.post(
            "/api/assessments",
            json={"target_url": "http://localhost:9090"},
        )
        assert res.status_code == 400
        detail = res.json()["detail"]
        assert "Scope violation" in detail
        assert "Port '9090' is not authorized" in detail

    def test_disallowed_scheme_rejected_and_https_not_downgraded(self, client: TestClient) -> None:
        """Rejects disallowed scheme and never silently redirects HTTPS to HTTP."""
        app.state.scope_guard = ScopeGuard(
            allowed_hosts=["localhost"],
            allowed_ports=[3000],
            allowed_schemes=["http"],
            allowed_methods=["GET"],
        )
        # When HTTPS is disallowed, target must fail scheme check
        res_https = client.post(
            "/api/assessments",
            json={"target_url": "https://localhost:3000"},
        )
        assert res_https.status_code == 400
        detail = res_https.json()["detail"]
        assert "Scope violation" in detail
        assert "Scheme 'https' is not allowed" in detail
        assert "never silently downgraded" in detail

        # FTP scheme rejected
        res_ftp = client.post(
            "/api/assessments",
            json={"target_url": "ftp://localhost:3000"},
        )
        assert res_ftp.status_code == 400
        assert "Scheme 'ftp' is not allowed" in res_ftp.json()["detail"]

    def test_https_certificate_validation_failure_reported_clearly(self, client: TestClient) -> None:
        """Displays a clear error when HTTPS certificate validation fails."""
        app.state.scope_guard = ScopeGuard(
            allowed_hosts=["bad-cert.example.com"],
            allowed_ports=[443],
            allowed_schemes=["https"],
            allowed_methods=["GET"],
        )
        app.state.target_profiles["bad_tls_profile"] = TargetProfileConfig(
            name="bad_tls_profile",
            base_url="https://bad-cert.example.com",
            allowed_schemes=["https"],
            verify_tls=True,
            tls_cert_valid=False,
            configured=True,
        )

        res = client.post(
            "/api/assessments",
            json={
                "target_url": "https://bad-cert.example.com",
                "target_profile": "bad_tls_profile",
            },
        )
        assert res.status_code == 400
        detail = res.json()["detail"]
        assert "HTTPS certificate validation failed" in detail
        assert "will not downgrade HTTPS to HTTP" in detail

    def test_unconfigured_target_profile_rejected_clearly(self, client: TestClient) -> None:
        """Displays a clear error when a requested target profile is not configured."""
        res = client.post(
            "/api/assessments",
            json={
                "target_url": "http://localhost:3000",
                "target_profile": "missing_production_profile",
            },
        )
        assert res.status_code == 400
        detail = res.json()["detail"]
        assert "Target profile 'missing_production_profile' is not configured" in detail


# ==============================================================================
# 5–6. SSE Agent Activity Streaming (All 14 Required Event Types)
# ==============================================================================


class TestSSEAgentActivityStreaming:
    """Verifies genuine SSE streaming of all 14 required agent activity event types."""

    def test_all_14_sse_event_types_mapped_and_streamed(self, client: TestClient, tmp_path: Path) -> None:
        """Verifies all 14 required SSE events can be mapped and streamed over /stream."""
        repo = _get_repository()
        scan_id = f"scan_sse_all_{uuid.uuid4().hex[:6]}"

        # Create a real temporary file for source location verification
        src_file = tmp_path / "routes" / "basket.js"
        src_file.parent.mkdir(parents=True, exist_ok=True)
        src_file.write_text(
            "const express = require('express');\n"
            "function getBasket(req, res) {\n"
            "  Basket.findByPk(req.params.id).then(b => res.json(b));\n"
            "}\n",
            encoding="utf-8",
        )

        fnd = FindingRecord(
            id=f"fnd_sse_{uuid.uuid4().hex[:6]}",
            scan_id=scan_id,
            title="Confirmed BOLA on /rest/basket/1",
            endpoint="/rest/basket/1",
            target_endpoint="/rest/basket/1",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            severity=SeverityLevel.HIGH,
            status="confirmed",
            validation_status="CONFIRMED",
            access_verdict="CONFIRMED_UNAUTHORIZED_ACCESS",
            technical_details={
                "source_location": {
                    "verified": True,
                    "repository_name": "juice-shop",
                    "file_path": "routes/basket.js",
                    "function_name": "getBasket",
                    "start_line": 2,
                    "end_line": 4,
                    "code_snippet": "Basket.findByPk(req.params.id).then(b => res.json(b));",
                }
            },
        )
        repo.save_finding(fnd)

        session = ScanSessionRecord(
            id=scan_id,
            target_url="http://localhost:3000",
            status="COMPLETED",
            endpoints_discovered_count=3,
            endpoints_tested_count=2,
            confirmed_findings_count=1,
            suspicious_results_count=1,
            summary_text="Assessment completed.",
        )
        repo.save_scan_session(session)

        events_to_save = [
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.SCOPE_VALIDATION_STARTED.value,
                stage=AssessmentStage.SCOPE_VALIDATION.value,
                message="Validating scope",
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
                stage=AssessmentStage.SCOPE_VALIDATION.value,
                message="Scope validated",
                metadata={"host": "localhost", "port": 3000, "scheme": "http"},
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.CONNECTION_COMPLETED.value,
                stage=AssessmentStage.TARGET_CONNECTION.value,
                message="Connected to target",
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ENDPOINT_DISCOVERED.value,
                stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
                message="Discovered /rest/basket/{id}",
                metadata={"path": "/rest/basket/{id}", "method": "GET", "category": "USER_RESOURCE"},
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value,
                stage=AssessmentStage.AUTHORIZATION_TESTING.value,
                message="Suspicious behavior on /rest/admin/application-configuration",
                metadata={
                    "endpoint": "/rest/admin/application-configuration",
                    "category": "BFLA",
                    "severity": "MEDIUM",
                },
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.FINDING_CONFIRMED.value,
                stage=AssessmentStage.EVIDENCE_VALIDATION.value,
                message="Confirmed BOLA on /rest/basket/1",
                metadata={
                    "finding_id": fnd.id,
                    "endpoint": "/rest/basket/1",
                    "category": "BOLA_IDOR",
                    "severity": "HIGH",
                },
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.EVIDENCE_VALIDATION_COMPLETED.value,
                stage=AssessmentStage.EVIDENCE_VALIDATION.value,
                message="Evidence validated",
                metadata={"confirmed_count": 1, "suspicious_count": 1},
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ASSESSMENT_COMPLETED.value,
                stage=AssessmentStage.REPORT_PREPARATION.value,
                message="Assessment complete",
                metadata={"confirmed_findings": 1, "suspicious_results": 1},
            ),
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ASSESSMENT_FAILED.value,
                stage=AssessmentStage.TARGET_CONNECTION.value,
                message="Simulated connection failure for tool_failed mapping check",
            ),
        ]
        for ev in events_to_save:
            repo.save_event(ev)

        with client.stream("GET", f"/api/assessments/{scan_id}/stream") as response:
            assert response.status_code == 200
            raw_stream = "".join(response.iter_text())

        required_14_events = [
            "assessment_started",
            "agent_thinking",
            "agent_plan",
            "tool_started",
            "tool_completed",
            "tool_failed",
            "endpoint_discovered",
            "finding_hypothesis",
            "finding_discovered",
            "evidence_validated",
            "source_location_found",
            "explanation_generated",
            "assessment_completed",
            "assessment_failed",
        ]
        for req_event in required_14_events:
            assert f"event: {req_event}\n" in raw_stream, f"Missing required SSE event: {req_event}"


# ==============================================================================
# 7–15. Detailed Finding Display, Statuses, Source Mapping, Remediation & Redaction
# ==============================================================================


class TestFindingSerializationAndStatuses:
    """Verifies Sections 7, 8, 10, and 11 for complete finding reports and status separation."""

    def test_confirmed_finding_contains_all_six_required_sections(self, client: TestClient) -> None:
        """Verifies a CONFIRMED finding includes Bug Identity, Website Location, Source Location, Impact, Resolution, and Evidence."""
        repo = _get_repository()
        scan_id = f"scan_conf_{uuid.uuid4().hex[:6]}"
        session = ScanSessionRecord(
            id=scan_id,
            target_url="https://staging.example.com:8443",
            status="COMPLETED",
            endpoints_discovered_count=5,
            endpoints_tested_count=4,
            confirmed_findings_count=1,
            suspicious_results_count=0,
            summary_text="1 confirmed vulnerability found.",
        )
        repo.save_scan_session(session)

        evi = EvidenceArtifact(
            id=f"evi_{uuid.uuid4().hex[:6]}",
            finding_id=f"fnd_conf_{uuid.uuid4().hex[:6]}",
            endpoint="/rest/basket/1",
            http_method="GET",
            testing_role="user_b",
            authorized_role="user_a",
            resource_id="1",
            expected_behavior="User B should receive HTTP 403 Forbidden when requesting User A's basket.",
            actual_behavior="User B received HTTP 200 OK containing User A's basket items.",
            validation_status="CONFIRMED",
            request_method="GET",
            request_url="https://staging.example.com:8443/rest/basket/1",
            request_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
            response_status=200,
            sanitized_response_body='{"status":"success","data":{"id":1,"UserId":1}}',
        )
        finding = FindingRecord(
            id=evi.finding_id,
            scan_id=scan_id,
            title="Broken Object Level Authorization (IDOR) on /rest/basket/{id}",
            endpoint="/rest/basket/{id}",
            target_endpoint="/rest/basket/{id}",
            http_method="GET",
            vulnerability_category="BOLA_IDOR",
            affected_role="user_b",
            affected_roles=["user_a", "user_b"],
            resource_id="1",
            expected_behavior=evi.expected_behavior,
            actual_behavior=evi.actual_behavior,
            severity=SeverityLevel.HIGH,
            status="confirmed",
            confirmation_status="confirmed",
            validation_status="CONFIRMED",
            access_verdict="CONFIRMED_UNAUTHORIZED_ACCESS",
            impact_explanation="Horizontal privilege escalation exposing private shopping baskets across tenants.",
            remediation_guidance="const basket = await Basket.findOne({ where: { id: req.params.id, UserId: req.user.id } });",
            evidence=evi,
        )
        repo.save_finding(finding)

        res = client.get(f"/api/assessments/{scan_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["scheme"] == "https"
        assert data["host"] == "staging.example.com"
        assert data["port"] == 8443
        assert data["confirmed_findings_count"] == 1
        assert data["no_confirmed_vulnerabilities"] is False

        f_out = data["findings"][0]
        # A. Bug identity
        assert f_out["vulnerability_name"] == "Broken Object Level Authorization (IDOR) on /rest/basket/{id}"
        assert f_out["vulnerability_category"] == "BOLA_IDOR"
        assert f_out["category_display"] == "BOLA / IDOR"
        assert f_out["severity"] == "HIGH"
        assert f_out["validation_status"] == "CONFIRMED"

        # B. Website location
        assert f_out["full_url"] == "https://staging.example.com:8443/rest/basket/1"
        assert f_out["hostname"] == "staging.example.com"
        assert f_out["port"] == 8443
        assert f_out["scheme"] == "https"
        assert f_out["endpoint"] == "/rest/basket/{id}"
        assert f_out["http_method"] == "GET"
        assert f_out["parameter_or_resource_id"] == "resource_id=1"

        # C. Source-code location (unavailable in black-box test -> explicit message, zero invented files)
        assert f_out["source_code_available"] is False
        assert f_out["source_file"] is None
        assert f_out["source_line"] is None
        assert f_out["source_unavailable_message"] == UNAVAILABLE_SOURCE_MESSAGE

        # D. What the bug can affect
        assert "exposed_data_or_functionality" in f_out and len(f_out["exposed_data_or_functionality"]) > 10
        assert "user_b" in f_out["affected_roles"]
        assert "attacker_capabilities" in f_out and len(f_out["attacker_capabilities"]) > 10
        assert "why_it_matters" in f_out and len(f_out["why_it_matters"]) > 10

        # E. How to resolve it (clearly labeled as proposed fix)
        assert len(f_out["root_cause"]) > 10
        assert len(f_out["recommended_fix"]) > 10
        assert "Basket.findOne" in f_out["proposed_code_fix"]
        assert "Proposed Fix" in f_out["proposed_fix_label"]
        assert "Not automatically applied" in f_out["proposed_fix_label"]
        assert len(f_out["verification_procedure"]) > 10

        # F. Sanitized Evidence Summary
        assert f_out["baseline_behavior"] == evi.expected_behavior
        assert f_out["unauthorized_behavior"] == evi.actual_behavior
        assert "Expected HTTP 401/403" in f_out["response_difference"]
        assert f_out["evidence_validation_status"] == "CONFIRMED"
        assert len(f_out["evidence"]["evidence_sha256"]) == 64

    def test_suspicious_finding_is_never_displayed_as_confirmed(self, client: TestClient) -> None:
        """Ensures a SUSPICIOUS finding retains SUSPICIOUS status even if raw fields are ambiguous."""
        finding = FindingRecord(
            id=f"fnd_susp_{uuid.uuid4().hex[:6]}",
            scan_id="scan_susp_test",
            title="Suspicious Unauthenticated Access to Admin Route /rest/admin/application-configuration",
            endpoint="/rest/admin/application-configuration",
            target_endpoint="/rest/admin/application-configuration",
            http_method="GET",
            vulnerability_category="BFLA",
            severity=SeverityLevel.MEDIUM,
            status="suspected",
            validation_status="SUSPICIOUS",
            access_verdict="SUSPICIOUS_ACCESS",
        )
        serialized = _serialize_detailed_finding(finding, "http://localhost:3000")
        assert serialized["validation_status"] == "SUSPICIOUS"
        assert serialized["evidence_validation_status"] == "SUSPICIOUS"
        assert serialized["category_display"] == "Broken Function Level Authorization"
        assert serialized["validation_status"] != "CONFIRMED"

    def test_all_five_finding_statuses_supported(self) -> None:
        """Verifies CONFIRMED, SUSPICIOUS, NOT_CONFIRMED, INCONCLUSIVE, and NOT_TESTED statuses serialize accurately."""
        status_cases = [
            ("CONFIRMED", "confirmed", "CONFIRMED_UNAUTHORIZED_ACCESS", "CONFIRMED"),
            ("SUSPICIOUS", "suspected", "SUSPICIOUS_ACCESS", "SUSPICIOUS"),
            ("NOT_CONFIRMED", "false_positive", "CORRECTLY_DENIED", "NOT_CONFIRMED"),
            ("INCONCLUSIVE", "suspected", "INCONCLUSIVE", "INCONCLUSIVE"),
            ("NOT_TESTED", "untested", "UNTESTED", "NOT_TESTED"),
        ]
        for raw_val, conf_st, verdict, expected in status_cases:
            # For INCONCLUSIVE test case, pass confirmation_status="inconclusive" so suspected doesn't override
            c_status = "inconclusive" if expected == "INCONCLUSIVE" else conf_st
            f = FindingRecord(
                id=f"fnd_{expected.lower()}",
                scan_id="scan_status_matrix",
                title=f"Test {expected}",
                endpoint="/api/test",
                http_method="GET",
                validation_status=raw_val,
                confirmation_status=c_status,
                status=c_status,
                access_verdict=verdict,
            )
            out = _serialize_detailed_finding(f, "http://localhost:3000")
            assert out["validation_status"] == expected

    def test_source_code_available_vs_unavailable(self) -> None:
        """Verifies exact source location fields when available and explicit fallback message when unavailable."""
        # Case 1: Source code available (verified)
        f_with_src = FindingRecord(
            id="fnd_src_avail",
            scan_id="scan_src",
            title="BOLA in basket handler",
            endpoint="/rest/basket/{id}",
            http_method="GET",
            validation_status="CONFIRMED",
            technical_details={
                "source_location": {
                    "verified": True,
                    "repository_name": "juice-shop/juice-shop",
                    "file_path": "routes/basket.ts",
                    "function_name": "retrieveBasket",
                    "start_line": 18,
                    "end_line": 24,
                    "code_snippet": "BasketModel.findOne({ where: { id: req.params.id } })",
                }
            },
        )
        out_avail = _serialize_detailed_finding(f_with_src, "http://localhost:3000")
        assert out_avail["source_code_available"] is True
        assert out_avail["source_repository"] == "juice-shop/juice-shop"
        assert out_avail["source_file"] == "routes/basket.ts"
        assert out_avail["source_line"] == "18-24"
        assert out_avail["source_function"] == "retrieveBasket"
        assert "BasketModel.findOne" in out_avail["vulnerable_snippet"]
        assert out_avail["source_unavailable_message"] is None

        # Case 2: Source code unavailable
        f_no_src = FindingRecord(
            id="fnd_src_unavail",
            scan_id="scan_src",
            title="Black-box BOLA finding",
            endpoint="/rest/basket/{id}",
            http_method="GET",
            validation_status="CONFIRMED",
        )
        out_unavail = _serialize_detailed_finding(f_no_src, "http://localhost:3000")
        assert out_unavail["source_code_available"] is False
        assert out_unavail["source_repository"] is None
        assert out_unavail["source_file"] is None
        assert out_unavail["source_line"] is None
        assert out_unavail["source_function"] is None
        assert out_unavail["vulnerable_snippet"] is None
        assert out_unavail["source_unavailable_message"] == (
            "Server-side source code was not available. This finding was detected through black-box HTTP testing."
        )

    def test_sensitive_evidence_redaction_strips_jwts_cookies_and_keys(self) -> None:
        """Verifies JWTs, cookies, API keys, and passwords are never exposed in serialized findings."""
        raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw_cookie = "session_id=super_secret_cookie_val_999"
        raw_api_key = "sk-live-9876543210abcdef"

        evi = EvidenceArtifact(
            id="evi_redact_01",
            finding_id="fnd_redact_01",
            endpoint="/api/Users",
            http_method="GET",
            request_headers={
                "Authorization": f"Bearer {raw_jwt}",
                "Cookie": raw_cookie,
                "X-API-Key": raw_api_key,
            },
            relevant_response_headers={
                "Set-Cookie": raw_cookie,
            },
            sanitized_response_body=f'{{"token": "{raw_jwt}", "password": "PlaintextPassword123!"}}',
        )
        fnd = FindingRecord(
            id="fnd_redact_01",
            scan_id="scan_redact",
            title="Sensitive Data Exposure",
            endpoint="/api/Users",
            http_method="GET",
            evidence=evi,
        )
        serialized = _serialize_detailed_finding(fnd, "http://localhost:3000")
        serialized_dump = json.dumps(serialized)

        assert raw_jwt not in serialized_dump
        assert raw_cookie not in serialized_dump
        assert raw_api_key not in serialized_dump
        assert "PlaintextPassword123!" not in serialized_dump

    def test_final_summary_and_no_confirmed_vulnerabilities_banner(self, client: TestClient) -> None:
        """Verifies Final Assessment Summary metrics and 'No confirmed vulnerabilities found' message."""
        repo = _get_repository()
        scan_id = f"scan_summary_{uuid.uuid4().hex[:6]}"
        session = ScanSessionRecord(
            id=scan_id,
            target_url="http://localhost:3000",
            status="COMPLETED",
            endpoints_discovered_count=4,
            endpoints_tested_count=3,
            confirmed_findings_count=0,
            suspicious_results_count=1,
            summary_text="Assessment completed.",
        )
        repo.save_scan_session(session)

        # Save discovered endpoints with NOT_CONFIRMED, INCONCLUSIVE, and NOT_TESTED states
        repo.save_discovered_endpoint(
            DiscoveredEndpointRecord(
                id=f"ep_{scan_id}_1",
                scan_id=scan_id,
                path="/rest/user/whoami",
                method="GET",
                category="USER_RESOURCE",
                test_status="TESTED",
                verdict="CORRECTLY_DENIED",
            )
        )
        repo.save_discovered_endpoint(
            DiscoveredEndpointRecord(
                id=f"ep_{scan_id}_2",
                scan_id=scan_id,
                path="/api/Quantitys",
                method="GET",
                category="BUSINESS_WORKFLOW",
                test_status="TESTED",
                verdict="INCONCLUSIVE",
            )
        )
        repo.save_discovered_endpoint(
            DiscoveredEndpointRecord(
                id=f"ep_{scan_id}_3",
                scan_id=scan_id,
                path="/rest/basket/{id}",
                method="GET",
                category="OBJECT_ID_RESOURCE",
                test_status="SKIPPED_MISSING_SESSION",
                verdict=None,
            )
        )

        res = client.get(f"/api/assessments/{scan_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["target_url"] == "http://localhost:3000"
        assert data["scheme"] == "http"
        assert data["port"] == 3000
        assert data["status"] == "COMPLETED"
        assert data["endpoints_discovered_count"] == 4
        assert data["endpoints_tested_count"] == 3
        assert data["confirmed_findings_count"] == 0
        assert data["suspicious_results_count"] == 1
        assert data["not_confirmed_count"] == 1
        assert data["inconclusive_count"] == 1
        assert data["not_tested_count"] == 1
        assert data["no_confirmed_vulnerabilities"] is True
        assert data["no_confirmed_message"] == "No confirmed vulnerabilities found"
        assert "ai_provider" in data
        assert data["ai_provider"]["provider"] == "Google Gemini"


# ==============================================================================
# 16–17. Cancellation, Error Handling, and SSE Reconnection
# ==============================================================================


class TestCancellationAndSSEReconnection:
    """Tests safe assessment cancellation and SSE cursor-based reconnection."""

    def test_cancel_running_assessment(self, client: TestClient) -> None:
        """Cancels an assessment cleanly via POST /api/assessments/{id}/stop."""
        create_res = client.post("/api/assessments", json={"target_url": "http://localhost:3000"})
        assert create_res.status_code == 201
        scan_id = create_res.json()["assessment_id"]

        stop_res = client.post(f"/api/assessments/{scan_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] in ("CANCELLING", "CANCELLED", "COMPLETED", "FAILED")

    def test_sse_reconnection_resumes_from_last_event_id(self, client: TestClient) -> None:
        """Reconnecting with Last-Event-ID skips already seen events and streams only newer events."""
        repo = _get_repository()
        scan_id = f"scan_recon_{uuid.uuid4().hex[:6]}"
        repo.save_scan_session(
            ScanSessionRecord(
                id=scan_id,
                target_url="http://localhost:3000",
                status="COMPLETED",
                summary_text="Completed scan.",
            )
        )
        id1 = repo.save_event(
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
                stage=AssessmentStage.SCOPE_VALIDATION.value,
                message="First event",
            )
        )
        id2 = repo.save_event(
            AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ENDPOINT_DISCOVERY_COMPLETED.value,
                stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
                message="Second event after cursor",
                metadata={"endpoints_discovered": 7},
            )
        )

        with client.stream(
            "GET",
            f"/api/assessments/{scan_id}/stream",
            headers={"Last-Event-ID": str(id1)},
        ) as response:
            assert response.status_code == 200
            text = "".join(response.iter_text())
            assert f"id: {id1}\n" not in text
            assert f"id: {id2}\n" in text
            assert "Second event after cursor" in text
            assert "event: done" in text
