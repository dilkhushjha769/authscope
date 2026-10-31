"""Automated tests for Phase 3.5 — Live AI Security Agent Interface & Assessment Engine.

Covers:
1. URL validation (`validate_target_url`).
2. Unauthorized target rejection before network execution.
3. Assessment creation & 7-stage initialization.
4. Real event generation & schema compliance (`AssessmentEvent`).
5. Event streaming (`stream_assessment`) & assessment status updates.
6. Missing authentication sessions handling (never inventing sessions).
7. Finding display and validation status (`CONFIRMED_UNAUTHORIZED_ACCESS` vs `SUSPICIOUS_ACCESS`).
8. Credential redaction in event messages, metadata, and persisted artifacts.
9. Assessment history persistence & retrieval in SQLite (`FindingRepository`).
10. Safe cancellation (`CancellationToken`).
11. Deterministic `AssessmentQueryAdapter` question answering & report export.
12. Live OWASP Juice Shop (`http://localhost:3000`) end-to-end assessment streaming.
"""

import json
import httpx
import pytest

from backend.analysis.evidence_validator import EvidenceValidationStatus
from backend.core.assessment_engine import (
    AssessmentEngine,
    AssessmentQueryAdapter,
    CancellationToken,
    sanitize_event_metadata,
    sanitize_event_text,
)
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentStage,
    EventType,
    StageStatus,
)


def _create_memory_repo() -> FindingRepository:
    """Creates an isolated in-memory SQLite FindingRepository for testing."""
    db = DatabaseManager(db_path=":memory:")
    return FindingRepository(db_manager=db)


def _build_mock_executor(
    session_manager: SessionManager,
    handler,
) -> RequestExecutor:
    """Builds a RequestExecutor backed by an httpx.MockTransport."""
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=False)
    return RequestExecutor(
        scope_guard=ScopeGuard(),
        session_manager=session_manager,
        client=client,
    )


@pytest.mark.unit
class TestUrlValidationAndUnauthorizedRejection:
    """Tests pre-scan URL validation and hard rejection of unauthorized targets."""

    def test_validate_target_url_allows_authorized_localhost(self) -> None:
        engine = AssessmentEngine(repository=_create_memory_repo())
        res = engine.validate_target_url("http://localhost:3000")
        assert res.is_allowed is True
        assert res.normalized_host == "localhost"
        assert res.normalized_port == 3000

    def test_validate_target_url_rejects_external_domain(self) -> None:
        engine = AssessmentEngine(repository=_create_memory_repo())
        res = engine.validate_target_url("https://example.com")
        assert res.is_allowed is False
        assert "allowlist" in res.reason.lower() or "not allowlisted" in res.reason.lower() or "scheme" in res.reason.lower()

    def test_unauthorized_target_rejected_in_stream_without_network_calls(self) -> None:
        repo = _create_memory_repo()
        mgr = SessionManager(load_from_env=False)
        network_called = False

        def forbidden_transport(request: httpx.Request) -> httpx.Response:
            nonlocal network_called
            network_called = True
            return httpx.Response(200, text="should never happen")

        executor = _build_mock_executor(mgr, forbidden_transport)
        engine = AssessmentEngine(repository=repo, session_manager=mgr, executor=executor)

        session, events = engine.run_assessment_sync("https://example.com")

        assert network_called is False
        assert session.status == "FAILED"
        assert session.stages[AssessmentStage.SCOPE_VALIDATION.value].status == StageStatus.FAILED
        # All subsequent stages must be SKIPPED
        assert session.stages[AssessmentStage.TARGET_CONNECTION.value].status == StageStatus.SKIPPED
        assert session.stages[AssessmentStage.AUTHORIZATION_TESTING.value].status == StageStatus.SKIPPED

        event_types = [e.event_type for e in events]
        assert EventType.ASSESSMENT_STARTED.value in event_types
        assert EventType.SCOPE_VALIDATION_STARTED.value in event_types
        assert EventType.ASSESSMENT_FAILED.value in event_types


@pytest.mark.unit
class TestAssessmentStreamingAndMissingSessions:
    """Tests assessment creation, event streaming, and missing authentication session handling."""

    def test_assessment_with_missing_sessions_marks_suspicious_not_confirmed(self) -> None:
        """When User A/B/Admin sessions are missing, parameterized routes are skipped and
        an unauthenticated 200 OK admin config response is marked SUSPICIOUS_ACCESS, never CONFIRMED.
        """
        repo = _create_memory_repo()
        mgr = SessionManager(load_from_env=False)  # No authenticated sessions configured

        def mock_juice_shop(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/":
                return httpx.Response(200, text="<html>OWASP Juice Shop</html>", headers={"content-type": "text/html"})
            if path == "/rest/admin/application-version":
                return httpx.Response(200, json={"version": "20.3.0"})
            if path == "/rest/admin/application-configuration":
                return httpx.Response(
                    200,
                    json={"application": {"name": "OWASP Juice Shop", "domain": "juice-sh.op"}},
                )
            return httpx.Response(401, json={"error": "Unauthorized"})

        executor = _build_mock_executor(mgr, mock_juice_shop)
        engine = AssessmentEngine(repository=repo, session_manager=mgr, executor=executor)

        session, events = engine.run_assessment_sync("http://localhost:3000")

        assert session.status == "COMPLETED"
        assert session.endpoints_discovered_count == 8
        assert session.confirmed_findings_count == 0
        assert session.suspicious_results_count == 1

        event_types = [e.event_type for e in events]
        assert EventType.ASSESSMENT_STARTED.value in event_types
        assert EventType.SCOPE_VALIDATION_COMPLETED.value in event_types
        assert EventType.CONNECTION_COMPLETED.value in event_types
        assert EventType.SESSION_VALIDATION_COMPLETED.value in event_types
        assert EventType.ENDPOINT_DISCOVERED.value in event_types
        assert EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value in event_types
        assert EventType.EVIDENCE_VALIDATION_COMPLETED.value in event_types
        assert EventType.ASSESSMENT_COMPLETED.value in event_types
        # Must NOT emit finding_confirmed when only unauthenticated suspicious behavior occurred
        assert EventType.FINDING_CONFIRMED.value not in event_types

        findings = repo.list_findings(session.id)
        assert len(findings) == 1
        assert findings[0].validation_status == EvidenceValidationStatus.SUSPICIOUS.value
        assert findings[0].access_verdict == AccessVerdict.SUSPICIOUS_ACCESS.value
        assert findings[0].target_endpoint == "/rest/admin/application-configuration"

        endpoints = repo.list_discovered_endpoints(session.id)
        basket_ep = next(ep for ep in endpoints if ep.path == "/rest/basket/{id}")
        assert basket_ep.test_status == "SKIPPED_MISSING_SESSION"


@pytest.mark.unit
class TestConfirmedVulnerabilityStreaming:
    """Tests end-to-end streaming when User A and User B sessions and owned resources are configured."""

    def test_confirmed_idor_finding_and_evidence_validation(self) -> None:
        repo = _create_memory_repo()
        mgr = SessionManager(load_from_env=False)
        mgr.authenticate_role(Role.USER_A, "userA@juice-sh.op", "passA", token="secret_jwt_user_a")
        mgr.authenticate_role(Role.USER_B, "userB@juice-sh.op", "passB", token="secret_jwt_user_b")
        mgr.register_resource_ownership(Role.USER_A, "basket", "1")
        mgr.register_resource_ownership(Role.USER_A, "basketitems", "1")

        def mock_vulnerable_app(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            auth = request.headers.get("Authorization", "")
            if path == "/":
                return httpx.Response(200, text="<html>Juice Shop</html>", headers={"content-type": "text/html"})
            if path == "/rest/basket/1":
                # Vulnerable IDOR: returns User A's basket to both User A and User B!
                if "secret_jwt_user_a" in auth or "secret_jwt_user_b" in auth:
                    return httpx.Response(
                        200,
                        json={
                            "status": "success",
                            "data": {
                                "id": 1,
                                "UserId": 1,
                                "email": "userA@juice-sh.op",
                                "Products": [{"name": "Apple Juice"}],
                            },
                        },
                    )
                return httpx.Response(401, json={"error": "Unauthorized"})
            if path == "/rest/admin/application-version":
                return httpx.Response(200, json={"version": "20.3.0"})
            return httpx.Response(401, json={"error": "Unauthorized"})

        executor = _build_mock_executor(mgr, mock_vulnerable_app)
        engine = AssessmentEngine(repository=repo, session_manager=mgr, executor=executor)

        session, events = engine.run_assessment_sync("http://localhost:3000")

        assert session.status == "COMPLETED"
        assert session.confirmed_findings_count >= 1

        event_types = [e.event_type for e in events]
        assert EventType.FINDING_CONFIRMED.value in event_types

        findings = repo.list_findings(session.id)
        confirmed = [
            f for f in findings
            if f.validation_status == EvidenceValidationStatus.CONFIRMED.value
            and f.access_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
        ]
        assert len(confirmed) >= 1
        basket_finding = next(f for f in confirmed if f.target_endpoint == "/rest/basket/{id}")
        assert basket_finding.resource_id == "1"
        assert basket_finding.evidence is not None
        assert len(basket_finding.evidence.evidence_sha256) == 64


@pytest.mark.unit
class TestCredentialRedactionAndCancellation:
    """Tests strict credential redaction in events and safe assessment cancellation."""

    def test_credential_redaction_in_event_text_and_metadata(self) -> None:
        raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        raw_msg = f"Testing with Authorization: Bearer {raw_jwt} and \"password\": \"Hunter2!\""
        sanitized_msg = sanitize_event_text(raw_msg)

        assert raw_jwt not in sanitized_msg
        assert "Hunter2!" not in sanitized_msg
        assert "[REDACTED" in sanitized_msg

        raw_meta = {
            "token": "super_secret_token_123",
            "password": "my_password",
            "headers": {"Authorization": f"Bearer {raw_jwt}", "Accept": "application/json"},
            "nested": {"jwt": raw_jwt},
        }
        clean_meta = sanitize_event_metadata(raw_meta)
        serialized = json.dumps(clean_meta)
        assert "super_secret_token_123" not in serialized
        assert "my_password" not in serialized
        assert raw_jwt not in serialized

    def test_safe_cancellation_stops_assessment_and_skips_remaining_stages(self) -> None:
        repo = _create_memory_repo()
        mgr = SessionManager(load_from_env=False)
        token = CancellationToken()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"status": "ok"})

        executor = _build_mock_executor(mgr, mock_handler)
        engine = AssessmentEngine(repository=repo, session_manager=mgr, executor=executor)

        emitted = []
        gen = engine.stream_assessment("http://localhost:3000", cancel_token=token)
        try:
            while True:
                evt = next(gen)
                emitted.append(evt)
                if evt.event_type == EventType.SCOPE_VALIDATION_COMPLETED.value:
                    token.cancel()
        except StopIteration as stop:
            final_session = stop.value

        assert final_session.status == "CANCELLED"
        assert any(e.event_type == EventType.ASSESSMENT_CANCELLED.value for e in emitted)
        assert final_session.stages[AssessmentStage.AUTHORIZATION_TESTING.value].status == StageStatus.SKIPPED


@pytest.mark.unit
class TestHistoryPersistenceAndQueryAdapter:
    """Tests SQLite assessment history retrieval, deterministic Q&A, and report export."""

    def test_history_and_query_adapter_questions(self) -> None:
        repo = _create_memory_repo()
        mgr = SessionManager(load_from_env=False)

        def mock_juice_shop(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(200, text="<html>Juice Shop</html>", headers={"content-type": "text/html"})
            if request.url.path == "/rest/admin/application-configuration":
                return httpx.Response(200, json={"application": {"name": "Juice Shop"}})
            return httpx.Response(401, json={"error": "Unauthorized"})

        executor = _build_mock_executor(mgr, mock_juice_shop)
        engine = AssessmentEngine(repository=repo, session_manager=mgr, executor=executor)
        session, _ = engine.run_assessment_sync("http://localhost:3000")

        # Verify history persistence
        stored_sessions = repo.list_scan_sessions()
        assert len(stored_sessions) == 1
        assert stored_sessions[0].id == session.id

        stored_events = repo.list_events(session.id)
        assert len(stored_events) > 0

        stored_endpoints = repo.list_discovered_endpoints(session.id)
        assert len(stored_endpoints) == 8

        # Verify AssessmentQueryAdapter deterministic answers
        adapter = AssessmentQueryAdapter(repository=repo)

        ans_completed = adapter.answer_question(session.id, "What has the agent completed?")
        assert session.id in ans_completed
        assert "COMPLETED" in ans_completed

        ans_discovered = adapter.answer_question(session.id, "Which endpoints were discovered?")
        assert "/rest/basket/{id}" in ans_discovered
        assert "/rest/admin/application-configuration" in ans_discovered

        ans_tested = adapter.answer_question(session.id, "Which endpoints were tested?")
        assert "PARTIAL_UNAUTH_ONLY" in ans_tested
        assert "SKIPPED_MISSING_SESSION" in ans_tested

        ans_suspicious = adapter.answer_question(session.id, "Why was this result marked suspicious?")
        assert "SUSPICIOUS_ACCESS" in ans_suspicious
        assert "/rest/admin/application-configuration" in ans_suspicious

        ans_evidence = adapter.answer_question(session.id, "Show me the evidence for this finding.")
        assert "Evidence SHA-256" in ans_evidence

        ans_fix = adapter.answer_question(session.id, "What should I fix first?")
        assert "Remediation Priority Plan" in ans_fix

        # Verify JSON & Markdown report export
        json_rep = json.loads(adapter.export_report_json(session.id))
        assert json_rep["session"]["id"] == session.id
        assert len(json_rep["discovered_endpoints"]) == 8

        md_rep = adapter.export_report_markdown(session.id)
        assert f"# AuthScope Security Assessment Report — `{session.id}`" in md_rep
        assert "/rest/admin/application-configuration" in md_rep


@pytest.mark.integration
def test_live_juice_shop_assessment_streaming() -> None:
    """Runs a real end-to-end streaming assessment against locally running OWASP Juice Shop."""
    try:
        probe = httpx.get("http://localhost:3000", timeout=2.0, follow_redirects=False)
        is_reachable = probe.status_code > 0
    except httpx.HTTPError:
        is_reachable = False

    if not is_reachable:
        pytest.skip("Local OWASP Juice Shop is not reachable at http://localhost:3000")

    repo = _create_memory_repo()
    engine = AssessmentEngine(repository=repo)
    session, events = engine.run_assessment_sync("http://localhost:3000")

    assert session.status == "COMPLETED"
    assert session.endpoints_discovered_count == 8
    assert session.endpoints_tested_count >= 4
    assert len(events) >= 10
    # Juice Shop exposes /rest/admin/application-configuration unauthenticated -> flagged as SUSPICIOUS_ACCESS
    assert session.suspicious_results_count >= 1
