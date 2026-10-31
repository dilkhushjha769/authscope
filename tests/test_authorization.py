"""Unit and mocked integration tests for Phase 3 Authorization-Differential Testing Engine.

Covers:
1. Role-based test accounts & AuthenticationAdapter interface.
2. Endpoint discovery, classification, and resource ID extraction.
3. Authorized owner access.
4. Unauthorized user access denied (401/403).
5. Confirmed vs. Suspicious cross-user access (BOLA/IDOR & BFLA).
6. Different response bodies & self-scoped profile responses.
7. Missing sessions handling (never inventing sessions).
8. Invalid endpoints, unowned resource IDs, and human approval boundaries.
9. False-positive prevention (SPA HTML 200 OK fallbacks, empty payloads, soft JSON errors).
"""

import httpx
import pytest

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import (
    AuthCredentials,
    AuthenticationAdapter,
    AuthenticationResult,
    EnvTokenAuthenticationAdapter,
    Role,
    SessionManager,
)
from backend.scanner.endpoint_discovery import (
    DiscoveredEndpoint,
    EndpointCategory,
    EndpointDiscovery,
)
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.scanner.authorization_tester import AuthorizationTester, VerifiedPromotionResult, compare_access
from backend.scanner.source_analyzer import FindingClassification, SourceFinding
from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.storage.models import FindingStatus
from backend.analysis.evidence_validator import EvidenceValidationStatus
from backend.utils.helpers import (
    HumanApprovalRequiredError,
    InvalidTargetURLError,
    MissingSessionError,
    ScopeViolationError,
    SessionAuthenticationError,
)


class MockCustomAuthAdapter(AuthenticationAdapter):
    """Test adapter simulating token retrieval for User A and User B."""

    def authenticate(self, role: Role, credentials: AuthCredentials) -> AuthenticationResult:
        if role == Role.USER_A and credentials.email == "usera@juice-sh.op":
            return AuthenticationResult(
                is_authenticated=True,
                token="adapter_jwt_user_a",
                user_id="1",
                owned_resources={"basket": ["1"]},
            )
        return AuthenticationResult(
            is_authenticated=False,
            error_message=f"No credentials configured for {role.value}",
        )


@pytest.mark.unit
class TestRoleSessionsAndAuthAdapter:
    """Verifies multi-role session isolation and AuthenticationAdapter behavior."""

    def test_session_manager_role_isolation(self):
        """Ensures session manager isolates tokens and ownership across personas."""
        mgr = SessionManager(load_from_env=False)
        mgr.authenticate_role(Role.USER_A, "userA@test.com", "passA", token="token_a")
        mgr.authenticate_role(Role.USER_B, "userB@test.com", "passB", token="token_b")
        mgr.register_resource_ownership(Role.USER_A, "basket", "1")

        headers_a = mgr.get_auth_headers(Role.USER_A)
        headers_b = mgr.get_auth_headers(Role.USER_B)

        assert headers_a["Authorization"] == "Bearer token_a"
        assert headers_b["Authorization"] == "Bearer token_b"
        assert mgr.get_session(Role.USER_A).owns_resource("basket", "1") is True
        assert mgr.get_session(Role.USER_B).owns_resource("basket", "1") is False
        assert mgr.get_auth_headers(Role.ANONYMOUS) == {}

    def test_authentication_adapter_interface(self):
        """Verifies AuthenticationAdapter authenticates configured accounts and rejects unconfigured ones."""
        mgr = SessionManager(load_from_env=False, auth_adapter=MockCustomAuthAdapter())
        mgr.set_credentials(Role.USER_A, email="usera@juice-sh.op")

        session_a = mgr.authenticate_with_adapter(Role.USER_A)
        assert session_a.is_authenticated is True
        assert session_a.user_id == "1"
        assert session_a.owns_resource("basket", "1") is True

        # User B is not configured in MockCustomAuthAdapter -> must raise SessionAuthenticationError
        with pytest.raises(SessionAuthenticationError):
            mgr.authenticate_with_adapter(Role.USER_B)

    def test_env_token_adapter_does_not_invent_sessions(self):
        """Verifies EnvTokenAuthenticationAdapter fails cleanly when no token is configured."""
        adapter = EnvTokenAuthenticationAdapter(role_tokens={Role.USER_A: ""})
        res = adapter.authenticate(Role.USER_A, AuthCredentials(email="user1@juice-sh.op"))
        assert res.is_authenticated is False
        assert res.token is None


@pytest.mark.unit
class TestEndpointDiscovery:
    """Verifies route discovery, classification, and resource identifier extraction."""

    def test_extract_resource_metadata_from_concrete_and_template_paths(self):
        """Checks parameter and resource ID extraction."""
        path1, params1, rtype1, rid1 = EndpointDiscovery.extract_resource_metadata("/rest/basket/1")
        assert path1 == "/rest/basket/1"
        assert "id" in params1
        assert rtype1 == "basket"
        assert rid1 == "1"

        path2, params2, rtype2, rid2 = EndpointDiscovery.extract_resource_metadata("/api/Users/{id}")
        assert path2 == "/api/Users/{id}"
        assert params2 == ["id"]
        assert rtype2 == "user"
        assert rid2 is None

    def test_endpoint_classification(self):
        """Verifies security categorization of routes."""
        disc = EndpointDiscovery(base_url="http://localhost:3000")
        routes = disc.discover_known_routes()
        assert len(routes) >= 6

        by_path = {r.path: r for r in routes}
        assert by_path["/rest/basket/{id}"].category == EndpointCategory.USER_OBJECT
        assert by_path["/rest/basket/{id}"].requires_owner_match is True
        assert by_path["/api/Users"].category == EndpointCategory.ADMIN_FUNCTION
        assert by_path["/rest/admin/application-version"].category == EndpointCategory.PUBLIC

    def test_reject_invalid_or_external_endpoint(self):
        """Ensures invalid paths or unreplaced templates without IDs are rejected."""
        disc = EndpointDiscovery(base_url="http://localhost:3000")
        with pytest.raises(InvalidTargetURLError):
            disc.register_endpoint(path="/rest/basket/\x00invalid")

        ep = disc.register_endpoint(path="/rest/basket/{id}")
        with pytest.raises(InvalidTargetURLError):
            disc.build_concrete_url(ep, resource_id=None)


@pytest.mark.unit
class TestAuthorizationDifferentialEngine:
    """Verifies ResponseAnalyzer and AuthorizationTester differential scenarios."""

    def test_response_analyzer_identifies_success(self):
        """Verifies 200 OK with valid data is evaluated as successful."""
        response = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": {"id": 1}}',
            json_data={"data": {"id": 1}}
        )
        assert ResponseAnalyzer.is_success_response(response) is True

    def test_response_analyzer_filters_error_status_codes(self):
        """Verifies 401 and 403 responses are recognized as denied access."""
        unauthorized = HttpResponseModel(status_code=401, body="Unauthorized")
        forbidden = HttpResponseModel(status_code=403, body="Forbidden")

        assert ResponseAnalyzer.is_success_response(unauthorized) is False
        assert ResponseAnalyzer.is_success_response(forbidden) is False

    def test_authorized_owner_access_allowed(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that when a role is authorized for a route, verdict is ALLOWED_ACCESS."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                json={"version": "20.3.0"}
            )

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.test_resource_access(
            endpoint="/rest/admin/application-version",
            owner_role=Role.ADMIN,
            test_roles=[Role.USER_A, Role.ANONYMOUS],
        )

        assert result.is_discrepancy_detected is False
        assert result.overall_verdict == AccessVerdict.ALLOWED_ACCESS
        assert result.probe_outcomes[Role.USER_A].verdict == AccessVerdict.ALLOWED_ACCESS
        assert result.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.ALLOWED_ACCESS

    def test_unauthorized_user_access_properly_denied(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that when User B gets 403/401 on User A's resource, verdict is CORRECTLY_DENIED."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")
        session_manager.register_resource_ownership(Role.USER_A, "basket", "1")

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth:
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    json={"status": "success", "data": {"id": 1, "UserId": 1, "Products": [{"name": "Juice"}]}}
                )
            return httpx.Response(
                status_code=403,
                headers={"Content-Type": "application/json"},
                json={"error": "Access Denied: Basket belongs to another user"}
            )

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.test_resource_access(
            endpoint="/rest/basket/{id}",
            owner_role=Role.USER_A,
            test_roles=[Role.USER_B, Role.ANONYMOUS],
        )

        assert result.is_discrepancy_detected is False
        assert result.is_confirmed is False
        assert result.overall_verdict == AccessVerdict.CORRECTLY_DENIED
        assert result.probe_outcomes[Role.USER_A].verdict == AccessVerdict.ALLOWED_ACCESS
        assert result.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CORRECTLY_DENIED
        assert result.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED
        assert len(result.evidence_artifacts) == 0

    def test_confirmed_cross_user_idor_detection(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that when User B receives User A's protected basket (with UserId=1), BOLA_IDOR is CONFIRMED."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")

        basket_1_payload = {
            "status": "success",
            "data": {
                "id": 1,
                "UserId": 1,
                "Products": [{"id": 10, "name": "Apple Juice", "price": 1.99}]
            }
        }

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth or "jwt_user_b" in auth:
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    json=basket_1_payload
                )
            return httpx.Response(status_code=401, json={"error": "Unauthorized"})

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)

        result = compare_access(
            endpoint="/rest/basket/{id}",
            method="GET",
            resource_id="1",
            owner_role=Role.USER_A,
            roles_to_test=[Role.USER_B, Role.ANONYMOUS],
            executor=executor,
            session_manager=session_manager,
            scope_guard=scope_guard,
        )

        assert result.is_discrepancy_detected is True
        assert result.is_confirmed is True
        assert result.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
        assert result.vulnerability_candidate == "BOLA_IDOR"
        assert result.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
        assert result.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED

        # Check validated evidence artifact
        assert len(result.evidence_artifacts) == 1
        evi = result.evidence_artifacts[0]
        assert evi.endpoint == "/rest/basket/{id}"
        assert evi.resource_id == "1"
        assert evi.test_role == Role.USER_B
        assert evi.authorized_role == Role.USER_A
        assert evi.validation_status == EvidenceValidationStatus.CONFIRMED
        assert evi.request_headers["Authorization"] == "Bearer [REDACTED_BEARER_TOKEN]"

    def test_suspicious_access_when_different_response_bodies(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that if User B gets 200 OK with a substantially different non-empty body and no owner match, it is marked SUSPICIOUS, not CONFIRMED."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth:
                return httpx.Response(
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    json={"data": {"id": 99, "UserId": 1, "secretNotes": "Owner private corporate ledger data"}}
                )
            return httpx.Response(
                status_code=200,
                headers={"Content-Type": "application/json"},
                json={"meta": "partial summary", "notice": " Publicly visible metadata stub only"}
            )

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.test_resource_access(
            endpoint="/rest/basket/99",
            owner_role=Role.USER_A,
            test_roles=[Role.USER_B],
        )

        assert result.is_discrepancy_detected is True
        assert result.is_confirmed is False
        assert result.overall_verdict == AccessVerdict.SUSPICIOUS_ACCESS
        assert result.probe_outcomes[Role.USER_B].verdict == AccessVerdict.SUSPICIOUS_ACCESS
        assert result.evidence_artifacts[0].validation_status == EvidenceValidationStatus.SUSPICIOUS

    def test_false_positive_prevention_spa_html_fallback_and_empty_json(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Ensures HTTP 200 SPA HTML fallback pages, soft errors, and self-scoped responses do NOT trigger false positives."""
        session_manager.set_credentials(Role.USER_A, email="user1@juice-sh.op", token="jwt_a")
        session_manager.set_credentials(Role.USER_B, email="user2@juice-sh.op", token="jwt_b")

        owner_json_resp = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"data": {"id": 1, "UserId": 1, "email": "user1@juice-sh.op"}}',
            json_data={"data": {"id": 1, "UserId": 1, "email": "user1@juice-sh.op"}},
        )

        # 1. SPA HTML 200 OK fallback
        spa_html_resp = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body="<!doctype html><html><body><app-root></app-root>OWASP Juice Shop</body></html>",
            json_data=None,
        )
        comp_spa = ResponseAnalyzer.compare_responses(owner_json_resp, spa_html_resp, expected_resource_id="1")
        assert comp_spa.verdict == AccessVerdict.CORRECTLY_DENIED
        assert comp_spa.is_unauthorized_access is False

        # 2. Empty JSON payload 200 OK (e.g. {"user": {}})
        empty_json_resp = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"user": {}}',
            json_data={"user": {}},
        )
        comp_empty = ResponseAnalyzer.compare_responses(owner_json_resp, empty_json_resp, expected_resource_id="1")
        assert comp_empty.verdict == AccessVerdict.CORRECTLY_DENIED

        # 3. Soft error in 200 OK JSON
        soft_err_resp = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"status": "error", "message": "Unauthorized access"}',
            json_data={"status": "error", "message": "Unauthorized access"},
        )
        comp_err = ResponseAnalyzer.compare_responses(owner_json_resp, soft_err_resp, expected_resource_id="1")
        assert comp_err.verdict == AccessVerdict.CORRECTLY_DENIED

        # 4. Self-scoped response returning User B's own email/ID
        self_scoped_resp = HttpResponseModel(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"user": {"id": 2, "email": "user2@juice-sh.op"}}',
            json_data={"user": {"id": 2, "email": "user2@juice-sh.op"}},
        )
        comp_self = ResponseAnalyzer.compare_responses(
            owner_response=owner_json_resp,
            test_response=self_scoped_resp,
            owner_email="user1@juice-sh.op",
            test_email="user2@juice-sh.op",
        )
        assert comp_self.verdict == AccessVerdict.ALLOWED_ACCESS
        assert comp_self.is_unauthorized_access is False

    def test_missing_session_raises_error(self, scope_guard: ScopeGuard):
        """Verifies that testing with an unauthenticated role raises MissingSessionError instead of inventing a session."""
        unauthenticated_mgr = SessionManager(load_from_env=False)
        tester = AuthorizationTester(session_manager=unauthenticated_mgr, scope_guard=scope_guard)

        with pytest.raises(MissingSessionError):
            tester.test_resource_access(
                endpoint="/rest/basket/1",
                owner_role=Role.USER_A,
                test_roles=[Role.USER_B],
            )

    def test_unowned_resource_id_and_human_approval_enforcement(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that tester refuses to invent resource IDs and enforces human approval on non-GET endpoints."""
        tester = AuthorizationTester(session_manager=session_manager, scope_guard=scope_guard)

        # Missing resource_id on parameterized route when User A has no registered basket ID
        with pytest.raises(InvalidTargetURLError):
            tester.test_resource_access(
                endpoint="/rest/basket/{id}",
                owner_role=Role.USER_A,
                test_roles=[Role.USER_B],
            )

        # Non-GET endpoint requires human approval
        post_ep = DiscoveredEndpoint(
            path="/api/Feedbacks",
            method="POST",
            requires_human_approval=True,
        )
        with pytest.raises(HumanApprovalRequiredError):
            tester.test_resource_access(
                endpoint=post_ep,
                owner_role=Role.USER_A,
                test_roles=[Role.USER_B],
                human_approved=False,
            )


class TestRuntimeVerificationAndPromotion:
    """Tests for Phase 5.1 Runtime Verification, Strict Finding Promotion, and Evidence Completeness."""

    @pytest.fixture
    def mock_idor_candidate(self) -> SourceFinding:
        return SourceFinding(
            finding_id="fnd_candidate_001",
            rule_id="AS-PY-BAC-001",
            vulnerability_category="BOLA_IDOR",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            classification=FindingClassification.POTENTIAL_VULNERABILITY,
            file_path="routers/baskets.py",
            route_path="/rest/basket/{id}",
            http_method="GET",
            start_line=15,
            end_line=20,
            code_snippet="def get_basket(id: int): return db.baskets.get(id)",
            detection_explanation="Potential IDOR flaw detected on basket endpoint.",
            detection_method="python_ast",
        )

    def test_verify_potential_finding_confirmed_promotion(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
        mock_idor_candidate: SourceFinding,
    ):
        """Verifies that reproducible unauthorized access promotes POTENTIAL to CONFIRMED_RUNTIME_VULNERABILITY."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")
        session_manager.register_resource_ownership(Role.USER_A, "basket", "1")

        basket_payload = {
            "status": "success",
            "data": {
                "id": 1,
                "UserId": 1,
                "Products": [{"id": 10, "name": "Apple Juice", "price": 1.99}]
            }
        }

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth or "jwt_user_b" in auth:
                return httpx.Response(status_code=200, json=basket_payload)
            return httpx.Response(status_code=401, json={"error": "Unauthorized"})

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.verify_potential_finding(
            candidate=mock_idor_candidate,
            owner_role=Role.USER_A,
            test_roles=[Role.USER_B, Role.ANONYMOUS],
            resource_id="1",
        )

        # 1. Promotion Assertions
        assert result.is_promoted is True
        assert result.new_classification == FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY
        assert result.status == FindingStatus.CONFIRMED.value
        assert result.validation_status == "CONFIRMED"
        assert result.confidence == ConfidenceLevel.CONFIRMED
        assert result.severity == SeverityLevel.HIGH

        # 2. Reproduction Steps Verification
        assert len(result.reproduction_steps) >= 4
        assert any("Target Endpoint & Method: GET" in s for s in result.reproduction_steps)
        assert any("Legitimate Baseline Check" in s for s in result.reproduction_steps)
        assert any("Unauthorized Probe Check" in s for s in result.reproduction_steps)
        assert any("Cryptographic Evidence" in s for s in result.reproduction_steps)

        # 3. Evidence Artifact Verification
        assert result.evidence is not None
        assert len(result.evidence.evidence_sha256) == 64
        assert result.evidence.validation_status == EvidenceValidationStatus.CONFIRMED

        # 4. FindingRecord Generation Verification
        assert result.finding_record is not None
        assert result.finding_record.classification == FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY.value
        assert result.finding_record.status == FindingStatus.CONFIRMED.value
        assert result.finding_record.validation_status == "CONFIRMED"
        assert result.finding_record.severity == SeverityLevel.HIGH
        assert len(result.recommended_fix) > 10

    def test_verify_potential_finding_not_reproducible_when_denied(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
        mock_idor_candidate: SourceFinding,
    ):
        """Verifies that server access denial classifies the finding as NOT_REPRODUCIBLE."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth:
                return httpx.Response(status_code=200, json={"id": 1, "UserId": 1})
            return httpx.Response(status_code=403, json={"error": "Access Denied"})

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.verify_potential_finding(
            candidate=mock_idor_candidate,
            owner_role=Role.USER_A,
            test_roles=[Role.USER_B, Role.ANONYMOUS],
            resource_id="1",
        )

        assert result.is_promoted is False
        assert result.new_classification == FindingClassification.NOT_REPRODUCIBLE
        assert result.status == FindingStatus.FALSE_POSITIVE.value
        assert result.validation_status == "REJECTED"

    def test_verify_potential_finding_suspicious_access_when_divergent(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
        mock_idor_candidate: SourceFinding,
    ):
        """Verifies that behavioral divergence without confirmed sensitive leakage is classified as SUSPICIOUS_ACCESS."""
        session_manager.set_token(Role.USER_A, "jwt_user_a", user_id="1")
        session_manager.set_token(Role.USER_B, "jwt_user_b", user_id="2")

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "jwt_user_a" in auth:
                return httpx.Response(status_code=200, json={"status": "ok", "user": "alice", "items": [1, 2]})
            if "jwt_user_b" in auth:
                # Returns 200 with divergent non-matching data
                return httpx.Response(status_code=200, json={"status": "ok", "user": "bob", "items": []})
            return httpx.Response(status_code=401, json={"error": "unauthorized"})

        client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        executor = RequestExecutor(scope_guard=scope_guard, session_manager=session_manager, client=client)
        tester = AuthorizationTester(executor=executor, session_manager=session_manager, scope_guard=scope_guard)

        result = tester.verify_potential_finding(
            candidate=mock_idor_candidate,
            owner_role=Role.USER_A,
            test_roles=[Role.USER_B, Role.ANONYMOUS],
            resource_id="1",
        )

        assert result.is_promoted is False
        assert result.new_classification == FindingClassification.SUSPICIOUS_ACCESS
        assert result.status == FindingStatus.SUSPECTED.value
        assert result.validation_status == "SUSPICIOUS"

    def test_verify_potential_finding_inconclusive_when_out_of_scope_or_source_only(
        self,
        scope_guard: ScopeGuard,
        session_manager: SessionManager,
    ):
        """Verifies that out-of-scope targets and pure source patterns produce INCONCLUSIVE classifications."""
        tester = AuthorizationTester(scope_guard=scope_guard, session_manager=session_manager)

        # 1. Pure source code location without HTTP route
        source_only_candidate = SourceFinding(
            finding_id="src_only_001",
            rule_id="AS-PY-BAC-001",
            vulnerability_category="BROKEN_ACCESS_CONTROL",
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.MEDIUM,
            classification=FindingClassification.POTENTIAL_VULNERABILITY,
            file_path="auth/decorators.py",
            route_path=None,
            start_line=5,
            end_line=10,
            code_snippet="def custom_helper(): pass",
            detection_explanation="Source code pattern",
            detection_method="python_ast",
        )
        res_source = tester.verify_potential_finding(source_only_candidate)
        assert res_source.is_promoted is False
        assert res_source.new_classification == FindingClassification.INCONCLUSIVE
        assert "no resolvable HTTP route" in res_source.summary

        # 2. Out of scope URL target
        out_of_scope_candidate = {
            "finding_id": "out_of_scope_001",
            "endpoint": "http://169.254.169.254/latest/meta-data",
            "http_method": "GET",
            "classification": "POTENTIAL_VULNERABILITY",
        }
        res_scope = tester.verify_potential_finding(out_of_scope_candidate)
        assert res_scope.is_promoted is False
        assert res_scope.new_classification == FindingClassification.INCONCLUSIVE
        assert "outside authorized testing scope" in res_scope.summary
