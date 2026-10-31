"""Comprehensive Test Suite for the AuthScope Four-Role Authorization Testing System.

Covers all 12 mandatory scenarios:
1. Anonymous access to protected endpoints (MISSING_AUTH vs 401/403 denial).
2. User A accessing their own resources (baseline establishment, permissions & resource tracking).
3. User B attempting to access User A's resources (BOLA / IDOR horizontal privilege escalation).
4. User B attempting unauthorized resource modification using safe test fixtures (and blocking DELETE).
5. Admin accessing permitted administrative endpoints and policy-dependent cross-role evaluation.
6. Normal users (User A, User B) attempting administrative access (BFLA / PRIVILEGE_ESCALATION).
7. Cross-role request comparison across all four roles (Anonymous, User A, User B, Admin).
8. Accurate vulnerability classification (MISSING_AUTH, BOLA_IDOR, BFLA, PRIVILEGE_ESCALATION, INCONCLUSIVE).
9. False-positive prevention (HTTP 200 SPA HTML, soft error JSON, empty payload, self-reflection, public routes).
10. Structured evidence generation, secret redaction, SHA-256 signing, and SQLite storage.
11. End-to-end integration with GeminiAuthScopeAgent, ToolRegistry, ToolRegistryAdapter, and RetestEngine.
12. Regression testing of ScopeGuard boundaries, redirect disabling, and canonical contracts.
"""

from typing import Dict, Any
import httpx
import pytest

from backend.ai_agent import AssessmentRequest, GeminiAgentConfig, GeminiAuthScopeAgent
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.retesting.retest_engine import RetestEngine
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingStatus
from backend.tools.agent_adapter import ToolRegistryAdapter
from backend.tools.authorization_tools import AuthorizationTools
from backend.tools.registry import ToolRegistry
from backend.tools.report_tools import ReportTools
from backend.tools.schemas import (
    CompareEndpointAccessInput,
    GenerateRemediationInput,
    RetestFindingInput,
    SaveFindingInput,
    TestUnauthorizedModificationInput,
)
from backend.utils.helpers import ScopeViolationError, UnsupportedMethodError


# ==============================================================================
# Fixtures & Helpers
# ==============================================================================


@pytest.fixture
def isolated_repo(tmp_path) -> FindingRepository:
    """Provides an isolated SQLite-backed FindingRepository."""
    db_file = tmp_path / "test_four_role_authscope.db"
    db = DatabaseManager(db_path=str(db_file))
    return FindingRepository(db_manager=db)


def build_four_role_tester(
    handler,
    authenticate_user_a: bool = True,
    authenticate_user_b: bool = True,
    authenticate_admin: bool = True,
    register_user_a_basket_1: bool = True,
) -> AuthorizationTester:
    """Creates an AuthorizationTester configured with all four roles and a MockTransport."""
    guard = ScopeGuard()
    sm = SessionManager(load_from_env=False)

    if authenticate_user_a:
        sm.authenticate_role(
            Role.USER_A,
            email="user_a@juice-sh.op",
            password="SecretPasswordA!123",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_payload.sig_a",
        )
        sm.set_token(
            Role.USER_A,
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_payload.sig_a",
            user_id="101",
        )
        if register_user_a_basket_1:
            sm.register_resource_ownership(Role.USER_A, "basket", "1")
            sm.register_resource_ownership(Role.USER_A, "order", "501")

    if authenticate_user_b:
        sm.authenticate_role(
            Role.USER_B,
            email="user_b@juice-sh.op",
            password="SecretPasswordB!456",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_payload.sig_b",
        )
        sm.set_token(
            Role.USER_B,
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_payload.sig_b",
            user_id="202",
        )
        sm.register_resource_ownership(Role.USER_B, "basket", "2")

    if authenticate_admin:
        sm.authenticate_role(
            Role.ADMIN,
            email="admin@juice-sh.op",
            password="SecretAdminPassword!789",
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_payload.sig_admin",
        )
        sm.set_token(
            Role.ADMIN,
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_payload.sig_admin",
            user_id="1",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    executor = RequestExecutor(scope_guard=guard, session_manager=sm, client=client)
    return AuthorizationTester(executor=executor, session_manager=sm, scope_guard=guard)


# ==============================================================================
# Scenario 1: Anonymous Access to Protected Endpoints
# ==============================================================================


@pytest.mark.security
def test_scenario_1_anonymous_access_to_protected_endpoints():
    """Tests Role 1 (Anonymous): detects MISSING_AUTH when protected info is exposed without login,
    and confirms CORRECTLY_DENIED when unauthenticated requests receive 401/403.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        url = str(request.url)
        # Endpoint A: Vulnerable protected endpoint leaking User A's basket to Anonymous
        if "/rest/basket/1" in url:
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "id": 1,
                        "UserId": 101,
                        "email": "user_a@juice-sh.op",
                        "Products": [{"id": 10, "name": "Apple Juice"}],
                    },
                },
            )
        # Endpoint B: Secure endpoint rejecting Anonymous with 401
        if "/api/Cards" in url:
            if not auth:
                return httpx.Response(401, json={"error": "Authentication required"})
            return httpx.Response(
                200,
                json={"data": [{"id": 7, "UserId": 101, "cardNum": "************1234"}]},
            )
        return httpx.Response(404)

    tester = build_four_role_tester(handler)

    # 1A: Vulnerable endpoint accessed by Anonymous -> MISSING_AUTH confirmed
    vuln_res = tester.test_resource_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        test_roles=[Role.ANONYMOUS],
        resource_id="1",
    )
    assert vuln_res.is_confirmed is True
    assert vuln_res.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert "MISSING_AUTH" in vuln_res.detected_vulnerabilities
    assert vuln_res.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert vuln_res.probe_outcomes[Role.ANONYMOUS].vulnerability_type == "MISSING_AUTH"

    # 1B: Properly protected endpoint -> Anonymous is CORRECTLY_DENIED
    secure_res = tester.test_resource_access(
        endpoint="/api/Cards",
        owner_role=Role.USER_A,
        test_roles=[Role.ANONYMOUS],
    )
    assert secure_res.is_confirmed is False
    assert secure_res.is_discrepancy_detected is False
    assert secure_res.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED


# ==============================================================================
# Scenario 2: User A Accessing Their Own Resources (Baseline & Permissions)
# ==============================================================================


@pytest.mark.security
def test_scenario_2_user_a_accessing_own_resources_baseline():
    """Tests Role 2 (User A): establishes legitimate baseline response and records accessible
    resources and permissions in SessionManager.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "user_a_payload" in auth and "/rest/basket/1" in str(request.url):
            return httpx.Response(
                200,
                json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
            )
        return httpx.Response(403, json={"error": "Forbidden"})

    tester = build_four_role_tester(handler)
    res = tester.test_resource_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
        resource_id="1",
    )

    # User A baseline succeeded and was recorded
    user_a_outcome = res.probe_outcomes[Role.USER_A]
    assert user_a_outcome.verdict == AccessVerdict.ALLOWED_ACCESS
    assert user_a_outcome.response.status_code == 200
    assert "1" in user_a_outcome.extracted_resource_ids

    user_a_session = tester.session_manager.get_session(Role.USER_A)
    assert "/rest/basket/1" in user_a_session.accessible_resources
    assert "GET:/rest/basket/1" in user_a_session.permissions


# ==============================================================================
# Scenario 3: User B Attempting to Access User A's Resources (BOLA / IDOR)
# ==============================================================================


@pytest.mark.security
def test_scenario_3_user_b_reading_user_a_resources_bola_idor():
    """Tests Role 3 (User B): detects horizontal privilege escalation (BOLA/IDOR) when User B
    reads User A's resource.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/basket/1" in str(request.url) and ("user_a_payload" in auth or "user_b_payload" in auth):
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "id": 1,
                        "UserId": 101,
                        "email": "user_a@juice-sh.op",
                        "Products": [{"id": 5, "name": "Lemon Juice"}],
                    },
                },
            )
        return httpx.Response(401)

    tester = build_four_role_tester(handler)
    res = tester.test_bola_idor(
        endpoint="/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )

    assert res.is_confirmed is True
    assert res.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.vulnerability_candidate == "BOLA_IDOR"
    assert "BOLA_IDOR" in res.detected_vulnerabilities
    assert res.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS


# ==============================================================================
# Scenario 4: User B Attempting Unauthorized Modification Using Safe Test Fixtures
# ==============================================================================


@pytest.mark.security
def test_scenario_4_user_b_unauthorized_resource_modification_with_safe_fixtures():
    """Tests Role 3 (User B) attempting to modify User A's resource using controlled,
    non-destructive PUT/PATCH payloads, and verifies that DELETE and destructive payloads are blocked.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if request.method in ("PUT", "PATCH") and "/rest/basket/1" in str(request.url):
            if "user_a_payload" in auth or "user_b_payload" in auth:
                return httpx.Response(
                    200,
                    json={
                        "status": "success",
                        "data": {
                            "id": 1,
                            "UserId": 101,
                            "email": "user_a@juice-sh.op",
                            "note": "authscope_non_destructive_probe",
                        },
                    },
                )
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(404)

    tester = build_four_role_tester(handler)

    # 4A: Non-destructive PUT modification with safe test fixture detects horizontal BOLA_IDOR
    mod_res = tester.test_unauthorized_modification(
        endpoint="/rest/basket/1",
        method="PUT",
        safe_payload={"quantity": 1, "note": "authscope_safe_fixture"},
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
        include_anonymous=True,
    )
    assert mod_res.is_confirmed is True
    assert mod_res.method == "PUT"
    assert mod_res.vulnerability_candidate == "BOLA_IDOR"
    assert mod_res.status_codes_by_role["user_a"] == 200
    assert mod_res.status_codes_by_role["user_b"] == 200
    assert mod_res.status_codes_by_role["anonymous"] == 401
    assert len(mod_res.finding_records) == 1
    assert "modify" in mod_res.finding_records[0].description.lower()

    # Verify default GET-only scope was restored on ScopeGuard after the test
    assert tester.scope_guard.allowed_methods == ["GET"]

    # 4B: Destructive HTTP DELETE is strictly rejected
    with pytest.raises(UnsupportedMethodError):
        tester.test_unauthorized_modification(
            endpoint="/rest/basket/1",
            method="DELETE",
            resource_id="1",
        )

    # 4C: Destructive payload keys are strictly rejected
    with pytest.raises(UnsupportedMethodError):
        tester.test_unauthorized_modification(
            endpoint="/rest/basket/1",
            method="PUT",
            safe_payload={"delete_basket": True},
            resource_id="1",
        )


# ==============================================================================
# Scenario 5: Admin Accessing Permitted Administrative Endpoints & Policy Evaluation
# ==============================================================================


@pytest.mark.security
def test_scenario_5_admin_permitted_endpoints_and_policy_awareness():
    """Tests Role 4 (Admin): verifies authorized access to administrative endpoints and
    policy-dependent evaluation when Admin accesses user resources.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        url = str(request.url)
        if "/rest/admin/application-configuration" in url:
            if "admin_payload" in auth:
                return httpx.Response(
                    200,
                    json={"config": {"security": {"cookieSecret": "admin_only_secret"}}},
                )
            return httpx.Response(403, json={"error": "Admin privileges required"})
        if "/rest/basket/1" in url:
            if "user_a_payload" in auth or "admin_payload" in auth:
                return httpx.Response(
                    200,
                    json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
                )
            return httpx.Response(403, json={"error": "Forbidden"})
        return httpx.Response(404)

    tester = build_four_role_tester(handler)

    # 5A: Admin accessing admin endpoint while Anonymous, User A, User B are denied -> Secure
    admin_ep_res = tester.test_four_role_access(
        endpoint="/rest/admin/application-configuration",
        owner_role=Role.ADMIN,
    )
    assert admin_ep_res.is_confirmed is False
    assert admin_ep_res.is_discrepancy_detected is False
    assert admin_ep_res.probe_outcomes[Role.ADMIN].verdict == AccessVerdict.ALLOWED_ACCESS
    assert admin_ep_res.probe_outcomes[Role.USER_A].verdict == AccessVerdict.CORRECTLY_DENIED
    assert admin_ep_res.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CORRECTLY_DENIED
    assert admin_ep_res.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED

    # 5B: Admin accessing User A's resource when admin_policy="allowed" -> ALLOWED_ACCESS (not a vulnerability)
    allowed_policy_res = tester.test_four_role_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        resource_id="1",
        admin_policy="allowed",
    )
    assert allowed_policy_res.is_confirmed is False
    assert allowed_policy_res.probe_outcomes[Role.ADMIN].verdict == AccessVerdict.ALLOWED_ACCESS

    # 5C: Admin accessing User A's resource when admin_policy="denied" (strict tenant privacy policy)
    denied_policy_res = tester.test_four_role_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        resource_id="1",
        admin_policy="denied",
    )
    assert denied_policy_res.is_confirmed is True
    assert denied_policy_res.probe_outcomes[Role.ADMIN].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS


# ==============================================================================
# Scenario 6: Normal Users Attempting Administrative Access (Vertical Escalation)
# ==============================================================================


@pytest.mark.security
def test_scenario_6_normal_users_attempting_administrative_access():
    """Tests vertical privilege escalation (BFLA & PRIVILEGE_ESCALATION) when User A or User B
    accesses an administrative endpoint.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/admin/application-configuration" in str(request.url):
            if "admin_payload" in auth or "user_a_payload" in auth or "user_b_payload" in auth:
                return httpx.Response(
                    200,
                    json={
                        "config": {
                            "application": {"name": "OWASP Juice Shop"},
                            "security": {"jwtSecret": "private_hmac_signing_key"},
                        }
                    },
                )
            return httpx.Response(401, json={"error": "Login required"})
        return httpx.Response(404)

    tester = build_four_role_tester(handler)
    res = tester.test_four_role_access(
        endpoint="/rest/admin/application-configuration",
        owner_role=Role.ADMIN,
    )

    assert res.is_confirmed is True
    assert res.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.vulnerability_candidate == "BFLA"
    assert "BFLA" in res.detected_vulnerabilities
    assert "PRIVILEGE_ESCALATION" in res.detected_vulnerabilities
    assert res.probe_outcomes[Role.USER_A].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED


# ==============================================================================
# Scenario 7: Cross-Role Request Comparison Matrix (All Four Roles)
# ==============================================================================


@pytest.mark.security
def test_scenario_7_four_role_cross_role_comparison_matrix():
    """Verifies that compare_four_roles compares status codes, response bodies, resource IDs,
    sensitive information exposure, permission differences, and response behavior across
    Anonymous, User A, User B, and Admin.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/basket/1" in str(request.url):
            if not auth:
                return httpx.Response(401, json={"error": "Unauthenticated"})
            # User A, User B, and Admin all get User A's basket #1
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": 1,
                        "UserId": 101,
                        "email": "user_a@juice-sh.op",
                        "token_hint": "sensitive_val",
                    }
                },
            )
        return httpx.Response(404)

    tester = build_four_role_tester(handler)
    res = tester.compare_four_roles(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        resource_id="1",
        admin_policy="allowed",
    )

    # 1. Status codes across all 4 roles
    assert res.status_codes_by_role == {
        "anonymous": 401,
        "user_a": 200,
        "user_b": 200,
        "admin": 200,
    }
    # 2. Returned resource identifiers
    assert "1" in res.resource_ids_by_role["user_a"]
    assert "1" in res.resource_ids_by_role["user_b"]
    assert res.resource_ids_by_role["anonymous"] == []
    # 3. Sensitive fields exposed
    assert "email" in res.sensitive_fields_by_role["user_b"]
    assert "token_hint" in res.sensitive_fields_by_role["user_b"]
    # 4. Response behaviors by role
    assert res.response_behaviors_by_role["anonymous"] == AccessVerdict.CORRECTLY_DENIED.value
    assert res.response_behaviors_by_role["user_a"] == AccessVerdict.ALLOWED_ACCESS.value
    assert res.response_behaviors_by_role["user_b"] == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
    assert res.response_behaviors_by_role["admin"] == AccessVerdict.ALLOWED_ACCESS.value
    # 5. Permission differences
    assert len(res.permission_differences) == 1
    assert "user_b" in res.permission_differences[0]
    assert "BOLA_IDOR" in res.permission_differences[0]


# ==============================================================================
# Scenario 8: Vulnerability Classification Accuracy
# ==============================================================================


@pytest.mark.security
def test_scenario_8_vulnerability_classification_accuracy():
    """Verifies distinct classification of MISSING_AUTH, BOLA_IDOR, BFLA, PRIVILEGE_ESCALATION,
    and INCONCLUSIVE when evidence is insufficient.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/rest/basket/1" in url:
            # Both Anonymous and User B can access User A's basket
            return httpx.Response(
                200,
                json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
            )
        if "/rest/admin/application-configuration" in url:
            return httpx.Response(
                200,
                json={"config": {"security": {"cookieSecret": "secret_123"}}},
            )
        return httpx.Response(404)

    tester = build_four_role_tester(handler)

    # Both MISSING_AUTH (for Anonymous) and BOLA_IDOR (for User B) detected on /rest/basket/1
    basket_res = tester.test_four_role_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        resource_id="1",
        admin_policy="allowed",
    )
    assert "MISSING_AUTH" in basket_res.detected_vulnerabilities
    assert "BOLA_IDOR" in basket_res.detected_vulnerabilities
    assert basket_res.probe_outcomes[Role.ANONYMOUS].vulnerability_type == "MISSING_AUTH"
    assert basket_res.probe_outcomes[Role.USER_B].vulnerability_type == "BOLA_IDOR"

    # Both MISSING_AUTH, BFLA, and PRIVILEGE_ESCALATION detected on /rest/admin/application-configuration
    admin_res = tester.test_four_role_access(
        endpoint="/rest/admin/application-configuration",
        owner_role=Role.ADMIN,
    )
    assert "MISSING_AUTH" in admin_res.detected_vulnerabilities
    assert "BFLA" in admin_res.detected_vulnerabilities
    assert "PRIVILEGE_ESCALATION" in admin_res.detected_vulnerabilities

    # Unverified ownership on object endpoint -> INCONCLUSIVE (never CONFIRMED)
    inconclusive_res = tester.test_resource_access(
        endpoint="/rest/basket/999",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
        resource_id="999",
    )
    assert inconclusive_res.overall_verdict == AccessVerdict.INCONCLUSIVE
    assert inconclusive_res.is_confirmed is False


# ==============================================================================
# Scenario 9: False-Positive Prevention
# ==============================================================================


@pytest.mark.security
def test_scenario_9_false_positive_prevention_on_http_200():
    """Ensures HTTP 200 OK responses are NOT treated as vulnerabilities when they return:
    1. SPA HTML fallback shell
    2. Soft error JSON (e.g. {"status": "error", "error": "Unauthorized"})
    3. Empty JSON payload (e.g. {"user": {}})
    4. Self-scoped user profile (/rest/user/whoami returning User B's own profile)
    5. Public catalog/version endpoint
    """
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        url = str(request.url)

        if "/rest/basket/1" in url:
            if "user_a_payload" in auth:
                return httpx.Response(200, json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}})
            if "user_b_payload" in auth:
                # Soft error with HTTP 200
                return httpx.Response(200, json={"status": "error", "error": "Unauthorized access to basket"})
            # Anonymous gets SPA HTML shell with HTTP 200
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<!doctype html><html><body><app-root></app-root></body></html>",
            )

        if "/rest/user/whoami" in url:
            if "user_a_payload" in auth:
                return httpx.Response(200, json={"user": {"id": 101, "email": "user_a@juice-sh.op"}})
            if "user_b_payload" in auth:
                return httpx.Response(200, json={"user": {"id": 202, "email": "user_b@juice-sh.op"}})
            return httpx.Response(200, json={"user": {}})

        if "/rest/admin/application-version" in url:
            return httpx.Response(200, json={"version": "14.5.0"})

        return httpx.Response(404)

    tester = build_four_role_tester(handler)

    # 1 & 2: Soft error JSON (User B) and SPA HTML fallback (Anonymous) on /rest/basket/1
    res_basket = tester.test_resource_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B, Role.ANONYMOUS],
        resource_id="1",
    )
    assert res_basket.is_confirmed is False
    assert res_basket.is_discrepancy_detected is False
    assert res_basket.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CORRECTLY_DENIED
    assert res_basket.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED

    # 3 & 4: /rest/user/whoami returning each user's own profile or empty {"user": {}} for Anonymous
    res_whoami = tester.test_resource_access(
        endpoint="/rest/user/whoami",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B, Role.ANONYMOUS],
    )
    assert res_whoami.is_confirmed is False
    assert res_whoami.is_discrepancy_detected is False
    assert res_whoami.probe_outcomes[Role.USER_B].verdict == AccessVerdict.ALLOWED_ACCESS
    assert res_whoami.probe_outcomes[Role.ANONYMOUS].verdict == AccessVerdict.CORRECTLY_DENIED

    # 5: Public endpoint /rest/admin/application-version
    res_pub = tester.test_four_role_access(
        endpoint="/rest/admin/application-version",
        owner_role=Role.USER_A,
    )
    assert res_pub.is_confirmed is False
    assert res_pub.is_discrepancy_detected is False


# ==============================================================================
# Scenario 10: Evidence Generation, Redaction & SQLite Storage
# ==============================================================================


@pytest.mark.security
def test_scenario_10_evidence_generation_redaction_and_sqlite_storage(isolated_repo: FindingRepository):
    """Verifies that confirmed findings generate complete structured evidence with all 10 required
    fields, redact all tokens/passwords/cookies, and persist cleanly in SQLite.
    """
    raw_jwt_b = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_payload.sig_b"
    raw_password = "SecretPasswordB!456"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json", "Set-Cookie": "session_id=raw_cookie_secret_999"},
            json={
                "status": "success",
                "data": {
                    "id": 1,
                    "UserId": 101,
                    "email": "user_a@juice-sh.op",
                    "password": raw_password,
                    "token": raw_jwt_b,
                },
            },
        )

    tester = build_four_role_tester(handler)
    diff_res = tester.test_resource_access(
        endpoint="/rest/basket/1",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
        resource_id="1",
        scan_id="scan_four_role_10",
    )

    assert diff_res.is_confirmed is True
    assert len(diff_res.finding_records) == 1

    saved_ids = tester.save_findings_to_repository(
        diff_res,
        repository=isolated_repo,
        scan_id="scan_four_role_10",
    )
    assert len(saved_ids) == 1

    persisted = isolated_repo.get_finding(saved_ids[0])
    assert persisted is not None
    assert persisted.vulnerability_type == "BOLA_IDOR"
    assert persisted.endpoint == "/rest/basket/1"
    assert persisted.http_method == "GET"
    assert persisted.affected_role == "user_b"
    assert persisted.expected_behavior != ""
    assert persisted.actual_behavior != ""
    assert persisted.description != ""

    details = persisted.technical_details
    assert details["vulnerability_type"] == "BOLA_IDOR"
    assert details["affected_endpoint"] == "/rest/basket/1"
    assert details["http_method"] == "GET"
    assert details["testing_role"] == "user_b"
    assert "request_details" in details
    assert "sanitized_response_details" in details
    assert len(details["reproducibility_steps"]) >= 3
    assert "risk_assessment" in details
    assert details["risk_assessment"]["severity"] == "HIGH"

    # Verify zero secret leakage in persisted record or evidence
    serialized = str(persisted.model_dump())
    assert raw_jwt_b not in serialized
    assert raw_password not in serialized
    assert "raw_cookie_secret_999" not in serialized
    assert persisted.evidence is not None
    assert len(persisted.evidence.evidence_sha256) == 64


# ==============================================================================
# Scenario 11: AI Agent & Approved Tool Registry End-to-End Integration
# ==============================================================================


@pytest.mark.asyncio
async def test_scenario_11_ai_agent_and_tool_registry_integration(isolated_repo: FindingRepository):
    """Verifies that the AI agent and ToolRegistryAdapter can:
    1. Select an endpoint for testing.
    2. Select the appropriate testing roles.
    3. Execute authorized role-based requests.
    4. Compare responses across all 4 roles.
    5. Identify potential vulnerabilities.
    6. Produce structured findings.
    7. Save evidence to SQLite.
    8. Recommend fixes.
    9. Support automated retesting (verifying remediation when fixed).
    """
    is_remediated = False

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "/rest/basket/1" in str(request.url):
            if "user_a_payload" in auth:
                return httpx.Response(
                    200,
                    json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
                )
            if is_remediated:
                return httpx.Response(403, json={"error": "Access Denied: Basket belongs to another user"})
            return httpx.Response(
                200,
                json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
            )
        return httpx.Response(404)

    tester = build_four_role_tester(handler)
    retest_engine = RetestEngine(repository=isolated_repo, tester=tester)
    auth_tools = AuthorizationTools(
        tester=tester,
        scope_guard=tester.scope_guard,
        session_manager=tester.session_manager,
        executor=tester.executor,
        repository=isolated_repo,
    )
    report_tools = ReportTools(
        validator=tester.evidence_validator,
        repository=isolated_repo,
        retest_engine=retest_engine,
    )
    registry = ToolRegistry(
        scope_guard=tester.scope_guard,
        executor=tester.executor,
        session_manager=tester.session_manager,
        authorization_tools=auth_tools,
        report_tools=report_tools,
    )
    adapter = ToolRegistryAdapter(registry=registry)

    # Step 1-7: Execute 4-role comparison & save finding through ToolRegistryAdapter
    comp_envelope = await adapter.execute_tool_call(
        tool_name="test_four_role_access",
        arguments={
            "endpoint": "/rest/basket/1",
            "owner_role": "USER_A",
            "test_roles": ["ANONYMOUS", "USER_B", "ADMIN"],
            "resource_id": "1",
            "admin_policy": "allowed",
            "save_findings": True,
            "scan_id": "scan_agent_e2e",
        },
        context={"assessment_id": "scan_agent_e2e", "caller": "gemini_agent"},
    )
    assert comp_envelope["ok"] is True
    data = comp_envelope["data"]
    assert data["is_confirmed"] is True
    assert "BOLA_IDOR" in data["detected_vulnerabilities"]
    assert "MISSING_AUTH" in data["detected_vulnerabilities"]
    assert len(data["saved_finding_ids"]) >= 1
    finding_id = data["saved_finding_ids"][0]

    # Step 8: Generate server-side remediation recommendation via ToolRegistryAdapter
    rem_envelope = await adapter.execute_tool_call(
        tool_name="generate_remediation",
        arguments={
            "finding_id": finding_id,
            "category": "BOLA_IDOR",
            "endpoint": "/rest/basket/1",
            "method": "GET",
            "code_snippet": "BasketModel.findByPk(req.params.id)",
        },
        context={"assessment_id": "scan_agent_e2e"},
    )
    assert rem_envelope["ok"] is True
    assert "ownership" in rem_envelope["data"]["recommendation"].lower()

    # Step 9: Simulate developer applying the fix and run automated retest via ToolRegistryAdapter
    is_remediated = True
    retest_envelope = await adapter.execute_tool_call(
        tool_name="retest_finding",
        arguments={"finding_id": finding_id},
        context={"assessment_id": "scan_agent_e2e"},
    )
    assert retest_envelope["ok"] is True
    retest_data = retest_envelope["data"]
    assert retest_data["remediation_verified"] is True
    assert retest_data["is_still_vulnerable"] is False
    assert retest_data["new_finding_status"] == FindingStatus.REMEDIATED.value

    # Also verify GeminiAuthScopeAgent executes bounded assessment cleanly with the adapter
    agent = GeminiAuthScopeAgent(
        config=GeminiAgentConfig(api_key="", max_iterations=4, max_tool_calls=6),
        scope_guard=tester.scope_guard,
        tool_executor=adapter,
    )
    run_res = await agent.arun_assessment(
        AssessmentRequest(
            assessment_id="scan_agent_e2e",
            target_url="http://localhost:3000",
            candidate_endpoints=["/rest/basket/1"],
        )
    )
    assert run_res.status == "COMPLETED"


# ==============================================================================
# Scenario 12: Regression Testing of Existing Security Guarantees
# ==============================================================================


@pytest.mark.security
def test_scenario_12_regression_scope_guard_redirects_and_canonical_contract():
    """Ensures existing ScopeGuard hard boundaries, disabled redirects, and Phase 5.3 canonical
    finding formats remain 100% intact.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        if "/redirect-test" in str(request.url):
            return httpx.Response(302, headers={"Location": "http://evil-attacker.com/steal"})
        return httpx.Response(
            200,
            json={"data": {"id": 1, "UserId": 101, "email": "user_a@juice-sh.op"}},
        )

    tester = build_four_role_tester(handler)

    # 1. Out-of-scope URL must be blocked by ScopeGuard
    with pytest.raises(ScopeViolationError):
        tester.test_four_role_access(endpoint="http://external-unapproved-site.org/api/users")

    # 2. HTTP 302 redirect is never followed automatically and is treated as CORRECTLY_DENIED
    redir_res = tester.test_resource_access(
        endpoint="/redirect-test",
        owner_role=Role.USER_A,
        test_roles=[Role.USER_B],
    )
    assert redir_res.probe_outcomes[Role.USER_B].response.status_code == 302
    assert redir_res.probe_outcomes[Role.USER_B].verdict == AccessVerdict.CORRECTLY_DENIED

    # 3. Canonical 12-field finding structure remains valid
    diff_res = tester.test_bola_idor(
        endpoint="/rest/basket/1",
        resource_id="1",
        owner_role=Role.USER_A,
        attacker_role=Role.USER_B,
    )
    canon = AuthorizationTester.build_canonical_finding(diff_res, assessment_id="reg_001")
    assert canon is not None
    assert canon["validation_status"] == "CONFIRMED"
    assert canon["testing_role"] == "user_b"
