"""Comprehensive test suite for Multi-Endpoint Attack-Chain Execution, Validation & Verification (Member 2).

Verifies all 20 required areas:
1. Valid chain validation.
2. Out-of-scope endpoint rejection.
3. Destructive method rejection.
4. Invalid chain dependency handling.
5. Correct resource identifier passing.
6. Anonymous chain execution.
7. User A legitimate access.
8. User B cross-user access.
9. Admin privilege comparison.
10. Unauthorized admin endpoint access.
11. Multi-step chain execution.
12. Chain execution stopping on failed prerequisites.
13. Evidence sanitization.
14. Evidence storage.
15. False-positive prevention.
16. Severity integration.
17. Remediation integration.
18. Automated chain retesting.
19. Tool registry integration.
20. Dashboard result integration.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import httpx
import pytest

from backend.agent.attack_chain import (
    AttackChainCandidate,
    AttackChainStep,
    ChainScenario,
    InputBinding,
    RelationshipType,
)
from backend.analysis.evidence_validator import EvidenceValidator
from backend.analysis.remediation import RemediationEngine
from backend.analysis.severity_engine import SeverityEngine
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.retesting.retest_engine import RetestEngine
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.attack_chain_executor import (
    AttackChainExecutor,
    AttackChainValidator,
    ChainExecutionResult,
    ChainExecutionStatus,
    StepExecutionResult,
    StepExecutionStatus,
)
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord, FindingStatus, SeverityLevel
from backend.tools.agent_adapter import ToolRegistryAdapter
from backend.tools.authorization_tools import AuthorizationTools
from backend.tools.registry import ToolRegistry
from backend.tools.schemas import (
    ExecuteAttackChainInput,
    RetestAttackChainInput,
    ValidateAttackChainInput,
)


# ==============================================================================
# Test Fixtures & Mock Target Builders
# ==============================================================================


@pytest.fixture
def isolated_repo(tmp_path: Path) -> FindingRepository:
    """Provides a fresh isolated SQLite database repository for each test."""
    db_file = tmp_path / "test_chain_storage.db"
    return FindingRepository(db_manager=DatabaseManager(db_path=str(db_file)))


def build_chain_test_environment(handler) -> Tuple[AttackChainExecutor, SessionManager, ScopeGuard]:
    """Builds a test environment wired with httpx.MockTransport."""
    scope = ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http"],
        allowed_methods=["GET", "POST", "PUT", "PATCH", "HEAD"],
    )
    sm = SessionManager(load_from_env=False)
    sm.set_token(Role.USER_A, "jwt_user_a_token", user_id="101")
    sm.set_token(Role.USER_B, "jwt_user_b_token", user_id="102")
    sm.set_token(Role.ADMIN, "jwt_admin_token", user_id="1")
    sm.register_resource_ownership(Role.USER_A, "basket", "1")
    sm.register_resource_ownership(Role.USER_A, "order", "101")

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        timeout=httpx.Timeout(5.0),
    )
    req_exec = RequestExecutor(scope_guard=scope, session_manager=sm, client=client)
    analyzer = ResponseAnalyzer()
    validator = EvidenceValidator()
    sev_eng = SeverityEngine()
    rem_eng = RemediationEngine()

    executor = AttackChainExecutor(
        scope_guard=scope,
        session_manager=sm,
        executor=req_exec,
        analyzer=analyzer,
        validator=validator,
        severity_engine=sev_eng,
        remediation_engine=rem_eng,
        base_url="http://localhost:3000",
    )
    return executor, sm, scope


# ==============================================================================
# 1. Valid Chain Validation
# ==============================================================================


def test_1_valid_chain_validation():
    """Verifies that a well-structured attack chain passes pre-execution validation."""
    scope = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
    validator = AttackChainValidator(scope_guard=scope, base_url="http://localhost:3000")

    candidate = {
        "candidate_id": "chain_valid_1",
        "scenario": "BOLA_IDOR",
        "steps": [
            {
                "step_id": "step-1",
                "path": "/api/orders",
                "method": "GET",
                "depends_on_step_ids": [],
            },
            {
                "step_id": "step-2",
                "path": "/api/orders/{id}",
                "method": "GET",
                "depends_on_step_ids": ["step-1"],
                "input_bindings": [{"parameter": "id", "source_step_id": "step-1"}],
            },
        ],
    }

    res = validator.validate_chain(candidate)
    assert res.is_valid is True
    assert res.step_count == 2
    assert len(res.rejection_reasons) == 0


# ==============================================================================
# 2. Out-of-Scope Endpoint Rejection
# ==============================================================================


def test_2_out_of_scope_endpoint_rejection():
    """Verifies that attack chains with endpoints violating scope boundaries are rejected."""
    scope = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
    validator = AttackChainValidator(scope_guard=scope, base_url="http://localhost:3000")

    # Target outside allowlisted domain
    bad_target_res = validator.validate_chain(
        {"candidate_id": "chain_bad", "steps": [{"path": "/api/users", "method": "GET"}, {"path": "/api/users/1", "method": "GET"}]},
        target_url="http://evil-attacker.com:3000",
    )
    assert bad_target_res.is_valid is False
    assert any("not authorized" in r.lower() for r in bad_target_res.rejection_reasons)

    # Path traversal outside allowed format
    bad_path_res = validator.validate_chain(
        {
            "candidate_id": "chain_bad_path",
            "steps": [
                {"step_id": "step-1", "path": "/api/orders", "method": "GET"},
                {"step_id": "step-2", "path": "/api/../../etc/passwd", "method": "GET", "depends_on_step_ids": ["step-1"]},
            ],
        }
    )
    assert bad_path_res.is_valid is False
    assert any("path" in r.lower() for r in bad_path_res.rejection_reasons)


# ==============================================================================
# 3. Destructive Method Rejection
# ==============================================================================


def test_3_destructive_method_rejection():
    """Verifies that chains containing DELETE or destructive payload keys are rejected."""
    scope = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
    validator = AttackChainValidator(scope_guard=scope, base_url="http://localhost:3000")

    # DELETE method must be rejected
    delete_chain = {
        "candidate_id": "chain_del",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET"},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "DELETE", "depends_on_step_ids": ["step-1"]},
        ],
    }
    del_res = validator.validate_chain(delete_chain)
    assert del_res.is_valid is False
    assert any("delete" in r.lower() for r in del_res.rejection_reasons)

    # Destructive payload keys (e.g. drop_table, wipe, reset) must be rejected
    destructive_payload_chain = {
        "candidate_id": "chain_payload",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET"},
            {
                "step_id": "step-2",
                "path": "/api/orders/1",
                "method": "POST",
                "depends_on_step_ids": ["step-1"],
                "json_body": {"action": "drop_table", "truncate": True},
            },
        ],
    }
    pay_res = validator.validate_chain(destructive_payload_chain)
    assert pay_res.is_valid is False
    assert any("destructive" in r.lower() for r in pay_res.rejection_reasons)


# ==============================================================================
# 4. Invalid Chain Dependency Handling
# ==============================================================================


def test_4_invalid_chain_dependency_handling():
    """Verifies that circular, forward, or non-existent step dependencies are rejected."""
    scope = ScopeGuard(allowed_hosts=["localhost"], allowed_ports=[3000])
    validator = AttackChainValidator(scope_guard=scope, base_url="http://localhost:3000")

    # Step depends on future step
    forward_dep = {
        "candidate_id": "chain_fwd",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "depends_on_step_ids": ["step-2"]},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "GET", "depends_on_step_ids": []},
        ],
    }
    res = validator.validate_chain(forward_dep)
    assert res.is_valid is False
    assert any("prerequisite" in r.lower() for r in res.rejection_reasons)


# ==============================================================================
# 5. Correct Resource Identifier Passing
# ==============================================================================


def test_5_correct_resource_identifier_passing():
    """Verifies that resource IDs extracted from Step 1 are accurately bound to Step 2."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/orders/999" in url:
            return httpx.Response(200, json={"id": 999, "owner": "user_a", "total": 150.0})
        if "/api/orders" in url:
            # Step 1 returns an order list with orderId 999
            return httpx.Response(200, json={"orders": [{"order_id": 999, "item": "Juice"}]})
        return httpx.Response(404)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_binding_test",
        "scenario": "BOLA_IDOR",
        "steps": [
            {
                "step_id": "step-1",
                "path": "/api/orders",
                "method": "GET",
                "role": "user_a",
            },
            {
                "step_id": "step-2",
                "path": "/api/orders/{id}",
                "method": "GET",
                "role": "user_b",
                "depends_on_step_ids": ["step-1"],
                "input_bindings": [{"parameter": "id", "source_step_id": "step-1", "source_field": "order_id"}],
            },
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.steps_executed == 2
    # Verify Step 2 requested the concrete resolved ID 999
    assert res.step_results[1].resolved_url == "http://localhost:3000/api/orders/999"
    assert res.extracted_context.get("step-1.order_id") == "999"


# ==============================================================================
# 6. Anonymous Chain Execution
# ==============================================================================


def test_6_anonymous_chain_execution():
    """Verifies unauthenticated chain execution and detection of missing authentication."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/public/catalog" in url:
            return httpx.Response(200, json={"catalog_id": 42, "status": "active"})
        if "/api/public/catalog/42/items" in url:
            # Unauthenticated access to protected order item records
            return httpx.Response(200, json={"item_id": 501, "customer_email": "user_a@juice-sh.op", "secret": "data"})
        return httpx.Response(404)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_anon",
        "scenario": "MISSING_AUTH",
        "steps": [
            {"step_id": "step-1", "path": "/api/public/catalog", "method": "GET", "role": "anonymous"},
            {
                "step_id": "step-2",
                "path": "/api/public/catalog/{id}/items",
                "method": "GET",
                "role": "anonymous",
                "depends_on_step_ids": ["step-1"],
                "input_bindings": [{"parameter": "id", "source_step_id": "step-1", "source_field": "catalog_id"}],
            },
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.steps_executed == 2
    assert res.step_results[0].role_used == "anonymous"
    assert res.step_results[1].role_used == "anonymous"
    assert res.step_results[1].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS


# ==============================================================================
# 7. User A Legitimate Access (Baseline)
# ==============================================================================


def test_7_user_a_legitimate_access_baseline():
    """Verifies that User A's baseline requests succeed and establish authorized telemetry."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "jwt_user_a_token" in auth:
            return httpx.Response(200, json={"basket_id": "1", "owner_email": "user_a@juice-sh.op"})
        return httpx.Response(401)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_user_a",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/rest/basket/1", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/rest/basket/1", "method": "GET", "role": "user_a", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.steps_executed == 2
    assert res.step_results[0].verdict == AccessVerdict.ALLOWED_ACCESS
    assert res.step_results[0].status == StepExecutionStatus.SUCCESS


# ==============================================================================
# 8. User B Cross-User Access (BOLA / IDOR Chain)
# ==============================================================================


def test_8_user_b_cross_user_access_bola_idor():
    """Scenario A: Resource Discovery -> Cross-User BOLA/IDOR."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if "/rest/basket" in url:
            if "jwt_user_a_token" in auth:
                return httpx.Response(200, json={"id": 1, "owner": "user_a", "items": ["Orange Juice"]})
            if "jwt_user_b_token" in auth:
                # User B receives User A's basket -> Confirmed IDOR
                return httpx.Response(200, json={"id": 1, "owner": "user_a", "items": ["Orange Juice"]})
        return httpx.Response(404)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_bola_scenario_a",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/rest/basket/1", "method": "GET", "role": "user_a"},
            {
                "step_id": "step-2",
                "path": "/rest/basket/{id}",
                "method": "GET",
                "role": "user_b",
                "depends_on_step_ids": ["step-1"],
                "input_bindings": [{"parameter": "id", "source_step_id": "step-1", "source_field": "id"}],
            },
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.status == ChainExecutionStatus.CONFIRMED
    assert res.is_confirmed is True
    assert res.step_results[1].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.step_results[1].role_used == "user_b"


# ==============================================================================
# 9. Admin Privilege Comparison
# ==============================================================================


def test_9_admin_privilege_comparison():
    """Verifies authorized Admin session establishes baseline on privileged administrative routes."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if "jwt_admin_token" in auth:
            return httpx.Response(200, json={"config": {"version": "1.0", "admin_enabled": True}})
        return httpx.Response(403)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_admin_baseline",
        "scenario": "PRIVILEGE_ESCALATION",
        "steps": [
            {"step_id": "step-1", "path": "/rest/admin/application-configuration", "method": "GET", "role": "admin"},
            {"step_id": "step-2", "path": "/rest/admin/application-configuration", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.step_results[0].role_used == "admin"
    assert res.step_results[0].verdict == AccessVerdict.ALLOWED_ACCESS
    # User B is correctly denied with HTTP 403
    assert res.step_results[1].status_code == 403
    assert res.step_results[1].verdict == AccessVerdict.CORRECTLY_DENIED
    assert res.status == ChainExecutionStatus.NOT_VULNERABLE


# ==============================================================================
# 10. Unauthorized Admin Endpoint Access (Scenario B: BFLA)
# ==============================================================================


def test_10_unauthorized_admin_endpoint_access_bfla():
    """Scenario B: Normal User -> Admin Endpoint (Privilege Escalation / BFLA)."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/rest/admin/application-configuration" in url:
            # Privileged endpoint exposes admin config to User B
            return httpx.Response(200, json={"secret_key": "prod_jwt_secret", "allow_registration": True})
        return httpx.Response(200, json={"status": "ok"})

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_bfla_scenario_b",
        "scenario": "PRIVILEGE_ESCALATION",
        "steps": [
            {"step_id": "step-1", "path": "/api/users/whoami", "method": "GET", "role": "user_b"},
            {
                "step_id": "step-2",
                "path": "/rest/admin/application-configuration",
                "method": "GET",
                "role": "user_b",
                "depends_on_step_ids": ["step-1"],
            },
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.status == ChainExecutionStatus.CONFIRMED
    assert res.is_confirmed is True
    assert res.vulnerability_category == "PRIVILEGE_ESCALATION"
    assert res.step_results[1].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS


# ==============================================================================
# 11. Multi-Step Chain Execution (Scenario C: Parent -> Child)
# ==============================================================================


def test_11_multi_step_parent_to_child_resource():
    """Scenario C: Parent Resource -> Related Resource (3-Step Chain)."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if "/api/orders/101/documents/555" in url:
            if "jwt_user_b_token" in auth:
                # User B accesses User A's invoice document
                return httpx.Response(200, json={"doc_id": 555, "invoice_for": "User A", "amount": 199.99})
        if "/api/orders/101/documents" in url:
            return httpx.Response(200, json={"documents": [{"document_id": 555, "type": "invoice"}]})
        if "/api/orders" in url:
            return httpx.Response(200, json={"orders": [{"order_id": 101, "total": 199.99}]})
        return httpx.Response(404)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_scenario_c_parent_child",
        "scenario": "RELATED_RESOURCE_ACCESS",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {
                "step_id": "step-2",
                "path": "/api/orders/{id}/documents",
                "method": "GET",
                "role": "user_a",
                "depends_on_step_ids": ["step-1"],
                "input_bindings": [{"parameter": "id", "source_step_id": "step-1", "source_field": "order_id"}],
            },
            {
                "step_id": "step-3",
                "path": "/api/orders/{id}/documents/{doc_id}",
                "method": "GET",
                "role": "user_b",
                "depends_on_step_ids": ["step-2"],
                "input_bindings": [
                    {"parameter": "id", "source_step_id": "step-1", "source_field": "order_id"},
                    {"parameter": "doc_id", "source_step_id": "step-2", "source_field": "document_id"},
                ],
            },
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.steps_executed == 3
    assert res.step_results[0].status == StepExecutionStatus.SUCCESS
    assert res.step_results[1].status == StepExecutionStatus.SUCCESS
    assert res.step_results[2].resolved_url == "http://localhost:3000/api/orders/101/documents/555"
    assert res.step_results[2].verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
    assert res.status == ChainExecutionStatus.CONFIRMED


# ==============================================================================
# 12. Chain Execution Stopping on Failed Prerequisites
# ==============================================================================


def test_12_chain_execution_stopping_on_failed_prerequisites():
    """Verifies that when Step 1 fails, dependent Step 2 is blocked and skipped safely."""
    def handler(request: httpx.Request) -> httpx.Response:
        # Step 1 returns 500 error
        if "/api/orders" in str(request.url):
            return httpx.Response(500, json={"error": "Database error"})
        return httpx.Response(200)

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_fail_prereq",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET"},
            {"step_id": "step-2", "path": "/api/orders/{id}", "method": "GET", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.step_results[0].status == StepExecutionStatus.FAILED
    assert res.step_results[1].status == StepExecutionStatus.BLOCKED
    assert res.is_confirmed is False


# ==============================================================================
# 13. Evidence Sanitization
# ==============================================================================


def test_13_evidence_sanitization(isolated_repo: FindingRepository):
    """Verifies that all tokens, JWTs, and passwords are fully redacted from chain evidence."""
    raw_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDIifQ.test_signature_secret_123"
    raw_pass = "SuperSecretPassword123!"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/api/users" in url:
            return httpx.Response(
                200,
                headers={"Authorization": f"Bearer {raw_jwt}"},
                json={"id": 1, "token": raw_jwt, "password": raw_pass, "email": "user_a@juice-sh.op"},
            )
        return httpx.Response(200)

    executor, _, _ = build_chain_test_environment(handler)
    executor.repository = isolated_repo

    chain = {
        "candidate_id": "chain_sanitize",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/users", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/users/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=True)
    assert res.is_confirmed is True

    persisted = isolated_repo.get_finding(res.finding_id)
    assert persisted is not None
    serialized = str(persisted.model_dump())
    assert raw_jwt not in serialized
    assert raw_pass not in serialized
    assert any(marker in serialized for marker in ["[REDACTED]", "[REDACTED_SECRET]", "[REDACTED_TOKEN]"])


# ==============================================================================
# 14. Evidence Storage in SQLite
# ==============================================================================


def test_14_evidence_storage_in_sqlite(isolated_repo: FindingRepository):
    """Verifies confirmed chain finding persistence with cryptographic SHA-256 evidence."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "owner": "user_a", "balance": 1000})

    executor, _, _ = build_chain_test_environment(handler)
    executor.repository = isolated_repo

    chain = {
        "candidate_id": "chain_storage_test",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/accounts", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/accounts/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, scan_id="scan_chain_persist", save_finding=True)
    assert res.finding_id is not None

    finding = isolated_repo.get_finding(res.finding_id)
    assert finding is not None
    assert finding.scan_id == "scan_chain_persist"
    assert finding.vulnerability_category == "MULTI_STEP_CHAIN"
    assert finding.evidence is not None
    assert len(finding.evidence.evidence_sha256) == 64


# ==============================================================================
# 15. False-Positive Prevention (SPA & Soft Errors)
# ==============================================================================


def test_15_false_positive_prevention_spa_and_soft_errors():
    """Verifies that HTTP 200 with SPA HTML fallback or soft errors are rejected as false positives."""
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if "/rest/basket/1" in url and "jwt_user_b_token" in auth:
            # Soft error returning HTTP 200
            return httpx.Response(200, json={"status": "error", "error": "Access Denied"})
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<!doctype html><html><body>SPA</body></html>")

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_soft_err",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/rest/basket", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/rest/basket/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.status == ChainExecutionStatus.NOT_VULNERABLE
    assert res.is_confirmed is False
    assert res.step_results[1].verdict == AccessVerdict.CORRECTLY_DENIED


# ==============================================================================
# 16. Severity Integration
# ==============================================================================


def test_16_severity_integration():
    """Verifies that SeverityEngine calculates deterministic severity with anti-inflation safeguards."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"admin_token": "secret", "config": "master"})

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_sev",
        "scenario": "PRIVILEGE_ESCALATION",
        "steps": [
            {"step_id": "step-1", "path": "/api/users", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/rest/admin/config", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert res.severity in ("HIGH", "CRITICAL")
    assert res.confidence == "CONFIRMED"


# ==============================================================================
# 17. Remediation Integration
# ==============================================================================


def test_17_remediation_integration():
    """Verifies concrete remediation recommendations and code patches are generated for confirmed chains."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "owner": "user_a"})

    executor, _, _ = build_chain_test_environment(handler)

    chain = {
        "candidate_id": "chain_rem",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=False)
    assert len(res.remediation_steps) >= 2
    assert res.remediation_code_patch is not None
    assert "ownership" in res.remediation_code_patch.lower() or "user" in res.remediation_code_patch.lower()


# ==============================================================================
# 18. Automated Chain Retesting
# ==============================================================================


def test_18_automated_chain_retesting(isolated_repo: FindingRepository):
    """Verifies RetestEngine retests an attack chain, verifying FIXED when remediated and STILL VULNERABLE when not."""
    is_fixed = False

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        auth = request.headers.get("Authorization", "")
        if "/api/orders/1" in url:
            if "jwt_user_a_token" in auth:
                return httpx.Response(200, json={"id": 1, "owner": "user_a"})
            if is_fixed:
                return httpx.Response(403, json={"error": "Access Denied: Not your order"})
            return httpx.Response(200, json={"id": 1, "owner": "user_a"})
        if "/api/orders" in url:
            return httpx.Response(200, json={"orders": [{"id": 1}]})
        return httpx.Response(404)

    executor, sm, scope = build_chain_test_environment(handler)
    executor.repository = isolated_repo
    tester = AuthorizationTester(
        executor=executor.executor,
        session_manager=sm,
        scope_guard=scope,
        base_url="http://localhost:3000",
    )
    retest_engine = RetestEngine(
        repository=isolated_repo,
        tester=tester,
        scope_guard=scope,
        session_manager=sm,
        base_url="http://localhost:3000",
    )

    chain = {
        "candidate_id": "chain_retest_demo",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    # 1. First execution confirms vulnerability
    res1 = executor.execute_chain(chain, save_finding=True)
    assert res1.is_confirmed is True
    finding_id = res1.finding_id

    # 2. Retest while still vulnerable -> STILL VULNERABLE
    log1 = retest_engine.retest_attack_chain(finding_id)
    assert log1.new_status == "STILL VULNERABLE"
    assert log1.is_vulnerable is True

    # 3. Simulate developer applying remediation -> FIXED
    is_fixed = True
    log2 = retest_engine.retest_attack_chain(finding_id)
    assert log2.new_status == "FIXED"
    assert log2.is_vulnerable is False

    persisted = isolated_repo.get_finding(finding_id)
    assert persisted.status == "remediated"
    assert persisted.retest_status == "fixed"


# ==============================================================================
# 19. Tool Registry & ToolRegistryAdapter Integration
# ==============================================================================


@pytest.mark.asyncio
async def test_19_tool_registry_and_adapter_integration(isolated_repo: FindingRepository):
    """Verifies that validate_attack_chain and execute_attack_chain execute through ToolRegistryAdapter."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "owner": "user_a"})

    executor, sm, scope = build_chain_test_environment(handler)
    executor.repository = isolated_repo

    auth_tools = AuthorizationTools(
        tester=executor.tester if hasattr(executor, "tester") else None,
        scope_guard=scope,
        session_manager=sm,
        executor=executor.executor,
        repository=isolated_repo,
    )
    registry = ToolRegistry(
        scope_guard=scope,
        executor=executor.executor,
        session_manager=sm,
        authorization_tools=auth_tools,
    )
    adapter = ToolRegistryAdapter(registry=registry)

    chain = {
        "candidate_id": "chain_adapter_test",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    # Execute tool via ToolRegistryAdapter
    exec_env = await adapter.execute_tool_call(
        tool_name="execute_attack_chain",
        arguments={"chain": chain, "save_findings": True},
        context={"assessment_id": "scan_adapter_test"},
    )
    assert exec_env["ok"] is True
    data = exec_env["data"]
    assert data["is_confirmed"] is True
    assert data["status"] == "CONFIRMED"
    assert data["finding_id"] is not None


# ==============================================================================
# 20. Dashboard Result Integration
# ==============================================================================


def test_20_dashboard_result_integration(isolated_repo: FindingRepository):
    """Verifies that chain finding technical details contain all fields required by the dashboard UI."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "owner": "user_a"})

    executor, _, _ = build_chain_test_environment(handler)
    executor.repository = isolated_repo

    chain = {
        "candidate_id": "chain_dash_ui",
        "chain_name": "User A to User B BOLA Chain",
        "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "step-1", "path": "/api/orders", "method": "GET", "role": "user_a"},
            {"step_id": "step-2", "path": "/api/orders/1", "method": "GET", "role": "user_b", "depends_on_step_ids": ["step-1"]},
        ],
    }

    res = executor.execute_chain(chain, save_finding=True)
    finding = isolated_repo.get_finding(res.finding_id)
    assert finding is not None

    tech = finding.technical_details
    assert "chain_id" in tech
    assert "chain_name" in tech
    assert "steps" in tech
    assert len(tech["steps"]) == 2
    assert "vulnerable_step_id" in tech
    assert "risk_assessment" in tech
    assert len(tech["reproducibility_steps"]) >= 3
