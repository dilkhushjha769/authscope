"""Real loopback integration checks for safe chain execution.

The target is an ephemeral local HTTP server. No external network is contacted.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from pathlib import Path
from typing import Iterator

import pytest

from backend.analysis.evidence_validator import EvidenceValidator
from backend.agent.attack_chain import AttackChainPlanner
from backend.analysis.remediation import RemediationEngine
from backend.analysis.severity_engine import SeverityEngine
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.attack_chain_executor import AttackChainExecutor, ChainExecutionStatus, StepExecutionStatus
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.scanner.authorization_tester import AuthorizationTester
from backend.retesting.retest_engine import RetestEngine
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository


@pytest.fixture
def local_target() -> Iterator[tuple[str, list[tuple[str, str]], dict[str, bool]]]:
    calls: list[tuple[str, str]] = []
    vulnerable = {"value": True}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            role_token = self.headers.get("Authorization", "")
            calls.append((self.path, role_token))
            if self.path == "/api/public/probe":
                payload, status = {"status": "anonymous baseline"}, 200
            elif self.path == "/api/items":
                payload, status = {"items": [{"item_id": "17"}]}, 200
            elif self.path == "/api/items/17":
                if role_token == "Bearer user-b" and not vulnerable["value"]:
                    payload, status = {"error": "forbidden"}, 403
                else:
                    payload, status = {"item_id": "17", "owner_id": "user-a", "name": "owned item"}, 200
            else:
                payload, status = {"error": "not found"}, 404
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls, vulnerable
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _executor(base_url: str) -> AttackChainExecutor:
    port = int(base_url.rsplit(":", 1)[1])
    scope = ScopeGuard(
        allowed_hosts=["127.0.0.1"], allowed_ports=[port], allowed_schemes=["http"],
        allowed_methods=["GET", "HEAD"],
    )
    sessions = SessionManager(load_from_env=False)
    sessions.set_token(Role.USER_A, "user-a", user_id="user-a")
    sessions.set_token(Role.USER_B, "user-b", user_id="user-b")
    sessions.set_token(Role.ADMIN, "admin", user_id="admin")
    sessions.register_resource_ownership(Role.USER_A, "item", "17")
    request_executor = RequestExecutor(scope_guard=scope, session_manager=sessions)
    return AttackChainExecutor(
        scope_guard=scope, session_manager=sessions, executor=request_executor,
        analyzer=ResponseAnalyzer(), validator=EvidenceValidator(), severity_engine=SeverityEngine(),
        remediation_engine=RemediationEngine(), base_url=base_url,
    )


def _chain() -> dict[str, object]:
    return {
        "candidate_id": "local-bola-chain", "scenario": "BOLA_IDOR",
        "steps": [
            {"step_id": "anonymous-baseline", "path": "/api/public/probe", "method": "GET", "role": "anonymous"},
            {
                "step_id": "discover", "path": "/api/items", "method": "GET", "role": "user_a",
                "resource_type": "item", "output_parameters": ["item_id"],
                "resource_identifier_name": "item_id",
            },
            {
                "step_id": "cross-user-read", "path": "/api/items/{item_id}", "method": "GET",
                "role": "user_b", "resource_type": "item", "depends_on_step_ids": ["discover"],
                "input_parameters": ["item_id"],
                "input_bindings": [{"parameter": "item_id", "source_step_id": "discover", "source_field": "item_id"}],
            },
            {
                "step_id": "admin-baseline", "path": "/api/items/17", "method": "GET", "role": "admin",
                "resource_type": "item", "depends_on_step_ids": ["cross-user-read"],
            },
        ],
    }


def test_local_vulnerable_target_uses_provenance_and_independent_roles(
    local_target: tuple[str, list[tuple[str, str]], dict[str, bool]], tmp_path: Path
) -> None:
    base_url, calls, _ = local_target
    executor = _executor(base_url)
    discovered = [
        {
            "path": "/api/items", "method": "GET", "category": "USER_COLLECTION",
            "resource_type": "item", "output_parameters": ["item_id"],
            "resource_identifier_name": "item_id", "requires_auth": True,
        },
        {
            "path": "/api/items/{item_id}", "method": "GET", "category": "USER_OBJECT",
            "resource_type": "item", "input_parameters": ["item_id"], "parameters": ["item_id"],
            "requires_owner_match": True, "requires_auth": True,
        },
    ]
    plan = AttackChainPlanner().plan(discovered, max_steps=2)
    assert len(plan.graph.relationships) == 1
    assert plan.candidates
    candidate_result = executor.execute_chain(plan.candidates[0].model_dump(mode="json"), save_finding=False)
    assert candidate_result.status == ChainExecutionStatus.CONFIRMED, [(r.path, r.error_message, r.expected_behavior) for r in candidate_result.step_results]
    calls.clear()

    repository = FindingRepository(DatabaseManager(db_path=str(tmp_path / "loopback-e2e.sqlite")))
    executor.repository = repository
    result = executor.execute_chain(_chain(), scan_id="loopback-e2e", save_finding=True)

    assert result.status == ChainExecutionStatus.CONFIRMED
    assert [path for path, _ in calls] == ["/api/public/probe", "/api/items", "/api/items/17", "/api/items/17"]
    assert [auth for _, auth in calls] == ["", "Bearer user-a", "Bearer user-b", "Bearer admin"]
    assert result.step_results[2].resource_identifier_provenance["item_id"]["source_step_id"] == "discover"
    assert result.step_results[2].resolved_url == f"{base_url}/api/items/17"
    finding = repository.get_finding(result.finding_id or "")
    assert finding is not None and finding.evidence is not None
    assert len(finding.evidence.evidence_sha256) == 64

    # Flip the same local app to the fixed behavior and verify the stored chain.
    _, _, vulnerable = local_target
    vulnerable["value"] = False
    tester = AuthorizationTester(
        executor=executor.executor,
        session_manager=executor.session_manager,
        scope_guard=executor.scope_guard,
        base_url=base_url,
    )
    retester = RetestEngine(
        repository=repository, tester=tester, scope_guard=executor.scope_guard,
        session_manager=executor.session_manager, base_url=base_url,
    )
    retest = retester.retest_attack_chain(finding.id)
    assert retest.new_status == "FIXED"


def test_local_missing_identifier_blocks_dependent_step(local_target: tuple[str, list[tuple[str, str]], dict[str, bool]]) -> None:
    base_url, calls, _ = local_target
    chain = _chain()
    chain["steps"][1]["output_parameters"] = []  # type: ignore[index]
    chain["steps"][1]["resource_identifier_name"] = None  # type: ignore[index]
    result = _executor(base_url).execute_chain(chain, save_finding=False)

    assert result.status == ChainExecutionStatus.EXECUTION_FAILED
    assert len(calls) == 2
    assert result.step_results[2].status == StepExecutionStatus.BLOCKED
    assert "could not be resolved" in (result.step_results[2].error_message or "")


def test_local_fixed_target_is_not_reported_as_vulnerable(local_target: tuple[str, list[tuple[str, str]], dict[str, bool]]) -> None:
    base_url, calls, vulnerable = local_target
    vulnerable["value"] = False
    executor = _executor(base_url)
    result = executor.execute_chain(_chain(), save_finding=False)
    assert result.status == ChainExecutionStatus.NOT_VULNERABLE
    assert len(calls) == 3

