"""Integration boundary checks using a small Member 2 executor-contract stub.

The current Member 2 executor is being developed as a parallel/untracked change,
so this stub asserts the stable request shape without coupling tests to its file.
"""
from typing import Any, Dict, List

from backend.agent.attack_chain import AttackChainPlanner


class ExecutorContractStub:
    """Minimal deterministic consumer for planner output; it does no requests."""

    def validate(self, candidate: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        if candidate.get("chain_id") != candidate.get("candidate_id"):
            errors.append("chain identifier compatibility fields disagree")
        if candidate.get("scenario") != candidate.get("vulnerability_category"):
            errors.append("category compatibility fields disagree")
        steps = candidate.get("steps")
        if not isinstance(steps, list) or not 2 <= len(steps) <= 5:
            return errors + ["chain must contain 2 to 5 ordered steps"]
        seen: set[str] = set()
        for step in steps:
            if step.get("endpoint") != step.get("path") or step.get("http_method") != step.get("method"):
                errors.append("executor and contract endpoint fields disagree")
            if not str(step.get("path", "")).startswith("/") or step.get("method") not in {"GET", "HEAD", "POST", "PUT", "PATCH"}:
                errors.append("invalid path or method")
            for dependency in step.get("depends_on_step_ids", []):
                if dependency not in seen:
                    errors.append("step dependency must reference a prior step")
            for binding in step.get("input_bindings", []):
                if binding.get("source_step_id") not in seen:
                    errors.append("resource binding must reference a prior step")
            seen.add(step.get("step_id", ""))
        return errors


def test_consumer_stub_accepts_generated_valid_chain():
    endpoints = [
        {"path": "/api/users", "method": "GET", "resource_type": "user", "category": "USER_COLLECTION",
         "output_parameters": ["id"]},
        {"path": "/api/users/{id}", "method": "GET", "resource_type": "user", "category": "USER_OBJECT",
         "input_parameters": ["id"], "parameters": ["id"], "requires_owner_match": True},
    ]
    candidate = AttackChainPlanner().plan(endpoints).candidates[0].model_dump(mode="json")
    assert ExecutorContractStub().validate(candidate) == []


def test_consumer_stub_rejects_incomplete_and_invalid_chains():
    stub = ExecutorContractStub()
    assert "chain must contain 2 to 5 ordered steps" in stub.validate({"steps": [{"step_id": "only"}]})
    invalid = {
        "chain_id": "same", "candidate_id": "same", "scenario": "BOLA_IDOR",
        "vulnerability_category": "BOLA_IDOR", "steps": [
            {"step_id": "one", "path": "https://outside.invalid", "endpoint": "https://outside.invalid", "method": "DELETE", "http_method": "DELETE"},
            {"step_id": "two", "path": "/api/x", "endpoint": "/api/x", "method": "GET", "http_method": "GET",
             "depends_on_step_ids": ["not-prior"]},
        ],
    }
    errors = stub.validate(invalid)
    assert "invalid path or method" in errors
    assert "step dependency must reference a prior step" in errors


def test_missing_resource_dependency_is_a_diagnostic_not_a_candidate():
    plan = AttackChainPlanner().plan([
        {"path": "/api/parent", "method": "GET", "resource_type": "parent"},
        {"path": "/api/child/{parent_id}", "method": "GET", "resource_type": "child",
         "input_parameters": ["parent_id"], "parent_resource_type": "parent"},
    ])
    assert plan.candidates == []
    assert any(edge.uncertain for edge in plan.graph.relationships) or not plan.graph.relationships
