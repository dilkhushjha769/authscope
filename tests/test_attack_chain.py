from backend.agent.attack_chain import (
    AttackChainPlanner,
    ChainScenario,
    RelationshipType,
)
from backend.scanner.endpoint_discovery import DiscoveredEndpoint, EndpointCategory


def test_graph_infers_object_identifier_relationship_and_symbolic_binding():
    planner = AttackChainPlanner()
    routes = [
        DiscoveredEndpoint(path="/api/users", method="GET", resource_type="user",
                           category=EndpointCategory.USER_COLLECTION),
        DiscoveredEndpoint(path="/api/users/{id}", method="GET", resource_type="user",
                           parameters=["id"], category=EndpointCategory.USER_OBJECT,
                           requires_owner_match=True),
    ]
    graph = planner.build_graph(routes)
    assert any(edge.relationship == RelationshipType.RESOURCE_IDENTIFIER_FLOW for edge in graph.relationships)
    candidate = planner.plan(routes).candidates[0]
    assert candidate.scenario == ChainScenario.BOLA_IDOR
    assert candidate.steps[1].input_bindings[0].source_field == "response.resource_id"
    assert candidate.execution_authorized is False
    assert "extracted_resource_id" not in candidate.model_dump_json()


def test_explicit_dependency_and_unresolved_dependency_are_reported():
    planner = AttackChainPlanner()
    routes = [
        {"path": "/api/session", "method": "GET"},
        {"path": "/api/profile/{id}", "method": "GET", "depends_on": ["/api/session"]},
        {"path": "/api/admin/report", "method": "GET", "dependencies": ["/api/missing"]},
    ]
    graph = planner.build_graph(routes)
    assert any(edge.relationship == RelationshipType.EXPLICIT_DEPENDENCY for edge in graph.relationships)
    assert graph.unresolved_dependencies[0].dependency == "/api/missing"


def test_generates_bounded_two_to_five_step_paths_and_ranks_admin_boundary():
    planner = AttackChainPlanner()
    routes = [
        {"path": "/api/users", "method": "GET", "resource_type": "user", "category": "USER_COLLECTION"},
        {"path": "/api/users/{id}", "method": "GET", "resource_type": "user", "parameters": ["id"], "category": "USER_OBJECT", "requires_owner_match": True},
        {"path": "/api/users/{user_id}/orders", "method": "GET", "resource_type": "order", "parameters": ["user_id"], "category": "USER_COLLECTION"},
        {"path": "/api/admin/users", "method": "GET", "resource_type": "user", "category": "ADMIN_FUNCTION", "expected_allowed_roles": ["admin"]},
        {"path": "/api/admin/audit", "method": "GET", "category": "ADMIN_FUNCTION"},
    ]
    plan = planner.plan(routes, max_steps=5)
    assert plan.candidates
    assert all(2 <= len(candidate.steps) <= 5 for candidate in plan.candidates)
    assert any(candidate.scenario in (ChainScenario.PRIVILEGE_ESCALATION, ChainScenario.MIXED_AUTHORIZATION)
               for candidate in plan.candidates)
    assert plan.candidates == sorted(plan.candidates, key=lambda candidate: (-candidate.risk_score, -len(candidate.steps), candidate.candidate_id))


def test_invalid_and_destructive_endpoints_are_rejected():
    graph = AttackChainPlanner().build_graph([
        "https://example.com/api/users",
        "/api/../secret",
        {"path": "/api/users", "method": "DELETE"},
        {"path": "/api/users/{id}", "method": "GET"},
    ])
    assert len(graph.nodes) == 1
    assert len(graph.rejected_endpoints) == 3


def test_cycles_do_not_repeat_nodes_in_candidate_paths():
    routes = [
        {"path": "/api/a", "method": "GET", "dependencies": ["/api/b"]},
        {"path": "/api/b", "method": "GET", "dependencies": ["/api/a"]},
    ]
    candidates = AttackChainPlanner().plan(routes).candidates
    assert candidates
    assert all(len({step.endpoint_id for step in candidate.steps}) == len(candidate.steps) for candidate in candidates)


def test_plan_enforces_max_steps_contract():
    import pytest

    with pytest.raises(ValueError):
        AttackChainPlanner().plan([], max_steps=6)
