import pytest

from backend.agent.attack_chain import (
    AttackChainCandidate,
    AttackChainPlanner,
    ChainScenario,
    RelationshipConfidence,
    RelationshipType,
)


@pytest.fixture
def endpoints():
    return [
        {
            "path": "/api/users", "method": "GET", "resource_type": "user",
            "category": "USER_COLLECTION", "output_parameters": ["id"],
            "resource_sensitivity": "HIGH", "requires_auth": True,
            "expected_allowed_roles": ["user_a", "user_b", "admin"],
        },
        {
            "path": "/api/users/{id}", "method": "GET", "resource_type": "user",
            "category": "USER_OBJECT", "input_parameters": ["id"], "output_parameters": ["id"],
            "parameters": ["id"], "requires_auth": True, "requires_owner_match": True,
            "expected_allowed_roles": ["user_a", "user_b", "admin"],
        },
        {
            "path": "/api/users/{user_id}/orders", "method": "GET", "resource_type": "order",
            "parent_resource_type": "user", "input_parameters": ["user_id"],
            "output_parameters": ["order_id"], "parameters": ["user_id"],
            "category": "USER_COLLECTION", "requires_auth": True,
        },
        {
            "path": "/api/admin/users/{id}", "method": "GET", "resource_type": "user",
            "input_parameters": ["id"], "parameters": ["id"], "category": "ADMIN_FUNCTION",
            "requires_auth": True, "expected_allowed_roles": ["admin"],
            "permissions": ["users:admin:read"], "resource_sensitivity": "CRITICAL",
        },
        {
            "path": "/api/admin/audit", "method": "GET", "resource_type": "audit_event",
            "category": "ADMIN_FUNCTION", "requires_auth": True,
            "expected_allowed_roles": ["admin"],
        },
    ]


def test_graph_identifies_only_metadata_supported_identifier_relationships(endpoints):
    graph = AttackChainPlanner().build_graph(endpoints)
    assert any(edge.relationship == RelationshipType.RESOURCE_IDENTIFIER_FLOW and not edge.uncertain
               for edge in graph.relationships)
    assert any(edge.relationship == RelationshipType.RELATED_RESOURCE and not edge.uncertain
               for edge in graph.relationships)
    assert any(edge.relationship == RelationshipType.PRIVILEGE_BOUNDARY for edge in graph.relationships)
    user_collection = next(node for node in graph.nodes if node.path == "/api/users")
    assert user_collection.output_parameters == ["id"]
    assert user_collection.expected_allowed_roles == ["user_a", "user_b", "admin"]
    assert "users:admin:read" in next(node for node in graph.nodes if "/admin/users" in node.path).permissions


def test_missing_source_output_metadata_is_uncertain_and_not_planned():
    planner = AttackChainPlanner()
    graph = planner.build_graph([
        {"path": "/api/users", "method": "GET", "resource_type": "user", "category": "USER_COLLECTION"},
        {"path": "/api/users/{id}", "method": "GET", "resource_type": "user", "parameters": ["id"]},
    ])
    possible = next(edge for edge in graph.relationships if edge.uncertain)
    assert possible.confidence == RelationshipConfidence.LOW
    assert "uncertain" in possible.rationale
    assert planner.plan(graph.nodes).candidates == []


def test_explicit_dependencies_and_missing_dependencies_are_reported():
    planner = AttackChainPlanner()
    routes = [
        {"path": "/api/session", "method": "GET"},
        {"path": "/api/profile/{id}", "method": "GET", "depends_on": ["/api/session"]},
        {"path": "/api/admin/report", "method": "GET", "dependencies": ["/api/missing"]},
    ]
    graph = planner.build_graph(routes)
    assert any(edge.relationship == RelationshipType.EXPLICIT_DEPENDENCY for edge in graph.relationships)
    assert graph.unresolved_dependencies[0].dependency == "/api/missing"


def test_generates_two_to_five_step_paths_and_ranks_using_risk_metadata(endpoints):
    plan = AttackChainPlanner().plan(endpoints, max_steps=5)
    assert len(plan.candidates) >= 3
    assert all(2 <= len(candidate.steps) <= 5 for candidate in plan.candidates)
    assert any(candidate.scenario in (ChainScenario.PRIVILEGE_ESCALATION, ChainScenario.MIXED_AUTHORIZATION)
               for candidate in plan.candidates)
    assert plan.candidates == sorted(plan.candidates, key=lambda candidate: (-candidate.risk_score, -len(candidate.steps), candidate.candidate_id))
    assert plan.candidates[0].risk_metadata.resource_sensitivity in {"HIGH", "CRITICAL"}
    assert {candidate.scenario for candidate in plan.candidates} >= {
        ChainScenario.MIXED_AUTHORIZATION, ChainScenario.BOLA_IDOR, ChainScenario.RELATED_RESOURCE_ACCESS,
    }


def test_rejects_unsafe_paths_and_unsupported_http_methods():
    graph = AttackChainPlanner().build_graph([
        "https://example.com/api/users", "/api/../secret",
        {"path": "/api/users", "method": "DELETE"},
        {"path": "/api/users", "method": "TRACE"},
        {"path": "/api/users/{id}", "method": "GET"},
    ])
    assert len(graph.nodes) == 1
    assert len(graph.rejected_endpoints) == 4


def test_cycles_do_not_repeat_nodes_and_duplicate_endpoints_are_removed():
    routes = [
        {"path": "/api/a", "method": "GET", "dependencies": ["/api/b"]},
        {"path": "/api/b", "method": "GET", "dependencies": ["/api/a"]},
        {"path": "/api/a", "method": "GET"},
    ]
    plan = AttackChainPlanner().plan(routes)
    assert len(plan.graph.nodes) == 2
    assert plan.candidates
    assert all(len({step.endpoint_id for step in candidate.steps}) == len(candidate.steps) for candidate in plan.candidates)


def test_chain_contract_contains_executor_fields_and_schema_aliases(endpoints):
    candidate = AttackChainPlanner().plan(endpoints).candidates[0]
    data = candidate.model_dump(mode="json")
    assert data["schema_version"] == "1.1"
    assert data["chain_id"] == data["candidate_id"]
    assert data["vulnerability_category"] == data["scenario"]
    assert data["risk_metadata"]["score"] == data["risk_score"]
    assert data["ordered_steps"] == data["steps"]
    assert {"endpoint", "http_method", "parameters", "resource_dependencies", "expected_role", "purpose", "depends_on_step_ids"} <= data["steps"][0].keys()
    assert candidate.execution_authorized is False
    assert candidate.requires_scope_validation is True
    with pytest.raises(Exception):
        AttackChainCandidate.model_validate({"steps": [{"step_id": "one"}]})


def test_ai_suggestions_can_only_reorder_existing_candidates(endpoints):
    planner = AttackChainPlanner()
    plan = planner.plan(endpoints)
    assert len(plan.candidates) > 1
    chosen = plan.candidates[-1].candidate_id
    ranked = planner.apply_ai_suggestions(plan, [
        {"candidate_id": chosen, "steps": [{"path": "https://attacker.invalid"}], "risk_score": 100},
        "invented-chain-id",
        chosen,
    ])
    assert ranked.candidates[0].candidate_id == chosen
    assert len(ranked.candidates) == len(plan.candidates)
    assert ranked.candidates[0].risk_score == plan.candidates[-1].risk_score
    assert ranked.candidates[0].steps == plan.candidates[-1].steps
    assert ranked.ai_suggestions_used is True


def test_ai_agent_can_request_chain_planner_only_through_approved_registry():
    from backend.ai_agent.planner import DEFAULT_APPROVED_TOOLS
    from backend.tools.registry import ToolRegistry

    assert "plan_attack_chains" in DEFAULT_APPROVED_TOOLS
    tool = ToolRegistry().get_tool("plan_attack_chains")
    assert tool is not None
    assert tool.requires_scope_check is False  # planning consumes in-scope persisted metadata; execution rechecks scope


def test_plan_enforces_max_steps_contract():
    with pytest.raises(ValueError):
        AttackChainPlanner().plan([], max_steps=6)
