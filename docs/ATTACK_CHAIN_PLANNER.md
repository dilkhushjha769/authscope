# Attack Chain Planner Contract

`backend.agent.attack_chain.AttackChainPlanner` creates **unverified planning candidates** from discovered endpoint metadata. It performs no network requests, does not read or create sessions, does not persist evidence, and cannot authorize execution. An HTTP status code, including 200, is not evidence of a vulnerability.

## Python interface

```python
from backend.agent.attack_chain import AttackChainPlanner

planner = AttackChainPlanner()
graph = planner.build_graph(discovered_endpoints)
plan = planner.plan(discovered_endpoints, max_steps=5, max_candidates=25)
# Compatibility API: serialized candidate dictionaries, without graph metadata.
candidate_dicts = planner.plan_chain(discovered_endpoints, max_steps=5)
```

Inputs may be `DiscoveredEndpoint`, persisted `DiscoveredEndpointRecord`, metadata mappings, or legacy relative path strings. Optional `dependencies` / `depends_on` / `endpoint_dependencies` metadata names prerequisite endpoint paths; missing dependencies are returned in `graph.unresolved_dependencies`. The current persisted endpoint model has no dependency field, so dependencies are only available when a discovery provider supplies them. Resource and identifier relationships are conservatively inferred from discovered resource types and parameter names. Unsafe paths and methods outside GET, HEAD, POST, PUT, PATCH are rejected; non-read methods carry `requires_human_approval=true`.

## Stable executor contract (schema version 1.0)

`AttackChainPlan` contains graph diagnostics and ranked `AttackChainCandidate` objects. Each candidate contains:

- `candidate_id`, `scenario` (`BOLA_IDOR`, `PRIVILEGE_ESCALATION`, `RELATED_RESOURCE_ACCESS`, or `MIXED_AUTHORIZATION`), deterministic heuristic `risk_score` (0–100), `priority`, and rationale.
- `steps` in execution order (2–5). Every step has stable `step_id`, `endpoint_id` (method + normalized route identity), relative `path`, `method`, endpoint metadata, prior-step references, and symbolic `input_bindings`.
- `execution_authorized=false`, `requires_scope_validation=true`, and `status="CANDIDATE_UNVERIFIED"` are fixed planner values. Risk and scenario are planning hints, not confirmation or permission.

Bindings name a parameter and source step/field (`response.resource_id`). They intentionally do not contain discovered concrete resource IDs. The executor must resolve values only from validated outputs of the referenced step; it must not guess identifiers. `path` is relative and must be revalidated against the active target by `ScopeGuard` before each request.

## Member 2 integration

1. Obtain endpoints from the existing `FindingRepository.list_discovered_endpoints(scan_id)` or the in-memory `EndpointDiscovery` result. Do not accept AI-generated paths as discovery.
2. Call `AttackChainPlanner.plan(endpoints, max_steps=5)` and serialize via `plan.model_dump(mode="json")` across the boundary. Persist/share `schema_version` with the executor adapter.
3. Present candidates for the existing authorization and human-approval policy. Ignore `risk_score` as execution authorization; require the active assessment and `ScopeGuard` checks.
4. For every step, validate the relative path and method with `ScopeGuard`, and dispatch only through the existing approved registry and `RequestExecutor`. Keep redirects disabled. Follow only `input_bindings` whose source output was safely validated.
5. Route captured results through the existing authorization comparison and evidence validation/storage pipeline. Only verified differential evidence may create or confirm a finding.
6. Treat unresolved dependencies and rejected endpoints as diagnostics; do not fill gaps with invented routes.

There is no AI-assisted chain generation in this planner. This preserves deterministic endpoint provenance; an AI can later rank only supplied `candidate_id` values, but cannot add steps, change risk/authorization flags, or execute a chain.

## Relationship and risk limits

Graph relationships include declared dependencies, resource identifier flow, related-resource references, and same-resource admin role boundaries. A graph can contain cycles, while candidate plans are simple paths and never repeat an endpoint. Scores are transparent deterministic prioritization heuristics; they do not represent measured exploitability, likelihood, CVSS, or a confirmed vulnerability. Existing discovery metadata may be too sparse to infer a complete business workflow.
