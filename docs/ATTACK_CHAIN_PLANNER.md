# Attack Chain Planner Contract

`backend.agent.attack_chain.AttackChainPlanner` plans unverified authorization tests from discovered endpoint metadata. It performs no network requests, does not manage sessions, does not store evidence, and cannot authorize execution. A response status, including HTTP 200, does not confirm a vulnerability.

## Interface

```python
from backend.agent.attack_chain import AttackChainPlanner

planner = AttackChainPlanner()
graph = planner.build_graph(discovered_endpoints)
plan = planner.plan(discovered_endpoints, max_steps=5, max_candidates=25)
# Backward-compatible JSON-compatible candidate list:
candidate_dicts = planner.plan_chain(discovered_endpoints, max_steps=5)
```

The allowlisted AI tool `plan_attack_chains` invokes the same planner over endpoints persisted for the active assessment. It does not accept endpoint paths from model arguments. `plan_attack_chains` is an approved tool name for the existing agent planner; it relies on the existing tool registry and execution context.

Inputs may be `DiscoveredEndpoint`, `DiscoveredEndpointRecord`, or endpoint mappings. Legacy path strings remain accepted, but without richer metadata they cannot establish resource identifier flows. Optional metadata includes `input_parameters`, `output_parameters`, `resource_identifier_name`, `parent_resource_type`, `related_resource_types`, `requires_auth`, `expected_allowed_roles`, `permissions` / `required_permissions`, `resource_sensitivity`, and explicit `dependencies` / `depends_on` / `endpoint_dependencies`.

Discovered endpoint records persist planner metadata separately from the stable endpoint columns; older SQLite databases receive a `planner_metadata_json` migration. OpenAPI path/query inputs come from declared parameters, and response identifier fields come only from explicit JSON response schemas (direct or nested properties). `$ref` schemas are not expanded.

Missing input parameter metadata falls back to discovered `parameters`; missing output metadata remains unknown. Missing role and permission metadata is represented by empty lists and a null `expected_role`. Missing sensitivity remains null and adds no risk weight. Concrete extracted resource IDs are never copied to candidate output. Parent/related resources without a known source identifier are represented as low-confidence `uncertain` graph relationships and are excluded from executable candidate paths. Explicit dependencies that do not resolve appear in `graph.unresolved_dependencies`. Rejected paths and unsupported methods appear in `graph.rejected_endpoints`.

## Schema version 1.1

Required candidate fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Contract version (`1.1`). |
| `chain_id`, `candidate_id` | string | Stable identity; equal values. `candidate_id` is the current executor compatibility key. |
| `chain_name` | string | Human-readable candidate label. |
| `vulnerability_category`, `scenario` | enum string | Equal planning category: BOLA_IDOR, PRIVILEGE_ESCALATION, RELATED_RESOURCE_ACCESS, or MIXED_AUTHORIZATION. |
| `risk_metadata` | object | `score` (0–100), `priority`, optional `resource_sensitivity`, and rationale list. |
| `ordered_steps`, `steps` | array of 2–5 step objects | Equal ordered lists. `steps` is required by the current Member 2 validator/executor. |
| `execution_authorized` | boolean | Always false in planner output. |
| `requires_scope_validation` | boolean | Always true. |
| `status` | string | Always `CANDIDATE_UNVERIFIED`. |

Each step includes required `step_id`, `endpoint_id`, `endpoint` and compatibility `path` (same relative path), `method` and compatibility `http_method` (same uppercase method), `parameters`, `input_parameters`, `output_parameters`, `resource_dependencies`, `purpose`, `requires_auth`, `requires_owner_match`, `depends_on_step_ids`, and `input_bindings`. Optional metadata includes `resource_type`, `expected_role` (null when role expectations are absent or ambiguous), `expected_allowed_roles`, `permissions`, and `requires_human_approval`. Bindings identify `parameter`, `source_step_id`, and `source_field`; concrete IDs are resolved only from validated execution outputs.

Validation errors are raised for `max_steps` outside 2–5, `max_candidates` below 1, or invalid Pydantic candidate contracts. Invalid endpoint inputs are diagnostics rather than fatal planning errors. The planner never inserts missing endpoints or dependencies. Every candidate edge must be a confident explicit dependency or a metadata-supported resource identifier relationship. Graph cycles are allowed, but plans are simple paths and never repeat endpoints.

## Representative candidate sequences

These are controlled metadata examples; they are proposed tests, not vulnerability reports.

1. **Cross-user object access (BOLA/IDOR):** `GET /api/users` (output `id`) → `GET /api/users/{id}` (owner match required; input `id`). Step 2 binds its `id` to the validated resource identifier from step 1 and compares access under the appropriate roles.
2. **Parent-child related resource:** `GET /api/users` (output `id`) → `GET /api/users/{user_id}/orders` (declared parent type `user`, input `user_id`, output `order_id`). The resource relationship is included only when metadata establishes the identifier flow.
3. **Administrative boundary:** `GET /api/users` (output `id`) → `GET /api/admin/users/{id}` (input `id`, admin-only expected role/permission metadata). The resulting candidate calls for role-boundary validation; it does not imply the operation is accessible.

## Member 2 integration

1. Retrieve endpoints from `FindingRepository.list_discovered_endpoints(scan_id)` or an existing trusted discovery result. Do not treat model-suggested paths as discovered endpoints.
2. Call `AttackChainPlanner.plan(...)`; pass `candidate.model_dump(mode="json")` (or the whole plan) to the executor. Current executor compatibility fields `candidate_id`, `scenario`, and `steps` are retained alongside the clearer `chain_id`, `vulnerability_category`, and `ordered_steps` fields. The model validator enforces equality between duplicated fields.
3. The executor independently validates chain length, dependency order, read-only GET/HEAD methods, and every path with `ScopeGuard`; mutation methods and request bodies are rejected. Requests use the existing `RequestExecutor`.
4. Resolve only `input_bindings` from successful prior-step responses and fields declared by endpoint metadata. A provenance record carries the source step, response field, status code, and response digest. Literal IDs are accepted only when registered as an explicit owned test fixture. Missing IDs and unresolved dependencies block the step; uncertain graph edges are not planned.
5. Preserve the existing four-role authorization comparison and evidence validation/storage flow. Only validated differential evidence can confirm a finding.

The existing AI agent may request the approved `plan_attack_chains` tool. `apply_ai_suggestions()` accepts only known candidate IDs and can reorder them; unknown IDs and any model-supplied routes, steps, scores, or authorization fields are ignored. Deterministic planning metadata remains unchanged, and the executor remains the deterministic validation gate.

## Risk and limitations

Risk score is a transparent prioritization heuristic based on chain scenario, relationship type, length, and available sensitivity metadata. It is not CVSS, measured exploitability, or a permission to execute. Configured fallback route inventories do not describe response schemas, so their outputs remain unknown and may yield no chain candidates. The assessment pipeline saves unverified plans after discovery but never auto-executes them. Deterministic no-network validation is available at `POST /api/assessments/{assessment_id}/attack-chains/validate`; execution validates again after explicit operator action.
