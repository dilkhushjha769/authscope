# Backend Implementation Status

Date: 2026-11-01

## Audit Summary

The repository already had a seven-stage assessment engine, scope validation, an `httpx` request executor with redirects disabled, role-separated session containers, authorization comparison, signed evidence, severity/remediation helpers, SQLite repositories, and FastAPI/SSE assessment lifecycle endpoints. The API already supported replay using `Last-Event-ID`, cancellation, recovery, and the frontend event vocabulary.

The audit found that endpoint discovery returned only a curated Juice Shop list, environment tokens implicitly assigned sample user IDs and owned resources, `authenticate_role()` synthesized a token when none was supplied, and response similarity or keyword matches could promote access to confirmed without enough role/ownership proof. Evidence hashes covered unsanitized response data and could not be checked against the sanitized artifact that was persisted. The assessment runner also treated every discrepancy as PII exposure when calculating severity.

## Completed

- `EndpointDiscovery.discover_from_openapi()` now fetches target API descriptions through the existing scoped `RequestExecutor`, accepts GET operations only, validates each discovered route, and caps discovery at 100 routes. It falls back to the existing curated Juice Shop routes when no usable in-scope OpenAPI document is exposed.
- User IDs and resource ownership are no longer inferred from role names or token presence. `authenticate_role()` no longer manufactures a session token. IDOR checks with a supplied ID require explicit owner registration before any request is sent.
- Confirmation now requires verified cross-role evidence tied to the registered resource or a shared sensitive value from the privileged baseline. HTTP 200, response shape, generic sensitive field names, and keyword presence alone cannot confirm a finding.
- Anonymous access to an admin route without an authenticated admin baseline is retained as suspicious, never confirmed.
- Severity calculation now derives PII and credential exposure from inspected response fields; admin route classification remains a separate privilege signal.
- Evidence hashes now cover the sanitized URL and sanitized response body that are stored. Completeness validation recomputes the hash. Evidence sanitization redacts email addresses, secret-like JSON fields, credential query parameters, and auth material.
- Request metadata, nested event data, and API failure events receive the shared secret/PII sanitizer. SSE streams now send comment heartbeats every 15 seconds and stop heartbeating after client disconnect.
- Test fixtures now register ownership explicitly and cover scoped OpenAPI discovery, absent ownership, false-positive BFLA prevention, evidence tampering, nested redaction, and token-only sessions.

## Not Completed / Limitations

- The live Juice Shop did not expose an OpenAPI document at the checked paths during the integration run, so the assessment used the configured eight-route Juice Shop fallback. Those fallback routes are test candidates and are not proof that every route exists on a particular target.
- A configured token is treated as configured session material; the session verification stage does not authenticate it against a target identity endpoint. Invalid tokens fail or produce incomplete baselines during requests, so affected checks remain suspicious, inconclusive, or untested.
- Parameterized object checks require resource ownership supplied by an authentication adapter or explicitly registered by the operator. The engine deliberately skips them when it cannot establish ownership. There is no default login flow that provisions separate Juice Shop test users or discovers their owned resources.
- `GeminiAuthScopeAgent` and source mapping/explanation adapters exist, but the default background runner uses the deterministic `AssessmentEngine` path unless an agent is injected. Automatically activating the external Gemini provider would make HTTP requests outside the target allowlist, which conflicts with the repository's absolute egress rule. Source mapping therefore is not guaranteed for ordinary API assessments; a provided source directory is only enriched on the adapter path.
- Source archives are not extracted by the default runner. Mapping requires a readable local source directory on the adapter path. Otherwise the result must be reported as unavailable/black-box.
- API request/response schemas and persisted event types were not changed. Existing SSE replay, lifecycle management, cancellation, and stable persisted event IDs remain in place; this change adds heartbeat comments without changing the SSE event contract.
- Remediation remains deterministic, category-based guidance from the existing `RemediationEngine`; it is not a target-language source patch unless the explanation/source adapter can verify actual source code.

## Files Modified

- `backend/analysis/evidence_validator.py`
- `backend/api/app.py`
- `backend/core/assessment_engine.py`
- `backend/core/session_manager.py`
- `backend/scanner/authorization_tester.py`
- `backend/scanner/endpoint_discovery.py`
- `backend/scanner/request_executor.py`
- `backend/scanner/response_analyzer.py`
- `backend/utils/helpers.py`
- `docs/BACKEND_IMPLEMENTATION_STATUS.md`
- `tests/conftest.py`
- `tests/test_assessment_engine.py`
- `tests/test_authorization.py`
- `tests/test_security_detection/test_bfla_detection.py`
- `tests/test_security_detection/test_bola_idor_detection.py`
- `tests/test_security_detection/test_request_safety_and_scope.py`
- `tests/test_task_recovery_and_multi_role.py`

## APIs and Events

- HTTP request/response schemas: unchanged.
- API endpoint paths and response schemas: unchanged.
- AssessmentEvent persisted schema: unchanged.
- Python interface addition: `EndpointDiscovery.discover_from_openapi(spec_url=None, executor=None, max_endpoints=100)`.
- SSE event names and payload schema: unchanged. The stream emits an SSE comment heartbeat during idle periods.

## Verification

Baseline before edits: `568 passed, 5 warnings`.

Final verification command and result:

```powershell
$env:PYTHONPATH='.'; .venv/Scripts/pytest.exe -q
```

Result: `572 passed, 5 warnings in 124.54s`.

Local Juice Shop integration selection:

```powershell
$env:PYTHONPATH='.'; .venv/Scripts/pytest.exe -q tests/test_assessment_engine.py::test_live_juice_shop_assessment_streaming tests/test_security_detection/test_live_juice_shop_integration.py -rs
```

Result: `7 passed`. The test suite's requests were limited to `http://localhost:3000`; the target was reachable. The assessment fell back to the configured route list because no supported OpenAPI document was available.

Warnings are Pydantic configuration/encoder deprecations and FastAPI `on_event` deprecation; no unexpected failures were observed.

## Run the Backend

```powershell
.venv/Scripts/uvicorn.exe backend.api.app:app --host 127.0.0.1 --port 8000
```

Run the local OWASP Juice Shop target separately at `http://localhost:3000`. Configure only real, separate test-role tokens and explicitly verified ownership metadata. Missing role sessions or ownership will cause checks to be skipped or marked inconclusive.

## Known Bugs / Remaining Work

- Add a target-specific, read-only session verification adapter that confirms the identity returned for each configured persona without inventing ownership.
- Discover safe Juice Shop routes from a target-maintained API description or another evidence-backed route source when available; identify fallback candidates separately in reports.
- Define an approved model-provider egress policy before making Gemini calls part of the default runner. Until then, keep provider calls opt-in and preserve the hard target boundary.
- Connect the optional local source directory/archive workflow to the default API runner and emit source mapping/explanation details only after filesystem verification.
- Add broader assessment lifecycle regression cases for idle SSE heartbeat, live-task duplicate initiation, and route-level failure reporting.
