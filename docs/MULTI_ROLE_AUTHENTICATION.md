# Multi-Role Authentication & Persistent Background Task Recovery

This document details the multi-role credential configuration, cross-tenant authorization testing architecture, and persistent background task recovery mechanisms implemented in **AuthScope**.

---

## 1. Persistent Background Task Recovery

To ensure that server restarts, crashes, or timeout events never leave assessment jobs in a corrupt, indeterminate, or indefinitely locked state, AuthScope implements SQLite-backed task state tracking.

### 1.1 Task Metadata in SQLite

The `scan_sessions` table persists lifecycle metadata for all assessments:
- `id`: Unique scan identifier (`scan_YYYYMMDD_HHMMSS_<hex>`).
- `status`: Current state (`PENDING`, `RUNNING`, `COMPLETED`, `CANCELLED`, `FAILED`).
- `started_at`: UTC timestamp of assessment initialization.
- `updated_at`: UTC timestamp of the most recent stage progression or status change.
- `completed_at`: UTC timestamp of termination.
- `failure_reason`: Explicit cause of failure (`SERVER_RESTART`, `TIMEOUT`, `EXECUTION_ERROR`, etc.).

### 1.2 Startup Recovery (`SERVER_RESTART`)

When the FastAPI backend starts up:
1. It queries `FindingRepository.recover_orphaned_running_sessions(active_session_ids=...)`.
2. Any session found in `RUNNING` or `PENDING` status that does not correspond to an active in-memory background task is identified as orphaned from a prior server process.
3. The session's status is atomically transitioned to `FAILED` with `failure_reason = 'SERVER_RESTART'`.
4. A corresponding `assessment_failed` audit event is persisted in the event stream for full traceability.
5. In-flight tasks in memory (if any) are preserved and never falsely marked as failed.

### 1.3 Assessment Timeout Protection

Background assessment execution is governed by `ASSESSMENT_TIMEOUT_SECONDS` (default: 300 seconds):
- If an assessment generator exceeds this threshold, `AssessmentTaskManager` catches `asyncio.TimeoutError`.
- The background task cancels the underlying token and transitions the session to `FAILED` with `failure_reason = 'TIMEOUT'`.
- An `ASSESSMENT_FAILED` event is emitted and broadcast to any connected SSE clients.

### 1.4 Safe Interrupted Task Retry

Operators can re-execute failed or interrupted assessments via:
`POST /api/assessments/{assessment_id}/retry`

- Verifies target scope allowlist via `ScopeGuard`.
- Re-initializes stage trackers and metrics to clean initial states.
- Retains the assessment ID and starts a new managed background worker.

---

## 2. Multi-Role Authentication Configuration

AuthScope performs authorization-differential testing across isolated personas without guessing or fabricating credentials.

### 2.1 Persona Roles

| Role | Environment Variables | Description |
|---|---|---|
| `anonymous` | None | Unauthenticated baseline persona. |
| `user_a` | `USER_A_TOKEN`, `USER_A_EMAIL`, `USER_A_PASSWORD` | Primary low-privilege resource owner (Tenant A). |
| `user_b` | `USER_B_TOKEN`, `USER_B_EMAIL`, `USER_B_PASSWORD` | Independent low-privilege peer tenant (Tenant B). |
| `admin` | `ADMIN_TOKEN`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` | High-privilege administrative persona. |

### 2.2 Strict Zero-Credential Exposure

Security boundaries strictly guarantee zero leakage of secret tokens:
1. **`repr=False` in Pydantic Models:** `AuthCredentials.password` and `RoleSession.token` are configured with `repr=False`, preventing secrets from appearing in `str()`, `repr()`, or exception stack traces.
2. **Masked Validation Reports:** `SessionManager.validate_configured_credentials()` reports boolean readiness (`multi_role_ready`, `authenticated_roles`) without exposing raw token values or hashes.
3. **Redacted Evidence & Logs:** Evidence artifacts and HTTP request log dumps only contain sanitized headers. Raw `Authorization: Bearer <token>` headers are never written to disk or returned to the frontend.

### 2.3 Cross-User Authorization Verification

When `USER_A_TOKEN` and `USER_B_TOKEN` are configured:
1. The engine checks resource ownership (e.g., Tenant A owns basket ID `1`; Tenant B owns basket ID `2`).
2. The engine probes ownership-based routes (`/rest/basket/1`) under Tenant A (expected `200 OK`) and Tenant B (expected `403 Forbidden`).
3. If Tenant B receives Tenant A's private data, the engine checks for reproducible cryptographic evidence.
4. Only when multi-role baselines and evidence validation succeed is a vulnerability marked `CONFIRMED`.
5. If tokens are missing or the response is indeterminate, AuthScope classifies the result as `SUSPICIOUS_ACCESS` pending human review, completely avoiding speculative false positives.

