# Four-Role Authorization Testing System

This document describes AuthScope's **Multi-Role Authorization Testing System**, which uses four isolated testing identities (`Anonymous`, `User A`, `User B`, and `Admin`) to detect and validate real authorization vulnerabilities with cryptographic, non-destructive evidence.

---

## 1. Purpose of the Four Testing Roles

AuthScope evaluates endpoint access control across four canonical roles defined in `backend.core.session_manager.Role`:

| Role Enum | Value | Identity Purpose | Primary Security Checks |
|---|---|---|---|
| `Role.ANONYMOUS` | `"anonymous"` | Unauthenticated client (zero `Authorization` or `Cookie` headers). | Verifies whether protected endpoints reject unauthenticated requests (`401`/`403`) or expose sensitive data without login (`MISSING_AUTH`). |
| `Role.USER_A` | `"user_a"` | Legitimate resource owner (Normal User A). | Establishes the authorized baseline response, records owned resource IDs (`owned_resources`), accessible endpoints (`accessible_resources`), and baseline permissions (`permissions`). |
| `Role.USER_B` | `"user_b"` | Separate normal user account (Normal User B). | Attempts horizontal access (reading or safe non-destructive modification) against resources owned by `User A` to detect **BOLA / IDOR** (`BOLA_IDOR`). |
| `Role.ADMIN` | `"admin"` | Privileged administrator account. | Establishes baseline access on administrative endpoints (`owner_role=Role.ADMIN`) so normal-user (`User A`, `User B`) and `Anonymous` probes can detect vertical privilege escalation (`BFLA`, `PRIVILEGE_ESCALATION`), and tests cross-tenant admin policies (`admin_policy`). |

---

## 2. How Authentication Sessions Are Managed

Authentication sessions are managed by `SessionManager` (`backend/core/session_manager.py`):

1. **Isolated Per-Role State (`RoleSession`):**
   - Each role is stored in an isolated `RoleSession` instance containing its own Bearer token (`token`), cookie jar (`cookies`), `user_id`, `owned_resources`, `accessible_resources`, and `permissions`.
   - `Role.ANONYMOUS` is strictly enforced to emit empty headers (`get_headers() -> {}`) and empty cookies (`get_cookies() -> {}`), preventing accidental credential bleed.
2. **Pluggable Authentication Adapters (`AuthenticationAdapter`):**
   - `EnvTokenAuthenticationAdapter` loads pre-configured tokens, cookies, user IDs, and owned resource mappings from environment variables (`USER_A_TOKEN`, `USER_B_TOKEN`, `ADMIN_TOKEN`, etc.).
   - Custom adapters can authenticate via target login endpoints (`SessionManager.authenticate_with_adapter`).
3. **Zero Credential Invention:**
   - `SessionManager.require_authenticated_session(role)` verifies that non-anonymous roles hold active authentication material before sending requests. If a required role lacks credentials, `MissingSessionError` is raised and the test is recorded as `INCONCLUSIVE` / `NOT_TESTED`—never fabricated.
4. **Strict Redaction:**
   - `RoleSession.to_redacted_summary()` and `redact_sensitive_text()` strip all JWTs, Bearer tokens, cookies, and passwords (`[REDACTED]`) before any log, event, or database write.

---

## 3. How Cross-Role Request Comparison Works

`AuthorizationTester.test_four_role_access` (and `compare_four_roles`) in `backend/scanner/authorization_tester.py` executes a structured four-role matrix against an in-scope endpoint:

1. **Scope Validation:** `ScopeGuard.assert_in_scope(url, method)` verifies the target scheme, hostname, port, and HTTP method before any socket is opened.
2. **Owner Baseline Probe:** The designated `owner_role` (`Role.USER_A` for user resources, or `Role.ADMIN` for admin endpoints) requests the endpoint first. `AuthorizationTester` verifies that the baseline response is genuine structured data (not an SPA HTML shell or soft error) and records the baseline in the owner's `RoleSession` (`accessible_resources`, `permissions`).
3. **Cross-Role Probes:** The remaining roles (`Anonymous`, `User B`, `Admin` or `User A`) send identical requests using their respective `RoleSession` contexts via `RequestExecutor` (`httpx` with `follow_redirects=False`).
4. **Multi-Dimensional Differential Analysis (`DifferentialResult`):**
   - `status_codes_by_role`: HTTP status code returned for each role.
   - `resource_ids_by_role`: Concrete resource identifiers (`id`, `userId`, `UserId`, `basketId`, `orderId`) extracted from each role's JSON body.
   - `sensitive_fields_by_role`: Sensitive fields (`email`, `role`, `password`, `totpSecret`, `cardNum`, `balance`, etc.) exposed to each role.
   - `permissions_by_role` & `permission_differences`: Role capability matrix and human-readable summaries of unauthorized access discrepancies.
   - `response_behaviors_by_role`: Per-role `AccessVerdict` (`ALLOWED_ACCESS`, `CORRECTLY_DENIED`, `CONFIRMED_UNAUTHORIZED_ACCESS`, `SUSPICIOUS_ACCESS`, `INCONCLUSIVE`).

---

## 4. How IDOR / BOLA Is Detected

AuthScope detects both **read** and **write/modification** BOLA/IDOR vulnerabilities:

1. **Cross-User Read BOLA/IDOR (`test_bola_idor` / `test_four_role_access`):**
   - `User A` owns resource `R` (verified in `RoleSession.owned_resources` or response ownership fields) and retrieves `R` (`HTTP 200` with valid JSON payload).
   - `User B` requests `R` using `User B`'s session token.
   - `ResponseAnalyzer.compare_responses` confirms `BOLA_IDOR` **only** if `User B` receives `User A`'s actual resource payload (matching resource IDs, user markers, or high field/structural similarity) without soft error markers or self-scoped profile substitution.
2. **Non-Destructive Modification BOLA/IDOR (`test_unauthorized_modification`):**
   - Tests whether `User B` or `Anonymous` can modify `User A`'s resource via `POST`, `PUT`, or `PATCH`.
   - Requires `safe_test_fixture=True` and a benign payload (e.g., `{"quantity": 2}`).
   - Rejects `DELETE` and any payload containing destructive keys (`delete`, `drop`, `destroy`, `truncate`, ` purge`, `remove`, `reset`, `wipe`, `revoke`, `disable_account`, `isAdmin`, `role`, `password`).

---

## 5. How Vertical Privilege Escalation Is Detected

Vertical privilege escalation (`BFLA` and `PRIVILEGE_ESCALATION`) is tested by establishing `Role.ADMIN` as the baseline owner on administrative or privileged endpoints (e.g., `/rest/admin/application-configuration`, `/api/Users`):

1. `Role.ADMIN` accesses the administrative endpoint and receives valid administrative data (`ALLOWED_ACCESS`).
2. `Role.USER_A` and `Role.USER_B` (normal users) and `Role.ANONYMOUS` request the same administrative endpoint.
3. If `Role.USER_A` or `Role.USER_B` receives the privileged administrative response:
   - `AuthorizationTester` classifies the finding under both `BFLA` (Broken Function Level Authorization) and `PRIVILEGE_ESCALATION` (Vertical Privilege Escalation).
4. If `Role.ANONYMOUS` also receives the protected response without authentication:
   - `AuthorizationTester` classifies the anonymous outcome as `MISSING_AUTH`.
5. **Admin Policy Awareness (`admin_policy`):**
   - When testing user-owned resources (`owner_role=Role.USER_A`), `admin_policy` controls how `Role.ADMIN` access is evaluated:
     - `"allowed"` (default): Admin access to user resources is permitted by application policy (`ALLOWED_ACCESS`).
     - `"denied"`: Admin is forbidden from reading private user resources; `200 OK` with `User A`'s data is flagged as a violation.
     - `"policy_dependent"`: Admin access is flagged as `SUSPICIOUS_ACCESS` for manual policy review.

---

## 6. False-Positive Prevention Rules

AuthScope **never** reports a vulnerability solely because an endpoint returned `HTTP 200 OK`. `ResponseAnalyzer` and `AuthorizationTester` enforce strict false-positive filters:

- **SPA HTML Fallbacks:** `HTTP 200` responses returning `text/html` (`<!doctype html>`, `<app-root>`) are rejected as `CORRECTLY_DENIED` (`is_spa_fallback=True`).
- **Soft Error JSON:** `HTTP 200` responses containing `{"status": "error", "error": "Unauthorized"}` are rejected as `CORRECTLY_DENIED` (`is_soft_error=True`).
- **Empty JSON Payloads:** `HTTP 200` responses returning empty objects/lists (`{"data": []}`, `{"user": {}}`) are rejected.
- **Self-Scoped Endpoints:** Endpoints like `/rest/user/whoami` that return `User B`'s own profile (`id: 102`) when queried by `User B` are recognized as legitimate self-scoped responses (`CORRECTLY_DENIED`).
- **Public Endpoints:** Unprotected public metadata/catalog routes (`/rest/admin/application-version`, `/api/Products`) are excluded from confirmation.
- **Insufficient Ownership Proof:** If `User A`'s ownership of a resource ID is not verified in `RoleSession`, any discrepancy is downgraded to `INCONCLUSIVE` / `SUSPICIOUS_ACCESS`.

---

## 7. How to Configure Test Account Credentials

Configure test sessions in `.env` (or pass them to `SessionManager` in code). Never commit real secrets to version control:

```ini
# Authorized Target
TARGET_BASE_URL=http://localhost:3000

# Role 2: User A (Resource Owner)
USER_A_EMAIL=user_a@juice-sh.op
USER_A_USER_ID=101
USER_A_TOKEN=<jwt_for_user_a>
USER_A_OWNED_RESOURCES=basket:1,order:5001

# Role 3: User B (Different Normal User)
USER_B_EMAIL=user_b@juice-sh.op
USER_B_USER_ID=102
USER_B_TOKEN=<jwt_for_user_b>
USER_B_OWNED_RESOURCES=basket:2,order:5002

# Role 4: Admin
ADMIN_EMAIL=admin@juice-sh.op
ADMIN_USER_ID=1
ADMIN_TOKEN=<jwt_for_admin>
```

Check credential readiness programmatically:

```python
from backend.core.session_manager import SessionManager

sm = SessionManager(load_from_env=True)
print(sm.validate_configured_credentials())
# {'anonymous_ready': True, 'user_a_ready': True, 'user_b_ready': True, 'admin_ready': True, 'four_role_ready': True, ...}
```

---

## 8. How to Run the Authorization Tests

Run the dedicated 12-scenario Four-Role Authorization test suite:

```bash
.\.venv\Scripts\python.exe -m pytest tests/test_four_role_authorization.py -v
```

Run the full repository test suite:

```bash
.\.venv\Scripts\python.exe -m pytest -q
```

---

## 9. Known Limitations & Safety Controls

- **Hard Scope Enforcement:** `ScopeGuard` blocks any request outside the allowlisted target (`http://localhost:3000` by default). The AI agent cannot modify or bypass `ScopeGuard`.
- **Disabled Redirects:** All `httpx` clients enforce `follow_redirects=False` to prevent open-redirect scope escapes and accurately capture `301`/`302` authorization responses.
- **Non-Destructive Testing Only:** `DELETE` requests and destructive payload fields are rejected at both the `ScopeGuard` and `AuthorizationTester` layers. Modification tests require `safe_test_fixture=True`.
- **Single-Step HTTP Replay in Retest Engine:** Automated retesting (`RetestEngine.retest_finding`) replays verified `GET` evidence vectors with current role sessions and cryptographic signature verification.

