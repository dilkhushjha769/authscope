# AuthScope: Comprehensive Testing Strategy

AuthScope demands a rigorous testing strategy because security tools must be reliable, reproducible, and safe.

---

## 1. Test Pyramid & Categorization

```
         /\
        /  \     Live Target Integration Tests (tests/integration/ vs localhost:3000)
       /----\
      /      \   Differential & Mocked Transport Tests (tests/test_authorization.py)
     /--------\
    /          \  Unit Tests (ScopeGuard, RequestExecutor, EvidenceValidator)
   /------------\
```

### A. Unit Tests (`tests/test_scope_guard.py`, `tests/test_evidence.py`, `tests/test_request_executor.py`)
- **ScopeGuard:** Boundary condition tests for invalid hostnames, arbitrary ports, IPv6 representations, non-HTTP schemes, non-GET methods, embedded credentials, null bytes, and cloud metadata IPs.
- **EvidenceValidator:** Verifies that authorization tokens, cookies, raw JWTs, and password fields in headers and response bodies are redacted, checks completeness gates, and verifies SHA-256 evidence hashing reproducibility.
- **RequestExecutor:** Ensures redirects are suppressed (`follow_redirects=False`), timeout settings are enforced, and headers are sanitized in metadata and logs.

### B. Differential Authorization Tests (`tests/test_authorization.py`, `tests/test_retesting.py`)
- Employs `httpx.MockTransport` representing controlled target responses:
  - **Authorized Owner Access:** Verifies `ALLOWED_ACCESS` when owner or allowed role accesses resource.
  - **Proper Denial:** Verifies `CORRECTLY_DENIED` when unauthorized role receives `401`/`403`.
  - **Confirmed Cross-User BOLA/IDOR:** Verifies `CONFIRMED_UNAUTHORIZED_ACCESS` when User B receives User A's resource (`id=1`, `UserId=1`) with matching structure and sensitive fields.
  - **Suspicious Cross-User Access:** Verifies `SUSPICIOUS_ACCESS` when User B receives `200 OK` with a different body and no matching owner identifiers.
  - **False-Positive Prevention:** Asserts that `200 OK` SPA HTML fallback shells, `200 OK` empty JSON (`{"user": {}}`), soft JSON errors, and self-scoped responses (`User B` viewing `User B`) are never flagged as vulnerabilities.
  - **Missing Sessions & Human Approval:** Verifies `MissingSessionError`, `InvalidTargetURLError` (refusing to invent resource ownership), and `HumanApprovalRequiredError`.

### C. Live Integration Tests (`tests/integration/test_juice_shop_connection.py`, `tests/integration/test_juice_shop_authorization.py`)
- Executes real GET requests against locally running OWASP Juice Shop (`http://localhost:3000`) when available.
- Verifies live SPA HTML fallback detection, `/rest/user/whoami` empty payload handling, and `/rest/basket/1` `401 Unauthorized` enforcement for `Anonymous`.

---

## 2. Test Execution Commands

```bash
# Run all tests (unit + live integration)
.venv\Scripts\python.exe -m pytest -v

# Run unit tests only
.venv\Scripts\python.exe -m pytest -m "not integration" -v

# Run authorization differential unit tests
.venv\Scripts\python.exe -m pytest tests/test_authorization.py -v

# Run live OWASP Juice Shop integration tests
.venv\Scripts\python.exe -m pytest tests/integration/ -v
```
