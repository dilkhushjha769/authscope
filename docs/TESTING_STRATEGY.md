# AuthScope: Comprehensive Testing Strategy

AuthScope demands a rigorous testing strategy because security tools must be reliable, reproducible, and safe.

---

## 1. Test Pyramid & Categorization

```
         /\
        /  \     End-to-End Tests (Full Agent + Juice Shop Container)
       /----\
      /      \   Integration Tests (Mocked Target & Multi-Role Scenarios)
     /--------\
    /          \  Unit Tests (ScopeGuard, RequestExecutor, Evidence Hashing)
   /------------\
```

### A. Unit Tests (`tests/test_scope_guard.py`, `tests/test_evidence.py`, `tests/test_request_executor.py`)
- **ScopeGuard:** Boundary condition tests for invalid hostnames, arbitrary ports, IPv6 representations, non-HTTP schemes, and cloud metadata IPs.
- **EvidenceValidator:** Verifies that authorization tokens and passwords are redacted, and verifies SHA-256 evidence hashing reproducibility.
- **RequestExecutor:** Ensures redirects are suppressed, timeout settings are enforced, and headers are structured correctly.

### B. Integration Tests (`tests/test_authorization.py`, `tests/test_retesting.py`)
- Employs a mocked HTTP server or test doubles representing OWASP Juice Shop responses.
- Simulates differential response scenarios:
  - User A gets 200, User B gets 200 (IDOR detected).
  - User A gets 200, User B gets 403 (Secure behavior verified).
  - Anonymous gets 200 on private route (Missing authentication detected).

### C. Agent Interaction Tests (`tests/test_agent.py`)
- Tests Anthropic tool call deserialization and schema validation.
- Asserts that malformed tool payloads from LLM responses are trapped safely.

---

## 2. Test Execution Commands

```bash
# Run all unit tests
pytest -m unit

# Run boundary & scope enforcement tests
pytest -m scope

# Run full integration test suite with coverage
pytest --cov=backend tests/
```

---

## 3. False-Positive Validation Checks

Every differential test assertion must be subjected to a 3-way check:
1. Did the unauthorized role receive a success status (200-299)?
2. Is the response body non-empty and devoid of embedded error messages?
3. Does the returned object ID match the victim's resource rather than a default empty template?

