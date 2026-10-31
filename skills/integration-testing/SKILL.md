---
name: integration-testing
description: Strategy, fixtures, and protocols for unit, integration, and security regression testing.
version: 1.0.0
---

# Integration Testing Skill: Contracts, Boundaries & Regression

This skill provides guidelines for writing robust, reproducible test suites verifying AuthScope's components.

---

## 1. Testing Hierarchy & Scope

1. **Unit Testing (`tests/test_scope_guard.py`, `tests/test_evidence.py`):**
   - Pure, deterministic tests with zero external network dependencies.
   - Assert all edge cases of hostname matching, IP validation, and cryptographic hashing.
2. **Integration Testing (`tests/test_authorization.py`, `tests/test_retesting.py`):**
   - Uses `pytest-mock` or custom HTTP transport adapters to simulate OWASP Juice Shop.
   - Tests the complete pipeline from endpoint discovery -> role session dispatch -> differential comparison -> evidence recording.
3. **End-to-End Testing (`tests/test_agent.py`):**
   - Tests the AI Agent tool orchestration loop using mocked LLM responses or local Anthropic API test keys.

---

## 2. Testing Scope Restrictions & Boundary Escape

Every test suite must assert that `ScopeGuard` rejects:
- Non-allowlisted external domains (`https://google.com`, `http://evil.com`).
- Disallowed local ports (`http://localhost:8080`, `http://localhost:22`).
- Dangerous schemes (`file:///etc/passwd`, `gopher://`, `ftp://`).
- Cloud instance metadata addresses (`http://169.254.169.254/latest/meta-data/`).

```python
def test_scope_guard_blocks_external_url():
    guard = ScopeGuard(allowed_hosts=["localhost", "127.0.0.1"], allowed_ports=[3000])
    result = guard.check_url("http://example.com/api")
    assert result.is_allowed is False
    assert "not allowlisted" in result.reason.lower()
```

---

## 3. Retesting & Regression Protocols

- Retesting tests must assert that when a mocked target is changed from returning `200 OK` (vulnerable) to `403 Forbidden` (fixed), the `RetestEngine` correctly updates the finding status from `CONFIRMED` to `REMEDIATED`.
- Test reproducibility: Verify that repeating the same non-destructive request yields matching evidence signatures.

