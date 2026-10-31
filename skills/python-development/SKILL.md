---
name: python-development
description: Best practices, standards, and guidelines for Python 3.10+ development in AuthScope.
version: 1.0.0
---

# Python Development Skill: Architecture, Typing & Quality

This skill instructs engineers and AI agents on Python standards, patterns, and libraries used within AuthScope.

---

## 1. Code Standards & Typing

- **Python Version:** 3.10+ required. Use modern type union syntax (`str | None` or `Optional[str]`).
- **Strict Typing:** All function arguments and return types must be explicitly typed.
- **Pydantic v2 Models:** Cross-module data transfers must use Pydantic models with descriptive field documentation:
  ```python
  from pydantic import BaseModel, Field

  class DiscoveredEndpoint(BaseModel):
      path: str = Field(..., description="Normalized URL path")
      method: str = Field("GET", description="HTTP method")
      requires_auth: bool = Field(True, description="True if endpoint expects credentials")
  ```

---

## 2. HTTP Client Best Practices (`httpx`)

Always use `httpx.Client` or `httpx.AsyncClient` with the following defensive defaults:
```python
import httpx

client = httpx.Client(
    timeout=httpx.Timeout(10.0, connect=5.0),
    follow_redirects=False,  # CRITICAL: Do not auto-follow redirects
    headers={"User-Agent": "AuthScope-Security-Agent/1.0"}
)
```
- Disabling `follow_redirects` prevents SSRF and preserves 301/302 responses for inspection.
- Always handle `httpx.TimeoutException`, `httpx.ConnectError`, and `httpx.HTTPError`.

---

## 3. Exception Handling & Logging

- Never use bare `except:` or catch `Exception` without re-raising or logging the specific context.
- Derive project exceptions from `backend.utils.helpers.AuthScopeException`:
  ```python
  class ScopeViolationError(AuthScopeException):
      """Raised when an out-of-scope URL is requested."""
      pass
  ```
- Use the central logger (`backend.utils.logger.get_logger(__name__)`):
  ```python
  from backend.utils.logger import get_logger

  logger = get_logger(__name__)
  logger.info("Executing differential test on endpoint", extra={"path": endpoint_path})
  ```

---

## 4. SQLite Storage Integration

- Use standard library `sqlite3` with parameterized queries (`?`) to prevent SQL injection.
- Enable foreign keys (`PRAGMA foreign_keys = ON;`).
- Encapsulate database interactions inside repository classes (`backend.storage.finding_repository.FindingRepository`).

---

## 5. Testing with Pytest

- All unit tests belong in `tests/` and start with `test_*.py`.
- Use `pytest` fixtures for common mocks (mocking `httpx` responses, database in-memory connections).
- Run tests regularly: `pytest -v`.

