# AuthScope: Developer Onboarding & Development Guide

Welcome to the AuthScope development team. This guide outlines how to configure your workstation, run local target instances, execute tests, and contribute safely.

---

## 1. Local Development Setup

### System Prerequisites
- **Python:** 3.10, 3.11, or 3.12
- **Docker:** (Required for running OWASP Juice Shop locally)
- **Git**

### Step-by-Step Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/authscope.git
   cd authscope
   ```

2. **Initialize Python Virtual Environment:**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Initialize Environment Variables:**
   ```bash
   cp .env.example .env
   ```
   Configure `.env` with your `ANTHROPIC_API_KEY`.

5. **Start Target Environment (OWASP Juice Shop):**
   ```bash
   docker run -d --name authscope-juice-shop -p 3000:3000 bkimminich/juice-shop
   ```
   Check that `http://localhost:3000` responds in your browser or with `curl http://localhost:3000`.

---

## 2. Directory Conventions

- `backend/core/`: Security perimeter and session infrastructure. Changes here affect global safety.
- `backend/scanner/`: Network transmission, HTTP response diffs, and endpoint parsing.
- `backend/agent/`: Claude 3.5 Sonnet integration, tool registration, prompt engineering.
- `backend/analysis/`: Evidence integrity checking, severity scoring, and remediation logic.
- `backend/storage/`: SQLite database schemas, models, and data repositories.
- `dashboard/`: Streamlit user interface components.
- `tests/`: Automated unit and integration tests.

---

## 3. Running Tests & Quality Verification

Always verify tests before opening a pull request or committing code:

```bash
# Run all tests
pytest

# Run only scope guard tests
pytest tests/test_scope_guard.py

# Run with verbose output and coverage
pytest -v --tb=short
```

---

## 4. How to Implement a New Scanner Check

1. **Define Contract:** In `docs/API_CONTRACTS.md` and `backend/scanner/`, specify the test function signature with typed parameters and return schemas.
2. **Implement Security Verification:** Use `ScopeGuard.validate_url()` prior to sending any request.
3. **Use RequestExecutor:** Never call `httpx` or `requests` directly; always route through `RequestExecutor` to enforce timeouts, redirect suppression, and audit logging.
4. **Capture Evidence:** Create an `Evidence` object, redact sensitive tokens, and compute an SHA-256 hash.
5. **Write Unit Tests:** Create test cases in `tests/` mocking the HTTP transport layer.

