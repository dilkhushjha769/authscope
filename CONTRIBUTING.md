# Contributing to AuthScope

Thank you for contributing to **AuthScope**. To maintain the highest security, reliability, and code quality standards, all contributors and coding agents must follow these guidelines.

---

## 1. Branch Naming Conventions

All feature and bug fix branches must follow the standard naming structure:
- `feature/<short-description>`: New functional capabilities (e.g., `feature/scope-guard-validator`).
- `fix/<short-description>`: Bug fixes and security hardening (e.g., `fix/redirect-suppression`).
- `docs/<short-description>`: Documentation additions and clarifications (e.g., `docs/api-contracts-update`).
- `test/<short-description>`: Additional test suites or fixtures (e.g., `test/session-isolation`).

---

## 2. Commit Message Guidelines

Use Conventional Commits formatting:
```
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```
Types:
- `feat`: New feature or scanner capability.
- `fix`: Bug fix in scanner, agent, or dashboard.
- `sec`: Security enhancement or scope enforcement improvement.
- `docs`: Documentation changes only.
- `refactor`: Code change that neither fixes a bug nor adds a feature.
- `test`: Adding missing tests or correcting existing tests.

Examples:
- `feat(scanner): implement differential authorization tester for REST endpoints`
- `sec(scope): enforce strict port and protocol allowlist in ScopeGuard`
- `test(core): add unit tests for multi-role session token rotation`

---

## 3. Pull Request Workflow

1. **Create Branch:** Create a branch from `main`.
2. **Follow Architectural Boundaries:** Respect the 5-layer architecture. No agent logic inside the network executor, no raw network calls inside the dashboard.
3. **Write Unit Tests:** Every new module or function must have corresponding tests in `tests/`.
4. **Run Local Checks:**
   ```bash
   pytest
   ```
5. **No Secrets:** Ensure zero credentials, cookies, or real API keys are present.
6. **Submit PR:** Open a PR against `main` with a clear description of changes, architectural impact, and test results.

---

## 4. Code Review Standards

Code reviews must verify:
1. **Scope Safety:** Does this change risk sending unmonitored or unapproved requests outside the target?
2. **Type Safety:** Are all inputs and outputs explicitly typed?
3. **Data Redaction:** Are Authorization headers and sensitive response fields scrubbed before persisting?
4. **Reproducibility:** Does the finding generation create an auditable, verifiable record?

