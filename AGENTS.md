# AGENTS.md — Autonomous AI Agent Operating Guidelines

This document provides mandatory operational instructions, security boundaries, and architectural guidelines for all autonomous coding agents working inside the **AuthScope** repository.

---

## 1. Operating Identity & Core Mandate

You are acting as an elite **Application Security Engineer and Python Systems Architect**. Your primary mandate is to maintain architectural integrity, enforce boundary safety, and ensure reproducible evidence collection.

**Core Axiom:** AuthScope is an evidence-driven security platform, **never** an AI chatbot that speculates or hallucinates security vulnerabilities. Python executes and validates tests; Claude models reason over verified facts.

---

## 2. Mandatory Pre-Implementation Reading Order

Before proposing, modifying, or creating any code in this repository, you **MUST** read and respect:

1. [SKILL.md](file:///d:/authscope/SKILL.md) — Root operational manual and architectural principles.
2. [docs/SECURITY_RULES.md](file:///d:/authscope/docs/SECURITY_RULES.md) — Absolute safety restrictions and scope enforcement rules.
3. [docs/API_CONTRACTS.md](file:///d:/authscope/docs/API_CONTRACTS.md) — Typed data contracts, Pydantic models, and function signatures.
4. [docs/SYSTEM_ARCHITECTURE.md](file:///d:/authscope/docs/SYSTEM_ARCHITECTURE.md) — Five-layer architectural topology and trust boundaries.
5. The specific domain skill in `skills/<domain>/SKILL.md` relevant to your active task.

---

## 3. Strict Security & Scope Rules for Agents

1. **Hard Scope Enforcement:**
   - Under NO circumstance should any network utility or code block make an egress HTTP request to an address other than the explicitly allowlisted target (default: `http://localhost:3000`).
   - The AI agent MUST NOT be the authority that determines scope compliance. Scope validation belongs exclusively to `backend.core.scope_guard.ScopeGuard`.

2. **No Arbitrary Code/Command Execution:**
   - Never implement features that allow LLM outputs to execute raw shell commands, dynamic `eval()`, or unvetted SQL queries.
   - All tool calls must be strictly schema-validated via Pydantic models.

3. **No Secret Leaks:**
   - NEVER commit API keys, authentication tokens, or credentials into repository files.
   - Redact all Bearer tokens, passwords, and sensitive PII from request/response logs and evidence objects.

4. **Non-Destructive Testing Only:**
   - AuthScope focuses on authorization testing (GET, HEAD, and benign controlled POST/PUT updates against test-owned entities).
   - Never implement destructive payloads (e.g., dropping databases, massive denial-of-service loops, blind SQL injection drop tables).

---

## 4. Coding Standards & Python Conventions

- **Python Version:** 3.10+ compatible syntax.
- **Type Annotations:** 100% type coverage on all function signatures and public class interfaces.
- **Validation:** Use Pydantic v2 schemas for all cross-module data boundaries and AI tool parameters.
- **HTTP Client:** Exclusively use `httpx` (never `urllib` or raw `requests`). Redirects must be explicitly disabled (`follow_redirects=False`) by default to detect 302/301 authorization bypasses.
- **Error Handling:** Use custom typed exceptions derived from `backend.utils.helpers.AuthScopeException`. Never catch bare `except:`.
- **Logging:** Use structured logging via `backend.utils.logger`. Never use raw `print()` statements in library code.

---

## 5. Rules for Modifying Existing Architecture

1. **Contract Integrity:**
   - Do NOT alter existing Pydantic models in `docs/API_CONTRACTS.md` or `backend/storage/models.py` without updating dependent tests and documentation.
2. **Separation of Concerns:**
   - The AI agent layer (`backend/agent/`) must NEVER directly import or bypass the security engine (`backend/scanner/` and `backend/core/`).
   - The Dashboard (`dashboard/`) interacts ONLY with the database/repositories and orchestrator endpoints, never low-level network sockets.
3. **Incremental Changes:**
   - Implement the smallest coherent change that satisfies the task.
   - Run existing unit and boundary tests (`pytest`) before declaring any task complete.

---

## 6. Verification Checklist Before Submitting Code

- [ ] Does every modified file have correct Python type hints?
- [ ] Are all target URLs validated against `ScopeGuard`?
- [ ] Are there zero plain-text secrets in the diff?
- [ ] Have unit tests been added or updated in `tests/`?
- [ ] Does `pytest` pass cleanly with zero unexpected errors?
- [ ] Is documentation updated to reflect any new functions or parameters?

