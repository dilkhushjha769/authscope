---
name: security-testing
description: Operational manual for authorization testing, IDOR detection, scope enforcement, and evidence collection.
version: 1.0.0
---

# Security Testing Skill: Authorization, IDOR & Access Control

This skill guides engineers and coding agents on executing secure, authorized penetration testing focusing on Broken Access Control (BAC) and Insecure Direct Object References (IDOR).

---

## 1. Core Security Concepts

### Authentication vs. Authorization
- **Authentication (AuthN):** Verifying identity ("Who are you?"). Usually handled via JWTs, session cookies, or API keys.
- **Authorization (AuthZ):** Verifying permissions ("What are you allowed to do?"). Checking whether an authenticated identity has the right to access a specific resource or perform an action.
- *AuthScope focuses primarily on Authorization failures.*

### Insecure Direct Object References (IDOR / BOLA)
- Occurs when an application provides direct access to objects based on user-supplied input without validating resource ownership.
- Example: `GET /rest/basket/1` accessed by a user whose own basket is `2`. If the endpoint returns Basket 1's contents, IDOR is confirmed.

### Broken Function Level Authorization (BFLA)
- Occurs when unprivileged users can invoke sensitive functions intended only for administrators or privileged roles (e.g., standard users accessing `/api/Users` or `/rest/admin/metrics`).

---

## 2. Authorization-Differential Testing Methodology

Differential testing is the cornerstone of AuthScope:

1. **Baseline Request:** Send request under `User A` (the legitimate owner of resource ID `X`). Validate expected success status (`200 OK`).
2. **Peer Differential Request:** Send identical request with parameter `X` under `User B` (a peer account with identical privilege level).
   - If response is `403 Forbidden` or `404 Not Found`: Authorization is **Enforced**.
   - If response is `200 OK` with User A's data: **IDOR / BOLA Confirmed**.
3. **Anonymous Differential Request:** Send identical request with zero authentication headers.
   - If response is `401 Unauthorized` or `302 Login`: Authentication is **Enforced**.
   - If response is `200 OK` with sensitive data: **Missing Authentication Confirmed**.

---

## 3. Safe Evidence Collection & Integrity

- **Non-Destructive Payloads:** Never use destructive methods (e.g. `DELETE /api/Users/1`) unless explicitly testing on throwaway test-generated entities. Prioritize read-based differential queries (`GET`).
- **Token & PII Redaction:** Always mask authorization headers (`Authorization: Bearer [REDACTED]`), cookie values, and PII before writing evidence to disk.
- **Cryptographic Hashing:** Generate an SHA-256 hash across the normalized request method, path, status code, and response body. This proves the evidence was captured directly from the test run without tampering.

---

## 4. Scope Enforcement Guardrails

- Never send a request before checking `ScopeGuard.validate_url(url)`.
- Re-check URLs after resolving query strings and route parameters.
- Disallow redirects to prevent open redirect SSRF escaping the target.

