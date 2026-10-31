# AuthScope: Mandatory Security Rules

These rules represent immutable security requirements for AuthScope. No coding agent, contributor, or administrator is permitted to bypass these constraints.

---

## 1. Absolute Scope Confinement
- **Allowlist Enforced:** Every network request must pass through `ScopeGuard.validate_url()`.
- **Default Target:** `http://localhost:3000` (OWASP Juice Shop).
- **Prohibited Egress:** Any request attempting to contact cloud metadata services (`169.254.169.254`, `metadata.google.internal`), external networks, unapproved domains, or arbitrary local ports is blocked and logged as a security event.

## 2. No Dynamic Arbitrary Code Execution
- The AI Agent is strictly prohibited from running shell commands, executing scripts, or evaluating arbitrary Python strings (`eval`, `exec`).
- All tool execution occurs via deterministic, statically declared Python functions.

## 3. Non-Destructive Operation Only
- AuthScope tests **authorization boundaries**, not system destruction.
- **Allowed HTTP Methods:** `GET`, `HEAD`, `OPTIONS`, `POST` (read-only/benign entity generation in isolated test accounts), `PUT`/`PATCH` (modifications of test-owned records only).
- **Destructive Payloads Prohibited:** Blind deletions of shared master tables, user account wipeouts, or Denial-of-Service volumetric loops are prohibited.

## 4. Redirect Suppression
- Automatic following of HTTP redirects is disabled (`follow_redirects=False`) across all client instances.
- Many authorization bypasses manifest as `302 Found` with redirect bodies containing leaked data. Following redirects silently masks this evidence or causes SSRF escapes.

## 5. Evidence Redaction & Secret Protection
- Authentication tokens (`Bearer eyJ...`), passwords, session cookies, and private customer emails must be redacted before being displayed or persisted to disk.
- All stored evidence must mask secrets using placeholders like `[REDACTED_BEARER_TOKEN]`.

## 6. Immutable Evidence Verification
- An alert is labeled `CONFIRMED` only when verified differential HTTP evidence exists.
- Evidence records are signed using SHA-256 over canonicalized request/response bytes to prevent evidence tampering.

