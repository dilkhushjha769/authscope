# AuthScope: Mandatory Security Rules

These rules represent immutable security requirements for AuthScope. No coding agent, contributor, or administrator is permitted to bypass these constraints.

---

## 1. Absolute Scope Confinement
- **Allowlist Enforced:** Every network request must pass through `ScopeGuard.validate_url()`.
- **Default Target:** `http://localhost:3000` (OWASP Juice Shop).
- **Prohibited Egress:** Any request attempting to contact cloud metadata services (`169.254.169.254`, `metadata.google.internal`), unapproved domains, or arbitrary local ports is blocked and logged as a security event.
- **GitHub App Provider Exception:** The separate account-integration client may contact only `https://github.com` for OAuth and `https://api.github.com` for the GitHub App API. Each request passes through its dedicated exact-host `ScopeGuard`, uses HTTPS/443, disables redirects, and permits only the OAuth/API methods needed for this integration. This provider allowlist never expands the website assessment target scope.

## 2. No Dynamic Arbitrary Code Execution
- The AI Agent is strictly prohibited from running shell commands, executing scripts, or evaluating arbitrary Python strings (`eval`, `exec`).
- All tool execution occurs via deterministic, statically declared Python functions.

## 3. Non-Destructive Operation Only
- AuthScope tests **authorization boundaries**, not system destruction.
- **Initially Permitted HTTP Methods:** Exclusively `GET` during early phases to guarantee zero state modification or destruction. POST/PUT/PATCH will be permitted only in subsequent phases for isolated test-owned resources.
- **Destructive Payloads Prohibited:** Blind deletions of shared master tables, user account wipeouts, or Denial-of-Service volumetric loops are prohibited.
- **Response Size Boundaries:** Strict limit (`MAX_RESPONSE_SIZE_BYTES=1048576`, 1MB) and body display limit (`MAX_BODY_DISPLAY_CHARS=25000`) prevents memory exhaustion and zip-bomb attacks.

## 4. Redirect Suppression & SSRF Defense
- Automatic following of HTTP redirects is strictly disabled (`follow_redirects=False`) on all `httpx.Client` instances.
- Many authorization bypasses manifest as `302 Found` with redirect bodies containing leaked data. Following redirects silently masks this evidence or causes SSRF escapes.
- All 3xx redirect status codes and `Location` headers are captured and returned directly for analysis.

## 5. Evidence Redaction & Secret Protection
- Authentication tokens (`Bearer eyJ...`), passwords, session cookies, and private customer emails must be redacted before being displayed or persisted to disk.
- All request metadata and structured logs pass through `sanitize_headers_for_logging()`, replacing Authorization tokens with `Bearer [REDACTED_TOKEN]`.
- Ephemeral session tokens reside exclusively in memory within `SessionManager`.

## 6. Immutable Evidence Verification
- An alert is labeled `CONFIRMED` only when verified differential HTTP evidence exists.
- Evidence records are signed using SHA-256 over canonicalized request/response bytes to prevent evidence tampering.

