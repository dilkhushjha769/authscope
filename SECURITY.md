# Security Policy

## 1. Authorized Testing & Ethical Use

AuthScope is designed strictly for **authorized, ethical penetration testing and security research**.

### Authorized Scope Rules
- AuthScope must only be pointed at systems, environments, or containers that you own or for which you have explicit, documented, written authorization to perform penetration testing.
- Default configuration targets a locally hosted OWASP Juice Shop (`http://localhost:3000`).
- Target allowlists are enforced at the network transport layer via `backend.core.scope_guard.ScopeGuard`.

---

## 2. Scope Enforcement & Egress Protection

To prevent inadvertent security incidents or unauthorized scanning:
1. **Host & Port Allowlisting:** Only domains and ports explicitly declared in `.env` are permitted.
2. **Protocol Restrictions:** Only `http` and `https` schemes are supported. `file://`, `ftp://`, `ldap://`, etc., are rejected immediately.
3. **Loopback & Private Network Safety:** While local testing defaults to `localhost:3000`, scanning cloud internal metadata addresses (e.g., `169.254.169.254`) is strictly blocked.
4. **Redirect Egress Protection:** Automatic HTTP redirection following is disabled (`follow_redirects=False`) to prevent open redirect SSRF escaping the target perimeter.

---

## 3. Secrets & Sensitive Data Handling

- **Never Commit Secrets:** Do not commit API keys, passwords, database credentials, or real authentication tokens into version control.
- **Evidence Redaction:** AuthScope's `EvidenceValidator` systematically scrubs sensitive request headers (`Authorization`, `Cookie`, `X-API-Key`) and personal identifiable information (PII) before storage or dashboard presentation.
- **Ephemeral Sessions:** Authentication session tokens are maintained in memory within `backend.core.session_manager.SessionManager` and should not be stored in raw plain-text database fields.

---

## 4. Reporting Security Vulnerabilities in AuthScope

If you discover a security vulnerability or boundary escape vulnerability within AuthScope itself (such as a scope guard bypass or unintended code execution flaw):

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report to the security maintainers (e.g., via private email or GitHub Security Advisory).
3. Include reproducible steps, target environment details, and proof of concept.
4. The maintainers will acknowledge receipt within 48 hours and work with you on a coordinated disclosure timeline.

