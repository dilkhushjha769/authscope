# AuthScope: Project Overview

## 1. Executive Summary

**AuthScope** is an evidence-driven, hard-scoped, AI-powered penetration testing agent specifically engineered to identify, validate, and document authorization vulnerabilities in modern web applications and APIs.

Traditional Dynamic Application Security Testing (DAST) tools are predominantly signature-based. They are effective at finding injection attacks (SQLi, XSS) where input reflection or server error messages signal flaws. However, they consistently fail at **Broken Access Control (OWASP #1)** and **Insecure Direct Object References (IDOR)** because authorization logic is deeply contextual:
- Does User A have legitimate business rights to view User B's order?
- Can a standard member invoke a tenant-level administration endpoint?
- Can an unauthenticated visitor enumerate private customer profiles?

AuthScope solves this by combining **deterministic Python-driven multi-role differential testing** with **Claude 3.5 Sonnet's contextual reasoning capabilities**.

---

## 2. Problem Statement & Market Gap

| Approach | Strength | Fatal Flaw |
|---|---|---|
| **Legacy DAST (Zap, Burp active scan)** | Broad fuzzing, high throughput | Misses authorization logic, blind to multi-user state separation |
| **LLM Security Chatbots** | High conceptual understanding of code | Hallucinates vulnerabilities, cannot produce reproducible proof |
| **Manual Penetration Testing** | High context, finds complex business logic chains | Expensive, slow, infrequent, non-continuous |
| **AuthScope (Our Solution)** | **Python executes & validates evidence; AI reasons over attack graph** | **Hard-scoped, zero hallucinated findings, fully reproducible** |

---

## 3. High-Level Objectives

1. **Autonomous Surface Discovery:** Parse target application OpenAPI/Swagger specifications, extract route trees, and extract path parameters.
2. **Deterministic Role Management:** Maintain multiple isolated authenticated sessions:
   - `Anonymous` (Unauthenticated)
   - `User A` (Low-privilege normal user)
   - `User B` (Low-privilege normal user, peer of User A)
   - `Admin` (Elevated privileges)
3. **Authorization-Differential Testing:** Execute identical HTTP requests across all roles and identify semantic access discrepancies.
4. **Multi-Endpoint Attack Chain Detection:** Enable the AI agent to chain multiple endpoints (e.g., leaking an internal ID via `/api/Users` -> accessing `/rest/basket/{id}`).
5. **Reproducible Non-Destructive Proof:** Capture full HTTP request/response payloads, redact secrets, and compute SHA-256 evidence verification hashes.
6. **Sensitivity-Aware Severity Scoring:** Score findings based on CVSS 3.1 criteria combined with data classification (PII, Financial, Admin controls).
7. **One-Click Retesting:** Provide verified regression retesting to validate fixes.
8. **Security Operations Dashboard:** Deliver a dark-themed, clean Streamlit dashboard.

---

## 4. Default Target: OWASP Juice Shop

AuthScope uses **OWASP Juice Shop** (`http://localhost:3000`) as its official reference target. Juice Shop is an intentionally vulnerable Node.js/Angular/Express application containing real-world representations of:
- BOLA / IDOR on shopping baskets (`/rest/basket/{id}`)
- Vertical privilege escalation on administrative endpoints
- Sensitive data exposure in user profile APIs
- Authorization bypass via parameter manipulation

