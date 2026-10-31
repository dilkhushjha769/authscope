# AuthScope: Hackathon & Implementation Roadmap

This roadmap breaks development into 10 structured phases, distinguishing core MVP deliverables from post-hackathon advanced capabilities.

---

## Roadmap Overview

```mermaid
gantt
    title AuthScope Hackathon Execution Schedule
    dateFormat  YYYY-MM-DD
    section Phase 1-3
    Phase 1: Project Foundation           :done,    p1, 2026-10-31, 1d
    Phase 2: Juice Shop Integration       :active,  p2, 2026-11-01, 1d
    Phase 3: Request Executor & Scope     :         p3, 2026-11-02, 1d
    section Phase 4-6
    Phase 4: Endpoint Discovery & Diff    :         p4, 2026-11-03, 1d
    Phase 5: Claude AI Agent Tools        :         p5, 2026-11-04, 1d
    Phase 6: Evidence & SQLite Storage    :         p6, 2026-11-05, 1d
    section Phase 7-10
    Phase 7: Severity & Remediation       :         p7, 2026-11-06, 1d
    Phase 8: Automated Retesting Engine   :         p8, 2026-11-07, 1d
    Phase 9: Streamlit Dashboard          :         p9, 2026-11-08, 1d
    Phase 10: E2E Testing & Demo Script   :         p10, 2026-11-09, 1d
```

---

## Detailed Phase Breakdown

### Phase 1: Project Foundation & Environment Setup
- **Status:** **COMPLETED** (Current Phase)
- **Scope:** Root documents, system architecture, API contracts, domain skills, directory scaffolding, `.env.example`, `requirements.txt`, `pytest.ini`.
- **Classification:** **[MVP - REQUIRED]**

### Phase 2: Juice Shop Integration & Test-Role Management
- **Target:** Automate local OWASP Juice Shop container launching.
- **Deliverables:** `SessionManager` capable of logging in as `User A`, `User B`, and `Admin`, extracting JWT tokens and storing them safely in memory.
- **Classification:** **[MVP - REQUIRED]**

### Phase 3: Secure Request Executor & Scope Guard
- **Target:** Establish the network perimeter and HTTP request pipeline.
- **Deliverables:** `ScopeGuard` with strict IP/hostname allowlist, `RequestExecutor` wrapped around `httpx` with timeout and redirect suppression.
- **Classification:** **[MVP - REQUIRED]**

### Phase 4: Endpoint Discovery & Authorization-Differential Tester
- **Target:** Map routes and execute comparative differential testing.
- **Deliverables:** Parse OpenAPI/Swagger JSON from Juice Shop; execute cross-role matrix tests on routes (`/rest/basket/{id}`, `/api/Users`, `/rest/admin/application-version`).
- **Classification:** **[MVP - REQUIRED]**

### Phase 5: AI Agent Integration (Claude 3.5 Sonnet)
- **Target:** Connect Claude model via Anthropic Python SDK with structured tool use.
- **Deliverables:** Register security tools (`check_scope`, `compare_access`), implement agent loop, inject anti-hallucination prompts.
- **Classification:** **[MVP - REQUIRED]**
- *Advanced Extension:* Dynamic multi-step attack chain hypothesis generation. **[ADVANCED]**

### Phase 6: Evidence Validation & Finding Storage
- **Target:** Cryptographic proof generation and persistence.
- **Deliverables:** Redact tokens/passwords, compute SHA-256 evidence signatures, store in SQLite via `FindingRepository`.
- **Classification:** **[MVP - REQUIRED]**

### Phase 7: Severity Engine & Remediation Generator
- **Target:** Calculate sensitivity-aware vulnerability severity and code patches.
- **Deliverables:** Risk calculator factoring data sensitivity (PII/Financial) and privilege gained; AI-generated code patches (Express middleware, authorization guards).
- **Classification:** **[MVP - REQUIRED]**

### Phase 8: Automated Retesting Engine
- **Target:** One-click retest of confirmed vulnerabilities.
- **Deliverables:** `RetestEngine` that re-runs the exact recorded non-destructive vector and validates whether the access discrepancy is resolved.
- **Classification:** **[MVP - REQUIRED]**

### Phase 9: Security Dashboard Integration (Streamlit)
- **Target:** Visual interface for security operators.
- **Deliverables:** Dark navy SaaS dashboard featuring Metrics Overview, Discovered Endpoints, Findings Cards, Evidence Diff Viewer, and Retest Console.
- **Classification:** **[MVP - REQUIRED]**

### Phase 10: End-to-End Testing & Hackathon Demonstration
- **Target:** Polished live demo and verification.
- **Deliverables:** Automated demonstration script showing Juice Shop BOLA discovery, evidence inspection, AI remediation patch display, and retest verification.
- **Classification:** **[MVP - REQUIRED]**

