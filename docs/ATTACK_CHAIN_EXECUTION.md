# Multi-Endpoint Attack-Chain Execution, Validation & Verification

This document specifies the execution, verification, evidence signing, deterministic severity assessment, and automated retesting architecture implemented for AuthScope's Multi-Endpoint Attack-Chain Testing System (Member 2 Responsibility).

---

## 1. Architecture Overview

While Member 1 generates candidate attack-chains through graph-based dependency analysis (`backend/agent/attack_chain.py`), Member 2 owns the safe, deterministic execution and verification layer (`backend/scanner/attack_chain_executor.py` and `backend/retesting/retest_engine.py`).

```
Candidate Attack Chain (Member 1)
                │
                ▼
   AttackChainValidator (Scope, Acyclic, Non-destructive checks)
                │ (Pass)
                ▼
   AttackChainExecutor (4-Role Session Dispatch)
      ├─ Step 1: Baseline Execution (User A / Owner)
      │     └─ Extract Context (IDs, Tokens, URLs)
      ├─ Step 2: Parameter Resolution & Variable Substitution
      ├─ Step 3: Cross-User Probe (User B / Anonymous / Admin)
      └─ Step 4: False-Positive Filtering (SPA HTML, Soft Errors)
                │
                ▼
        Access Verdict
    (CONFIRMED_UNAUTHORIZED_ACCESS)
                │
                ├─ EvidenceValidator: SHA-256 Signed Evidence Artifact
                ├─ SeverityEngine: Deterministic Anti-Inflation Scoring
                ├─ RemediationEngine: Framework-Specific Code Patches
                └─ FindingRepository: SQLite Storage (MULTI_STEP_CHAIN)
                │
                ▼
        RetestEngine (Automated Replay & Verification)
```

---

## 2. Four-Role Authorization Execution Model

Attack chains execute across four distinct roles without role confusion or session pollution:

| Role | Responsibility in Attack Chain |
|---|---|
| **Anonymous** | Evaluates whether sensitive multi-step sequences or child resources are accessible without any session tokens. |
| **User A (Resource Owner)** | Establishes the legitimate access baseline, discovering resources and populating the runtime context with verified IDs. |
| **User B (Attacker / Different Tenant)** | Replays the dependent step substituting User A's resource IDs into User B's authenticated session to prove BOLA/IDOR. |
| **Admin** | Executes administrative actions or provides the baseline for comparing vertical privilege escalation (BFLA). |

---

## 3. Strict Pre-Execution Validation (`AttackChainValidator`)

Every candidate attack chain must pass strict validation before any network request is issued:

1. **Hard ScopeGuard Boundary:** All target URLs and step paths are validated against allowlisted hosts (`localhost:3000`) and schemes (`http`). Out-of-scope targets are immediately rejected.
2. **Non-Destructive Enforcement:** Permitted methods are strictly `GET`, `POST`, `PUT`, `PATCH`, `HEAD`. `DELETE` and destructive keywords (`drop`, `truncate`, `wipe`, `destroy`) are blocked.
3. **Bounded Step Count:** Chains must contain between 2 and 5 steps.
4. **Acyclic Prerequisite Dependencies:** Dependencies must reference existing, prior step IDs. Cyclic or forward references are rejected.
5. **Session Availability:** Verified session tokens must exist for all roles required in the chain.

---

## 4. Parameter Binding & Context Propagation

Between steps, dynamic parameters are extracted from response bodies and substituted into downstream request templates:

- **Path Parameter Substitution:** `/api/orders/{id}` or `/rest/basket/:id` replaced with extracted `order_id` or `basket_id`.
- **Query Parameter Binding:** `?order_id={id}` resolved dynamically.
- **Header & Body Forwarding:** Extracted IDs bound to JSON payloads for modification verification.
- **Fail-Safe Pre-requisite Checks:** If Step 1 returns an error (HTTP 500/404), dependent Step 2 is automatically marked `BLOCKED` and skipped safely.

---

## 5. False-Positive Prevention & Evidence Signing

AuthScope enforces strict evidence-based criteria:

- **SPA HTML Fallbacks:** Single-page applications returning HTTP 200 with HTML (`<!doctype html>`) are rejected.
- **Soft Errors:** JSON responses containing error envelopes (`{"error": "Access Denied"}`) under HTTP 200 are recognized and classified as `CORRECTLY_DENIED`.
- **Cryptographic Evidence Artifacts:** Confirmed violations generate an `EvidenceArtifact` signed with a 64-character SHA-256 hash.
- **Secret Redaction:** Bearer tokens, JWT signatures, passwords, and emails are scrubbed before storage and display.

---

## 6. Automated Chain Retesting (`RetestEngine`)

Developers and security engineers can re-execute the exact attack chain via `RetestEngine.retest_attack_chain`:

1. Retrieves original chain telemetry and step bindings from `FindingRecord.technical_details["steps"]`.
2. Obtains fresh session credentials for all required roles.
3. Replays the attack chain sequence end-to-end against the authorized target.
4. Evaluates the resulting status:
   - **`FIXED`**: Baseline succeeded, but unauthorized cross-user attempt returned HTTP 401/403.
   - **`STILL VULNERABLE`**: Unauthorized cross-user attempt succeeded (HTTP 200).
   - **`INCONCLUSIVE`**: Target returned unexpected server errors or changed structure.

---

## 7. Streamlit Findings UI Integration

Attack chain findings are rendered with full forensic visibility:
- **Chain Summary Pill:** Displays Chain ID, Scenario, Total Steps, and Vulnerable Step.
- **Ordered Execution Sequence:** Step-by-step card showing HTTP Method, Path, Role, Status Code, and Verdict.
- **Context Identifiers:** Key-value pairs extracted and bound across steps.
- **Deterministic Risk & Remediation:** Displays CVSS/CWE/OWASP references alongside framework-specific code fixes.

