# AuthScope: Data Flow & Lifecycle

This document describes how data enters, transitions through, and persists across AuthScope's components.

---

## 1. End-to-End Execution Flow

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Security Operator
    participant UI as Streamlit Dashboard
    participant Agent as Claude 3.5 Sonnet Agent
    participant Tools as Agent Tool Layer
    participant Guard as ScopeGuard
    participant Session as SessionManager
    participant Exec as RequestExecutor
    participant Target as OWASP Juice Shop
    participant Tester as AuthorizationTester
    participant Val as EvidenceValidator
    participant DB as SQLite DB

    Operator->>UI: Start Scan (Target: http://localhost:3000)
    UI->>DB: Create ScanSession (status="RUNNING")
    UI->>Agent: Run Autonomous Scan Task
    Agent->>Session: Ensure Active Sessions (Anon, UserA, UserB, Admin)
    Session->>Exec: Authenticate Test Personas
    Exec->>Target: POST /api/Users/login
    Target-->>Exec: 200 OK (JWT Tokens)
    Exec-->>Session: Return Tokens (Stored in Memory)

    Agent->>Tools: Discover Endpoints (e.g., /rest/basket/{id})
    Tools->>Guard: Validate Base URL Scope
    Guard-->>Tools: Scope Confirmed
    Tools-->>Agent: Discovered 12 candidate routes

    loop For Candidate Endpoints
        Agent->>Tools: compare_access(endpoint, method, param_matrix)
        Tools->>Guard: Validate Full Target URL
        Guard-->>Tools: Target Permitted
        Tools->>Tester: Execute Role-Differential Requests
        Tester->>Exec: GET /rest/basket/1 with UserB Token
        Exec->>Target: HTTP GET /rest/basket/1
        Target-->>Exec: 200 OK (User A's Cart Data - IDOR!)
        Exec-->>Tester: Raw Response
        Tester->>Val: Validate Evidence (UserB accessed UserA's basket)
        Val->>Val: Redact Bearer Tokens & Compute SHA-256 Hash
        Val-->>Tester: Validated Evidence Object
        Tester-->>Tools: Differential Discrepancy Found
        Tools-->>Agent: Structured Finding Data
        Agent->>Tools: save_finding(finding_spec)
        Tools->>DB: INSERT into findings & evidence tables
    end

    Agent->>UI: Scan Completed (N Findings Found)
    UI->>DB: Update ScanSession (status="COMPLETED")
    Operator->>UI: View Findings & Trigger Retest
```

---

## 2. Data Transformation States

### State 1: Discovery Input
- Raw OpenAPI JSON / HTML crawling routes / configured endpoint lists.
- Normalized into `DiscoveredEndpoint` models with path parameters (e.g., `{id}`).

### State 2: Request Execution Context
- `ExecutionContext`: Role identity (`UserA`, `UserB`, `Admin`, `Anonymous`), target URL, HTTP method, headers, JSON body, query parameters.
- Evaluated against `ScopeGuard` rules prior to transmission.

### State 3: Raw HTTP Exchange
- Raw HTTP request wire bytes (method, full URL, headers, body).
- Raw HTTP response wire bytes (status code, headers, body, latency).

### State 4: Normalized Evidence Object
- Authentication headers and sensitive tokens replaced with `[REDACTED_BEARER_TOKEN]`.
- Response payloads parsed and summarized.
- Checksum computed via SHA-256 (`evidence_hash`).

### State 5: Persisted Finding Record
- Pydantic `FindingRecord` stored in SQLite containing:
  - Finding UUID
  - Vulnerability Type (e.g., `BOLA_IDOR`, `BFLA`)
  - Target Endpoint & Method
  - Discrepancy Matrix (Status codes & response hashes per role)
  - Severity (CVSS + Data sensitivity)
  - Claude Reasoned Explanation
  - Remediation Patch Guidance
  - Non-destructive reproduction steps

