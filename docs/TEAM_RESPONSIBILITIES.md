# AuthScope: Team Responsibilities & Ownership Matrix

To ensure clear division of labor, rapid execution, and seamless integration, AuthScope is divided across four specialized engineering roles.

---

## 1. Member 1: Backend & Security Engine Lead
**Focus:** Core security perimeter, HTTP execution, scope enforcement, and role-based differential testing.

### Primary Ownership
- `backend/core/scope_guard.py`
- `backend/core/target_manager.py`
- `backend/core/session_manager.py`
- `backend/scanner/request_executor.py`
- `backend/scanner/endpoint_discovery.py`
- `backend/scanner/authorization_tester.py`

### Key Deliverables
1. Hard-scoped URL allowlisting engine with zero egress leaks.
2. Robust `httpx` wrapper with redirect blocking and timeout safety.
3. Automated multi-role session token lifecycle manager (Juice Shop login).
4. Multi-role differential execution matrix engine.

### Collaboration Points
- Provides clean, typed callable interfaces to Member 2 (AI Agent tools).
- Coordinates with Member 4 on mock server fixtures and scope test coverage.

---

## 2. Member 2: AI Agent & Vulnerability Analysis Lead
**Focus:** Claude 3.5 Sonnet integration, tool calling, prompt engineering, attack chaining, and remediation synthesis.

### Primary Ownership
- `backend/agent/agent.py`
- `backend/agent/tools.py`
- `backend/agent/prompts.py`
- `backend/agent/finding_analyzer.py`
- `backend/agent/attack_chain.py`
- `backend/analysis/severity_engine.py`
- `backend/analysis/remediation.py`

### Key Deliverables
1. Anthropic SDK tool calling loop and schema definitions.
2. Structured system prompts with anti-hallucination guardrails.
3. Multi-endpoint attack chain correlation algorithm.
4. CVSS + data sensitivity severity calculator.
5. Production-ready code patch generation for detected flaws.

### Collaboration Points
- Consumes Python security tools created by Member 1.
- Supplies structured `FindingRecord` objects to Member 4 for database persistence.

---

## 3. Member 3: Dashboard & UI/UX Lead
**Focus:** Streamlit user interface, cybersecurity visualization, dark-theme styling, and operator workflow.

### Primary Ownership
- `dashboard/app.py`
- `dashboard/components/overview.py`
- `dashboard/components/scan_panel.py`
- `dashboard/components/findings.py`
- `dashboard/components/evidence_viewer.py`
- `dashboard/components/retest_panel.py`
- `dashboard/assets/`

### Key Deliverables
1. Professional dark navy cybersecurity console with restrained blue/purple accents.
2. Real-time scan telemetry and progress indicator.
3. Interactive findings card view with severity badges.
4. Side-by-side request/response evidence viewer with token redaction display.
5. Interactive one-click retest button with live diff comparison.

### Collaboration Points
- Queries `FindingRepository` developed by Member 4.
- Triggers scan and retest orchestrators built by Members 1 and 2.

---

## 4. Member 4: Storage, Testing, QA & Integration Lead
**Focus:** SQLite database, repository layer, cryptographic evidence validation, retesting engine, and CI/pytest.

### Primary Ownership
- `backend/storage/database.py`
- `backend/storage/models.py`
- `backend/storage/finding_repository.py`
- `backend/analysis/evidence_validator.py`
- `backend/retesting/retest_engine.py`
- `tests/*` (Full test suite)
- `scripts/setup_environment.py`

### Key Deliverables
1. SQLite schema initialization and migration scripts.
2. Pydantic models for cross-module type contracts.
3. Evidence validator with SHA-256 cryptographic signature generation.
4. Retest engine verifying reproducibility without re-scanning entire app.
5. Comprehensive test suite with high coverage across scope guards and differential logic.

### Collaboration Points
- Enforces contract compliance across all members' modules.
- Ensures zero regressions via automated test verification before releases.

