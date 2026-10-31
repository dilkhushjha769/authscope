# Changelog

All notable changes to the **AuthScope** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-31

### Added
- **Project Foundation:** Initial repository architecture, folder structure, and development configurations.
- **Root Documentation:** `README.md`, `AGENTS.md`, `SKILL.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CHANGELOG.md`.
- **System Architecture Docs:**
  - `docs/PROJECT_OVERVIEW.md`
  - `docs/SYSTEM_ARCHITECTURE.md` (Mermaid architectural flows & trust boundaries)
  - `docs/DATA_FLOW.md`
  - `docs/DEVELOPMENT_GUIDE.md`
  - `docs/API_CONTRACTS.md` (Typed Python interfaces and Pydantic schemas)
  - `docs/SECURITY_RULES.md`
  - `docs/SCOPE_AND_AUTHORIZATION.md`
  - `docs/VULNERABILITY_DETECTION.md`
  - `docs/AI_AGENT_BEHAVIOR.md`
  - `docs/DATABASE_SCHEMA.md`
  - `docs/TESTING_STRATEGY.md`
  - `docs/TEAM_RESPONSIBILITIES.md` (4-member team breakdown)
  - `docs/HACKATHON_ROADMAP.md` (10-phase execution plan)
- **Modular Domain Skills:**
  - `skills/security-testing/SKILL.md`
  - `skills/python-development/SKILL.md`
  - `skills/ai-agent-development/SKILL.md`
  - `skills/frontend-dashboard/SKILL.md`
  - `skills/integration-testing/SKILL.md`
- **Scaffolded Python Packages:**
  - `backend/core/` (`scope_guard`, `target_manager`, `session_manager`)
  - `backend/scanner/` (`endpoint_discovery`, `request_executor`, `response_analyzer`, `authorization_tester`)
  - `backend/agent/` (`agent`, `tools`, `prompts`, `finding_analyzer`, `attack_chain`)
  - `backend/analysis/` (`evidence_validator`, `severity_engine`, `remediation`)
  - `backend/storage/` (`database`, `models`, `finding_repository`)
  - `backend/retesting/` (`retest_engine`)
  - `backend/utils/` (`logger`, `helpers`)
- **Dashboard UI Prototype:**
  - `dashboard/app.py` with multi-page components (`overview`, `scan_panel`, `findings`, `evidence_viewer`, `retest_panel`).
- **Initial Test Suite:**
  - `tests/conftest.py` and unit test stubs for scope guard, request executor, authorization, evidence, agent, and retesting.
- **Environment & Scripts:**
  - `requirements.txt`, `.env.example`, `.gitignore`, `pytest.ini`, `scripts/setup_environment.py`, and `scripts/run_juice_shop.sh`.

