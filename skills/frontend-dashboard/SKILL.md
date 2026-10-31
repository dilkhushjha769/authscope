---
name: frontend-dashboard
description: Guidelines for building the professional Streamlit cybersecurity dashboard.
version: 1.0.0
---

# Frontend Dashboard Skill: Streamlit Cybersecurity UI/UX

This skill guides the design and implementation of the AuthScope operator console using Streamlit.

---

## 1. Design Direction: Professional Cybersecurity SaaS

- **Color Palette:**
  - Primary Background: Deep dark navy (`#0B0F19`, `#111827`)
  - Surface Cards: Solid slate navy (`#1F2937`, `#1E293B`)
  - Accent Colors: Electric blue (`#3B82F6`) and restrained violet/purple (`#8B5CF6`)
  - Status Colors:
    - Critical: Crimson (`#EF4444`)
    - High: Orange (`#F97316`)
    - Medium: Amber (`#F59E0B`)
    - Low: Cyan (`#06B6D4`)
    - Info / Safe: Emerald (`#10B981`)
- **Aesthetic Principles:**
  - Clean, restrained, high-contrast typography.
  - Solid surfaces with 1px subtle borders (`#374151`).
  - No bloated gradients, glowing glassmorphism, or distracting animations.
  - Clear spacing, readable monospaced font blocks for HTTP payloads.

---

## 2. Dashboard Layout & Navigation

AuthScope features a multi-section operator console:
1. **Header / Scope Banner:** Prominently displays target base URL, active scope status, and connection health to OWASP Juice Shop.
2. **Navigation Tabs:**
   - **Overview:** Security posture metrics, vulnerability breakdown charts, active scan telemetry.
   - **Scan Console:** Target configuration, persona selection, start/stop scan controls.
   - **Findings Explorer:** Filterable list of detected vulnerabilities with severity badges, endpoint paths, and affected roles.
   - **Evidence Viewer:** Side-by-side comparative inspection of raw request and raw response payloads, highlighting token redactions and differential mismatches.
   - **Retest Console:** One-click automated retesting interface with historical verification status.

---

## 3. UI Component Architecture

- Create modular UI renderers in `dashboard/components/`:
  - `overview.py`: Metric cards (`st.metric`), severity distribution charts.
  - `scan_panel.py`: Form inputs, target selection, scan logs with `st.status`.
  - `findings.py`: Expandable card views (`st.expander`), severity tags, AI remediation code blocks.
  - `evidence_viewer.py`: Side-by-side code blocks (`st.code(language='http')`) for User A vs. User B.
  - `retest_panel.py`: Retest trigger buttons and verification result banners.
- Always handle:
  - **Empty States:** "No findings recorded yet. Run a scan to test target endpoints."
  - **Loading States:** Display spinners (`st.spinner`) and real-time progress bars during scans.
  - **Error States:** Display clean warning alerts (`st.error`) if Juice Shop is unreachable.

