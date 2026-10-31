"""Dashboard Component: Findings Explorer & Vulnerability Cards."""

import streamlit as st
from typing import List
from backend.storage.models import FindingRecord


def render_findings_list(findings: List[FindingRecord]):
    """Renders interactive finding cards with severity badges and remediation."""
    st.subheader("Discovered Vulnerabilities")

    if not findings:
        st.info("No vulnerabilities recorded yet. Run a scan from the Scan Console to begin testing.")
        return

    for finding in findings:
        badge_color = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪"
        }.get(finding.severity.value, "⚪")

        with st.expander(f"{badge_color} [{finding.severity.value}] {finding.title} — {finding.target_endpoint}"):
            st.markdown(f"**Vulnerability Type:** `{finding.vulnerability_type}`")
            st.markdown(f"**HTTP Method:** `{finding.http_method}`")
            st.markdown(f"**Status:** `{finding.status.upper()}`")
            st.markdown(f"**Description:** {finding.description}")

            st.markdown("#### Recommended Remediation")
            st.code(finding.remediation_guidance, language="javascript")

