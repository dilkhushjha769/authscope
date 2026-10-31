"""Dashboard Component: Security Posture Overview & Metrics."""

import streamlit as st
from typing import List
from backend.storage.models import FindingRecord


def render_overview(findings: List[FindingRecord]):
    """Renders high-level metrics and vulnerability distribution cards."""
    st.subheader("Security Posture Overview")

    col1, col2, col3, col4 = st.columns(4)
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    retested_count = sum(1 for f in findings if f.status == "remediated")

    with col1:
        st.metric("Total Findings", total_findings)
    with col2:
        st.metric("Critical Flaws", critical_count)
    with col3:
        st.metric("High Flaws", high_count)
    with col4:
        st.metric("Remediated", retested_count)

    st.markdown("---")
    st.info("System initialized in Hard-Scoped Mode. Authorized Target: `http://localhost:3000` (OWASP Juice Shop).")

