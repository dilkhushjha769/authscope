"""Dashboard Component: One-Click Retesting & Verification Console."""

import streamlit as st
from typing import List
from backend.storage.models import FindingRecord


def render_retest_panel(findings: List[FindingRecord]):
    """Renders one-click retesting controls and regression status."""
    st.subheader("Automated Retesting & Patch Verification")

    if not findings:
        st.info("No confirmed findings to retest.")
        return

    st.write("Execute non-destructive differential verification to confirm whether developers have remediated the vulnerability.")

    for finding in findings:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"**{finding.title}** (`{finding.target_endpoint}`)")
            st.caption(f"Current Status: `{finding.status}`")
        with col2:
            if st.button(f"Retest Finding", key=f"retest_btn_{finding.id}"):
                st.info(f"Re-executing test vector against {finding.target_endpoint}...")
                # TODO (Phase 8): Connect to RetestEngine

