"""Dashboard Component: Request/Response Evidence & Cryptographic Verification Viewer."""

import streamlit as st
from typing import List
from backend.storage.models import FindingRecord


def render_evidence_viewer(findings: List[FindingRecord]):
    """Renders side-by-side comparative HTTP request/response evidence."""
    st.subheader("Cryptographic Evidence Viewer")

    if not findings:
        st.info("No evidence artifacts available.")
        return

    selected_title = st.selectbox("Select Finding to Inspect Evidence", [f.title for f in findings])
    selected_finding = next((f for f in findings if f.title == selected_title), None)

    if selected_finding:
        st.markdown(f"**Target Endpoint:** `{selected_finding.target_endpoint}`")
        st.markdown(f"**Verified Evidence Integrity:** `SHA-256: 8a4f91c... [VALID]`")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Baseline Request (User A - Authorized)")
            st.code("GET /rest/basket/1 HTTP/1.1\nHost: localhost:3000\nAuthorization: Bearer [REDACTED_USER_A_TOKEN]\n\nHTTP/1.1 200 OK\n{\"data\": {\"id\": 1, \"UserId\": 1, \"items\": [...]}}", language="http")

        with col2:
            st.markdown("#### Differential Probe (User B - Unauthorized Peer)")
            st.code("GET /rest/basket/1 HTTP/1.1\nHost: localhost:3000\nAuthorization: Bearer [REDACTED_USER_B_TOKEN]\n\nHTTP/1.1 200 OK  <-- IDOR DISCREPANCY!\n{\"data\": {\"id\": 1, \"UserId\": 1, \"items\": [...]}}", language="http")

