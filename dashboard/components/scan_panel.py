"""Dashboard Component: Scan Configuration & Execution Console."""

import streamlit as st


def render_scan_panel():
    """Renders the scan configuration controls and execution monitor."""
    st.subheader("Autonomous Penetration Testing Console")

    with st.form("scan_config_form"):
        target_url = st.text_input("Target Base URL", value="http://localhost:3000", disabled=True)
        st.caption("🔒 Target locked to authorized local OWASP Juice Shop scope.")

        test_roles = st.multiselect(
            "Personas to Include in Differential Matrix",
            ["Anonymous", "User A (Victim)", "User B (Attacker)", "Admin"],
            default=["Anonymous", "User A (Victim)", "User B (Attacker)"]
        )

        scan_depth = st.selectbox(
            "Scan Depth",
            ["Standard (OpenAPI Routes & Known IDOR Paths)", "Deep (Multi-Endpoint Attack Chaining)"]
        )

        submit = st.form_submit_button("Initiate Autonomous Scan")

    if submit:
        st.info("Scan trigger initiated. Security engine executing differential test suite...")
        # TODO (Phase 9): Connect to background scan runner

