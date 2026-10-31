"""AuthScope Operator Dashboard — Main Streamlit Application."""

import streamlit as st
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord
from backend.analysis.severity_engine import SeverityLevel
from dashboard.components.overview import render_overview
from dashboard.components.scan_panel import render_scan_panel
from dashboard.components.findings import render_findings_list
from dashboard.components.evidence_viewer import render_evidence_viewer
from dashboard.components.retest_panel import render_retest_panel

# Configure Streamlit Page
st.set_page_config(
    page_title="AuthScope | Security Testing Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark Navy Styling
st.markdown("""
<style>
    .main {
        background-color: #0B0F19;
        color: #F3F4F6;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 16px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        background-color: #1F2937;
        border-radius: 6px;
        color: #9CA3AF;
    }
    .stTabs [aria-selected="true"] {
        background-color: #3B82F6 !important;
        color: #FFFFFF !important;
    }
</style>
""", unsafe_allow_html=True)


def load_findings():
    """Fetches findings from database or returns initial sample demonstration finding."""
    repo = FindingRepository()
    records = repo.list_findings()
    if not records:
        # Provide sample baseline record for dashboard initialization
        return [
            FindingRecord(
                id="fnd_sample_01",
                scan_id="scn_init_01",
                title="BOLA / IDOR in Shopping Basket Access",
                vulnerability_type="BOLA_IDOR",
                severity=SeverityLevel.HIGH,
                status="confirmed",
                target_endpoint="/rest/basket/1",
                http_method="GET",
                description="User B was able to access User A's private shopping basket contents by manipulating the basket identifier parameter.",
                remediation_guidance="// Verify resource ownership\nif (req.user.id !== basket.UserId) {\n    return res.status(403).json({ error: 'Access Denied' });\n}"
            )
        ]
    return records


def main():
    st.title("🛡️ AuthScope Security Testing Console")
    st.caption("Authorized, Hard-Scoped AI Penetration Testing Agent | Target: OWASP Juice Shop (localhost:3000)")

    findings = load_findings()

    tab_overview, tab_scan, tab_findings, tab_evidence, tab_retest = st.tabs([
        "📊 Overview",
        "🎯 Scan Console",
        "🔍 Findings Explorer",
        "📑 Evidence Viewer",
        "🔄 Retest & Verify"
    ])

    with tab_overview:
        render_overview(findings)

    with tab_scan:
        render_scan_panel()

    with tab_findings:
        render_findings_list(findings)

    with tab_evidence:
        render_evidence_viewer(findings)

    with tab_retest:
        render_retest_panel(findings)


if __name__ == "__main__":
    main()

