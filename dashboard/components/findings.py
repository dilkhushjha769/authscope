"""AuthScope Dashboard — Security Findings Presentation Component.

Renders security findings categorized by severity, validation state, and access verdict.
Displays full technical impact, root-cause explanations, and retest states.
"""

from typing import List, Optional
import streamlit as st

from backend.core.assessment_engine import AssessmentQueryAdapter
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.models import (
    EvidenceValidationStatus,
    FindingRecord,
    SeverityLevel,
)


def _render_single_finding_card(finding: FindingRecord, is_confirmed: bool = True) -> None:
    """Renders a structured, visually distinct finding card with complete telemetry."""
    sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    sev_colors = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MEDIUM": "#F59E0B",
        "LOW": "#3B82F6",
        "INFO": "#94A3B8",
        "INFORMATIONAL": "#94A3B8",
    }
    border_color = sev_colors.get(sev_str.upper(), "#64748B")

    with st.container():
        st.markdown(
            f"""
            <div style="border-left: 4px solid {border_color}; padding: 10px 14px; margin-bottom: 12px; background-color: #1E293B; border-radius: 4px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:700; font-size:1.05rem; color:#F8FAFC;">{finding.title}</span>
                    <span style="background-color:{border_color}; color:#FFFFFF; font-weight:700; padding:2px 8px; border-radius:3px; font-size:0.75rem;">
                        {sev_str.upper()}
                    </span>
                </div>
                <div style="color:#94A3B8; font-size:0.83rem; margin-top:4px;">
                    Finding ID: <code>{finding.id}</code> · Target: <code>{finding.target_endpoint}</code> ({finding.http_method})
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_meta1, col_meta2, col_meta3 = st.columns(3)
        with col_meta1:
            st.markdown(f"**Validation Status:** `{finding.validation_status}`")
            st.markdown(f"**Access Verdict:** `{finding.access_verdict}`")
            st.markdown(f"**Vulnerability Class:** `{finding.vulnerability_type}`")
        with col_meta2:
            st.markdown(f"**Endpoint:** `{finding.http_method} {finding.target_endpoint}`")
            st.markdown(f"**Resource ID:** `{finding.resource_id or 'N/A (Non-parameterized)'}`")
            st.markdown(f"**Retest Status:** `{finding.retest_status}`")
        with col_meta3:
            if finding.evidence:
                test_role_val = getattr(finding.evidence.test_role, "value", finding.evidence.test_role)
                auth_role_val = getattr(finding.evidence.authorized_role, "value", finding.evidence.authorized_role)
                st.markdown(f"**Tested Role:** `{test_role_val}`")
                st.markdown(f"**Authorized Role:** `{auth_role_val}`")
                st.markdown(f"**HTTP Status:** `{finding.evidence.response_status}`")
            else:
                st.markdown("**Evidence Artifact:** `Not Attached`")

        st.markdown("---")
        col_beh1, col_beh2 = st.columns(2)
        with col_beh1:
            st.markdown("**Expected Security Behavior**")
            st.info(finding.expected_behavior or "Unauthorized requests should be denied with HTTP 401/403.")
        with col_beh2:
            st.markdown("**Actual Observed Behavior**")
            if is_confirmed:
                st.error(finding.actual_behavior or finding.description)
            else:
                st.warning(finding.actual_behavior or finding.description)

        if finding.remediation_guidance:
            with st.expander("🛠️ Prescriptive Server-Side Remediation Guidance", expanded=False):
                st.markdown(finding.remediation_guidance)

        if finding.evidence and finding.evidence.sanitized_response_evidence:
            with st.expander("📄 Raw Differential Telemetry (Sanitized)", expanded=False):
                st.markdown(f"**Fingerprint (SHA-256):** `{finding.evidence.evidence_sha256}`")
                st.markdown(f"**Request:** `{finding.evidence.request_method} {finding.evidence.request_url}`")
                st.code(finding.evidence.sanitized_response_evidence, language="json")


def render_findings_list(
    findings: List[FindingRecord],
    query_adapter: Optional[AssessmentQueryAdapter] = None,
    scan_id: Optional[str] = None,
) -> None:
    """Renders findings strictly separated into Confirmed Vulnerabilities and Suspicious Results."""
    confirmed = [
        f
        for f in findings
        if f.validation_status == EvidenceValidationStatus.CONFIRMED.value
        and f.access_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
    ]
    suspicious = [f for f in findings if f not in confirmed]

    col_hdr, col_exp1, col_exp2 = st.columns([3, 1, 1])
    with col_hdr:
        st.markdown(
            f"""
            <div style="margin-bottom:8px;">
                <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Security Findings &amp; Validation Matrix</span>
                <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">
                    {len(confirmed)} Confirmed · {len(suspicious)} Suspicious
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    if query_adapter and scan_id:
        with col_exp1:
            json_report = query_adapter.export_report_json(scan_id)
            st.download_button(
                label="⬇️ Export JSON",
                data=json_report,
                file_name=f"authscope_report_{scan_id}.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_exp2:
            md_report = query_adapter.export_report_markdown(scan_id)
            st.download_button(
                label="⬇️ Export MD",
                data=md_report,
                file_name=f"authscope_report_{scan_id}.md",
                mime="text/markdown",
                use_container_width=True,
            )

    st.markdown("##### 🚨 Confirmed Vulnerabilities (Independently Verified)")
    if not confirmed:
        st.caption("0 confirmed vulnerabilities identified in active assessment.")
    else:
        for finding in confirmed:
            _render_single_finding_card(finding, is_confirmed=True)

    st.markdown("##### ⚠️ Suspicious Observations & Discrepancies (Unconfirmed)")
    if not suspicious:
        st.caption("0 suspicious results recorded.")
    else:
        for finding in suspicious:
            _render_single_finding_card(finding, is_confirmed=False)
