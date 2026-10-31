"""Dashboard Component: Findings Explorer & Confirmed vs. Suspicious Vulnerability Cards."""

from typing import List, Optional
import streamlit as st

from backend.analysis.evidence_validator import EvidenceValidationStatus
from backend.core.assessment_engine import AssessmentQueryAdapter
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.models import FindingRecord


SEVERITY_COLORS = {
    "CRITICAL": ("#EF4444", "#450A0A"),
    "HIGH": ("#F97316", "#431407"),
    "MEDIUM": ("#F59E0B", "#451A03"),
    "LOW": ("#3B82F6", "#172554"),
    "INFO": ("#94A3B8", "#1E293B"),
}


def _render_single_finding_card(finding: FindingRecord, is_confirmed: bool) -> None:
    """Renders an expandable card for a single confirmed or suspicious finding."""
    sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    sev_fg, sev_bg = SEVERITY_COLORS.get(sev_str, ("#94A3B8", "#1E293B"))

    val_fg = "#22C55E" if is_confirmed else "#F59E0B"
    val_bg = "#052E16" if is_confirmed else "#451A03"
    val_label = "CONFIRMED VULNERABILITY" if is_confirmed else "SUSPICIOUS ACCESS (REVIEW REQUIRED)"

    st.markdown(
        f"""
        <div style="background-color:#111827; border:1px solid {val_fg}55; border-radius:8px; padding:12px 16px; margin-bottom:4px;">
            <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="background-color:{sev_bg}; color:{sev_fg}; border:1px solid {sev_fg}66; font-size:0.74rem; font-weight:700; padding:2px 8px; border-radius:4px; font-family:monospace;">{sev_str}</span>
                    <span style="color:#F9FAFB; font-weight:600; font-size:0.96rem;">{finding.title}</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="background-color:{val_bg}; color:{val_fg}; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; font-family:monospace;">{val_label}</span>
                    <span style="color:#94A3B8; font-family:monospace; font-size:0.8rem;">{finding.http_method} {finding.target_endpoint}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander(f"Inspect Evidence & Remediation — {finding.id} ({finding.http_method} {finding.target_endpoint})", expanded=is_confirmed):
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
                st.markdown(f"**Tested Role:** `{finding.evidence.test_role.value}`")
                st.markdown(f"**Authorized Role:** `{finding.evidence.authorized_role.value}`")
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

        if finding.evidence:
            st.markdown("#### Cryptographic Evidence Summary")
            st.markdown(
                f"**SHA-256 Integrity Signature:** `{finding.evidence.evidence_sha256}`  \n"
                f"**Captured Timestamp:** `{finding.evidence.timestamp}`"
            )
            st.code(
                f"{finding.evidence.request_method} {finding.evidence.request_url}\n"
                f"Sanitized Headers: {finding.evidence.sanitized_request_headers}\n\n"
                f"HTTP {finding.evidence.response_status}\n"
                f"{finding.evidence.sanitized_response_evidence[:800]}",
                language="json",
            )

        st.markdown("#### Recommended Remediation")
        st.code(finding.remediation_guidance, language="javascript")


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
                label="⬇ Export JSON",
                data=json_report,
                file_name=f"authscope_report_{scan_id}.json",
                mime="application/json",
                key=f"dl_json_{scan_id}_{id(findings)}",
                use_container_width=True,
            )
        with col_exp2:
            md_report = query_adapter.export_report_markdown(scan_id)
            st.download_button(
                label="⬇ Export Markdown",
                data=md_report,
                file_name=f"authscope_report_{scan_id}.md",
                mime="text/markdown",
                key=f"dl_md_{scan_id}_{id(findings)}",
                use_container_width=True,
            )

    if not findings:
        st.markdown(
            """
            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:16px; color:#94A3B8; font-size:0.9rem;">
                No confirmed or suspicious findings recorded for this assessment.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Section 1: Confirmed Vulnerabilities
    st.markdown(
        f"##### 🔴 Confirmed Vulnerabilities (`{len(confirmed)}`)"
    )
    if not confirmed:
        st.caption(
            "0 confirmed vulnerabilities. AuthScope requires a verified cross-account baseline match and complete EvidenceValidator artifact before marking any finding CONFIRMED."
        )
    else:
        for finding in confirmed:
            _render_single_finding_card(finding, is_confirmed=True)

    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

    # Section 2: Suspicious Results
    st.markdown(
        f"##### 🟡 Suspicious Access Results (`{len(suspicious)}`)"
    )
    if not suspicious:
        st.caption("0 suspicious results recorded.")
    else:
        for finding in suspicious:
            _render_single_finding_card(finding, is_confirmed=False)
