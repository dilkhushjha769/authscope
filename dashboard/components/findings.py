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
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import SessionManager
from backend.retesting.retest_engine import RetestEngine
from backend.storage.finding_repository import FindingRepository


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

        # Render Multi-Endpoint Attack Chain Details if present
        tech_details = finding.technical_details or {}
        if "chain_id" in tech_details or "steps" in tech_details:
            with st.expander("🔗 Multi-Endpoint Attack-Chain Telemetry & Step Sequence", expanded=True):
                col_ch1, col_ch2, col_ch3 = st.columns(3)
                with col_ch1:
                    st.markdown(f"**Chain ID:** `{(tech_details.get('chain_id') or finding.id)}`")
                    st.markdown(f"**Scenario:** `{tech_details.get('scenario', finding.vulnerability_type)}`")
                with col_ch2:
                    steps_list = tech_details.get("steps") or []
                    st.markdown(f"**Step Count:** `{len(steps_list)}`")
                    st.markdown(f"**Vulnerable Step:** `{(tech_details.get('vulnerable_step_id') or 'N/A')}`")
                with col_ch3:
                    risk_meta = tech_details.get("risk_assessment") or {}
                    st.markdown(f"**Severity Rating:** `{risk_meta.get('severity', sev_str)}`")
                    st.markdown(f"**Confidence:** `{risk_meta.get('confidence', 'CONFIRMED')}`")

                st.markdown("##### Ordered Execution Sequence")
                for s in steps_list:
                    s_id = s.get("step_id", "step")
                    s_meth = s.get("method", "GET")
                    s_ep = s.get("endpoint_path") or s.get("endpoint") or ""
                    s_role = s.get("role_used") or s.get("role") or ""
                    s_code = s.get("status_code", 0)
                    s_verdict = s.get("verdict", "")
                    s_icon = "🔴" if "CONFIRMED" in s_verdict or "UNAUTHORIZED" in s_verdict else ("🟢" if "ALLOWED" in s_verdict or "DENIED" in s_verdict else "⚪")
                    st.markdown(
                        f"- {s_icon} **`{s_id}`** `[{s_role}]` `{s_meth} {s_ep}` → **HTTP {s_code}** ({s_verdict})"
                    )
                    if s.get("actual_behavior"):
                        st.caption(f"  Observed: {s['actual_behavior']}")

                ctx = tech_details.get("extracted_context") or {}
                if ctx:
                    st.markdown("##### Bound Context Identifiers")
                    st.json(ctx)

        if finding.evidence and finding.evidence.sanitized_response_evidence:
            with st.expander("📄 Raw Differential Telemetry (Sanitized)", expanded=False):
                st.markdown(f"**Fingerprint (SHA-256):** `{finding.evidence.evidence_sha256}`")
                st.markdown(f"**Request:** `{finding.evidence.request_method} {finding.evidence.request_url}`")
                st.code(finding.evidence.sanitized_response_evidence, language="json")


def render_findings_list(
    findings: List[FindingRecord],
    query_adapter: Optional[AssessmentQueryAdapter] = None,
    scan_id: Optional[str] = None,
    repository: Optional[FindingRepository] = None,
    scope_guard: Optional[ScopeGuard] = None,
    session_manager: Optional[SessionManager] = None,
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
    status_counts = {"FIXED": 0, "STILL VULNERABLE": 0, "PARTIALLY FIXED": 0, "INCONCLUSIVE": 0, "NOT_TESTED": 0}
    for item in findings:
        current = str(item.retest_status or "NOT_TESTED").upper()
        status_counts[current if current in status_counts else "NOT_TESTED"] += 1
    metric_cols = st.columns(5)
    metric_cols[0].metric("Issues found", len(findings))
    metric_cols[1].metric("Fixed", status_counts["FIXED"])
    metric_cols[2].metric("Still vulnerable", status_counts["STILL VULNERABLE"])
    metric_cols[3].metric("Partially fixed", status_counts["PARTIALLY FIXED"])
    metric_cols[4].metric("Need investigation", status_counts["INCONCLUSIVE"] + status_counts["NOT_TESTED"])
    if not confirmed:
        st.caption("0 confirmed vulnerabilities identified in active assessment.")
    else:
        for finding in confirmed:
            _render_single_finding_card(finding, is_confirmed=True)
            if repository and scope_guard and session_manager and st.button("Verify Fix", key=f"verify_fix_{finding.id}"):
                session = repository.get_scan_session(finding.scan_id)
                if not session:
                    st.error("Assessment session is unavailable; verification was not run.")
                else:
                    with st.spinner("Rechecking the original scoped GET authorization test…"):
                        result = RetestEngine(
                            repository=repository,
                            scope_guard=scope_guard,
                            session_manager=session_manager,
                            base_url=session.target_url,
                        ).retest_finding(finding.id)
                        repository.save_retest_result(result)
                    st.session_state[f"verification_result_{finding.id}"] = result.model_dump(mode="json")
                    st.rerun()
            _render_verification(finding, repository)

    st.markdown("##### ⚠️ Suspicious Observations & Discrepancies (Unconfirmed)")
    if not suspicious:
        st.caption("0 suspicious results recorded.")
    else:
        for finding in suspicious:
            _render_single_finding_card(finding, is_confirmed=False)


def _render_verification(finding: FindingRecord, repository: Optional[FindingRepository]) -> None:
    """Displays persisted verification comparison and assessment-local history."""
    latest = st.session_state.get(f"verification_result_{finding.id}")
    if repository:
        history = repository.get_retest_history(finding.id)
        if history:
            latest = history[0].model_dump(mode="json")
    if not latest:
        return
    st.markdown(f"**Fix verification:** `{latest.get('new_status', 'INCONCLUSIVE')}`")
    st.info(latest.get("summary") or latest.get("notes") or "No explanation was recorded.")
    detail = latest.get("differential_result") or {}
    before = detail.get("before")
    after = detail.get("after")
    if before or after:
        st.json({"before_fix": before, "after_fix": after, "remaining_concerns": detail.get("regression_checks")})
    if latest.get("new_status") == "FIXED":
        st.success("The deterministic authorization comparison supports that this tested issue is fixed.")
    elif latest.get("new_status") in {"STILL VULNERABLE", "PARTIALLY FIXED"}:
        st.error("The tested issue remains reproducible or has a remaining tested path.")
