"""Dashboard Component: Endpoint Explorer & Cryptographic Evidence Viewer."""

from typing import List, Optional
import streamlit as st

from backend.storage.models import DiscoveredEndpointRecord, FindingRecord


VERDICT_COLORS = {
    "CONFIRMED_UNAUTHORIZED_ACCESS": ("#EF4444", "#450A0A"),
    "SUSPICIOUS_ACCESS": ("#F59E0B", "#451A03"),
    "CORRECTLY_DENIED": ("#22C55E", "#052E16"),
    "ALLOWED_ACCESS": ("#3B82F6", "#172554"),
    "INCONCLUSIVE": ("#94A3B8", "#1E293B"),
}


def render_endpoint_explorer(
    endpoints: List[DiscoveredEndpointRecord],
    findings: Optional[List[FindingRecord]] = None,
) -> None:
    """Renders the Endpoint Explorer showing discovered routes, methods, test status, and associated findings."""
    st.markdown(
        f"""
        <div style="margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Endpoint Explorer</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">{len(endpoints)} discovered application routes</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not endpoints:
        st.markdown(
            """
            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:16px; color:#94A3B8; font-size:0.9rem;">
                No discovered endpoints recorded yet. Start an assessment to map target routes.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    findings_by_id = {f.id: f for f in (findings or [])}

    for ep in endpoints:
        verdict_str = ep.verdict or "NOT_EVALUATED"
        v_fg, v_bg = VERDICT_COLORS.get(verdict_str, ("#94A3B8", "#1E293B"))
        assoc_count = len(ep.associated_finding_ids)

        st.markdown(
            f"""
            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px 16px; margin-bottom:6px;">
                <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="background-color:#172554; color:#3B82F6; font-family:monospace; font-size:0.76rem; font-weight:700; padding:2px 8px; border-radius:4px;">{ep.method}</span>
                        <span style="color:#F9FAFB; font-family:monospace; font-weight:600; font-size:0.94rem;">{ep.path}</span>
                        <span style="background-color:#1E293B; color:#94A3B8; font-size:0.72rem; padding:2px 8px; border-radius:4px; font-family:monospace;">{ep.category}</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="background-color:#1E293B; color:#E5E7EB; font-size:0.72rem; padding:2px 8px; border-radius:4px; font-family:monospace;">Status: {ep.test_status}</span>
                        <span style="background-color:{v_bg}; color:{v_fg}; border:1px solid {v_fg}55; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; font-family:monospace;">{verdict_str}</span>
                        <span style="color:#94A3B8; font-size:0.78rem; font-family:monospace;">Findings: {assoc_count}</span>
                    </div>
                </div>
                <div style="color:#94A3B8; font-size:0.84rem; margin-top:6px;">
                    {ep.summary or ep.description}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if ep.associated_finding_ids:
            with st.expander(f"Associated Findings for {ep.method} {ep.path} ({assoc_count})"):
                for fid in ep.associated_finding_ids:
                    f_rec = findings_by_id.get(fid)
                    if f_rec:
                        st.markdown(
                            f"- **`{f_rec.id}`** — **{f_rec.title}** (`{f_rec.severity.value}` | `{f_rec.validation_status}` | `{f_rec.access_verdict}`)"
                        )
                    else:
                        st.markdown(f"- Finding ID: `{fid}`")


def render_evidence_viewer(findings: List[FindingRecord]) -> None:
    """Renders cryptographic SHA-256 evidence inspection for findings."""
    st.markdown(
        """
        <div style="margin-top:12px; margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Cryptographic Evidence Artifacts</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Sanitized HTTP telemetry &amp; SHA-256 verification</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with_evi = [f for f in findings if f.evidence is not None]
    if not with_evi:
        st.info("No signed evidence artifacts recorded for this assessment.")
        return

    for f in with_evi:
        evi = f.evidence
        if evi is None:
            continue
        with st.expander(f"Artifact {evi.finding_id} — {f.http_method} {f.target_endpoint} (SHA-256: {evi.evidence_sha256[:16]}...)", expanded=True):
            st.markdown(f"**Full SHA-256 Digest:** `{evi.evidence_sha256}`")
            st.markdown(
                f"**Validation Status:** `{evi.validation_status.value}` | "
                f"**Test Role:** `{evi.test_role.value}` | **Authorized Role:** `{evi.authorized_role.value}`"
            )
            st.code(
                f"{evi.request_method} {evi.request_url}\n"
                f"Headers: {evi.sanitized_request_headers}\n\n"
                f"HTTP/1.1 {evi.response_status}\n"
                f"{evi.sanitized_response_evidence}",
                language="json",
            )
