"""AuthScope Dashboard — Cryptographic Evidence & Route Inspection Component."""

from typing import Dict, List, Optional
import streamlit as st

from backend.storage.models import EndpointModel, FindingRecord


def render_endpoint_explorer(
    endpoints: List[EndpointModel],
    findings: List[FindingRecord],
) -> None:
    """Renders tabular attack surface endpoint discovery with associated findings."""
    st.markdown(
        """
        <div style="margin-top:10px; margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Attack Surface Route Discovery</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Safe, non-destructive route enumeration</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not endpoints:
        st.info("No endpoints enumerated for this assessment session.")
        return

    findings_by_id: Dict[str, FindingRecord] = {f.id: f for f in findings}

    col_srch, col_filt = st.columns([2, 1])
    with col_srch:
        search_query = st.text_input("Filter endpoints by path or pattern", placeholder="/rest/...")
    with col_filt:
        filter_findings_only = st.checkbox("Show only endpoints with findings", value=False)

    displayed_endpoints = [
        ep
        for ep in endpoints
        if (not search_query or search_query.lower() in ep.path.lower())
        and (not filter_findings_only or len(ep.associated_finding_ids) > 0)
    ]

    st.caption(f"Displaying {len(displayed_endpoints)} of {len(endpoints)} enumerated attack surface paths.")

    for ep in displayed_endpoints:
        assoc_count = len(ep.associated_finding_ids)
        badge_color = "#EF4444" if assoc_count > 0 else "#64748B"
        badge_text = f"{assoc_count} Finding(s)" if assoc_count > 0 else "Clean Baseline"

        with st.container():
            st.markdown(
                f"""
                <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; margin-bottom:6px; background-color:#1E293B; border-radius:4px; border-left:3px solid {badge_color};">
                    <div>
                        <code style="color:#38BDF8; font-weight:700;">{ep.method}</code>
                        <span style="font-family:monospace; color:#F8FAFC; margin-left:8px;">{ep.path}</span>
                    </div>
                    <div>
                        <span style="background-color:#0F172A; color:{badge_color}; border:1px solid {badge_color}; font-weight:600; font-size:0.75rem; padding:2px 6px; border-radius:3px;">
                            {badge_text}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if assoc_count > 0:
            with st.expander(f"Associated Findings for {ep.method} {ep.path} ({assoc_count})"):
                for fid in ep.associated_finding_ids:
                    f_rec = findings_by_id.get(fid)
                    if f_rec:
                        sev_val = getattr(f_rec.severity, "value", f_rec.severity)
                        st.markdown(
                            f"- **`{f_rec.id}`** — **{f_rec.title}** (`{sev_val}` | `{f_rec.validation_status}` | `{f_rec.access_verdict}`)"
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
            val_status_str = getattr(evi.validation_status, "value", evi.validation_status)
            test_role_str = getattr(evi.test_role, "value", evi.test_role)
            auth_role_str = getattr(evi.authorized_role, "value", evi.authorized_role)
            st.markdown(
                f"**Validation Status:** `{val_status_str}` | "
                f"**Test Role:** `{test_role_str}` | **Authorized Role:** `{auth_role_str}`"
            )
            st.code(
                f"{evi.request_method} {evi.request_url}\n"
                f"Headers: {evi.sanitized_request_headers}\n\n"
                f"HTTP/1.1 {evi.response_status}\n"
                f"{evi.sanitized_response_evidence}",
                language="json",
            )
