"""Dashboard Component: Assessment History & Security Posture Overview."""

from typing import Callable, List, Optional
import streamlit as st

from backend.storage.models import FindingRecord, ScanSessionRecord


SESSION_STATUS_COLORS = {
    "COMPLETED": ("#22C55E", "#052E16"),
    "RUNNING": ("#3B82F6", "#172554"),
    "FAILED": ("#EF4444", "#450A0A"),
    "CANCELLED": ("#F59E0B", "#451A03"),
}


def render_overview(
    findings: List[FindingRecord],
    sessions: Optional[List[ScanSessionRecord]] = None,
    on_select_session: Optional[Callable[[str], None]] = None,
) -> None:
    """Renders posture summary cards and the persisted Assessment History explorer."""
    st.markdown(
        """
        <div style="margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Assessment History &amp; Posture</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Persisted SQLite scan sessions, stages, endpoints &amp; findings</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    all_sessions = sessions or []
    confirmed_count = sum(1 for f in findings if f.validation_status == "CONFIRMED")
    suspicious_count = sum(1 for f in findings if f.validation_status != "CONFIRMED")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Stored Assessments", len(all_sessions))
    with col2:
        st.metric("Confirmed Findings", confirmed_count)
    with col3:
        st.metric("Suspicious Results", suspicious_count)
    with col4:
        latest_status = all_sessions[0].status if all_sessions else "IDLE"
        st.metric("Latest Run Status", latest_status)

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

    if not all_sessions:
        st.markdown(
            """
            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:16px; color:#94A3B8; font-size:0.9rem;">
                No historical assessments stored yet. Launch a scan from the Active Assessment view.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    for sess in all_sessions:
        fg, bg = SESSION_STATUS_COLORS.get(sess.status, ("#94A3B8", "#1E293B"))
        started_str = sess.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        col_card, col_btn = st.columns([5, 1])
        with col_card:
            st.markdown(
                f"""
                <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:12px 16px; margin-bottom:6px;">
                    <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span style="color:#F9FAFB; font-family:monospace; font-weight:600; font-size:0.94rem;">{sess.id}</span>
                            <span style="background-color:{bg}; color:{fg}; border:1px solid {fg}55; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; font-family:monospace;">{sess.status}</span>
                            <span style="color:#E5E7EB; font-family:monospace; font-size:0.84rem;">{sess.target_url}</span>
                        </div>
                        <span style="color:#94A3B8; font-family:monospace; font-size:0.78rem;">{started_str}</span>
                    </div>
                    <div style="color:#94A3B8; font-size:0.83rem; margin-top:6px;">
                        Routes Discovered: <code>{sess.endpoints_discovered_count}</code> ·
                        Routes Probed: <code>{sess.endpoints_tested_count}</code> ·
                        Confirmed: <code>{sess.confirmed_findings_count}</code> ·
                        Suspicious: <code>{sess.suspicious_results_count}</code>
                    </div>
                    <div style="color:#64748B; font-size:0.8rem; margin-top:4px;">{sess.summary_text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_btn:
            if on_select_session is not None:
                if st.button("Open Scan", key=f"hist_open_{sess.id}", use_container_width=True):
                    on_select_session(sess.id)
