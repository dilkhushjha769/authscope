"""Dashboard Component: Target URL Input & 7-Stage Real-Time Agent Activity Timeline."""

from typing import Dict, List, Optional
import streamlit as st

from backend.core.scope_guard import ScopeCheckResult
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    STAGE_LABELS,
    ScanSessionRecord,
    StageStateRecord,
    StageStatus,
)


STATUS_BADGE_CONFIG: Dict[str, tuple[str, str, str]] = {
    StageStatus.WAITING.value: ("WAITING", "#64748B", "#1E293B"),
    StageStatus.RUNNING.value: ("RUNNING", "#3B82F6", "#172554"),
    StageStatus.COMPLETED.value: ("COMPLETED", "#22C55E", "#052E16"),
    StageStatus.FAILED.value: ("FAILED", "#EF4444", "#450A0A"),
    StageStatus.SKIPPED.value: ("SKIPPED", "#94A3B8", "#1E293B"),
}


def render_scope_validation_banner(target_url: str, scope_result: ScopeCheckResult) -> None:
    """Renders real-time ScopeGuard validation feedback and authorized-target indicator."""
    if scope_result.is_allowed:
        st.markdown(
            f"""
            <div style="background-color:#052E16; border:1px solid #22C55E; border-radius:8px; padding:10px 14px; margin-bottom:12px; display:flex; align-items:center; justify-content:space-between;">
                <div>
                    <span style="color:#22C55E; font-weight:600; font-size:0.88rem;">● AUTHORIZED TARGET VERIFIED</span>
                    <span style="color:#E5E7EB; font-size:0.88rem; margin-left:8px; font-family:monospace;">{target_url}</span>
                </div>
                <span style="color:#94A3B8; font-size:0.8rem;">ScopeGuard: {scope_result.reason}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div style="background-color:#450A0A; border:1px solid #EF4444; border-radius:8px; padding:10px 14px; margin-bottom:12px;">
                <div style="color:#EF4444; font-weight:600; font-size:0.88rem;">✖ TARGET REJECTED BY HARD SCOPE GUARD</div>
                <div style="color:#FCA5A5; font-size:0.84rem; margin-top:4px;">{scope_result.reason}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_stage_timeline(
    session: Optional[ScanSessionRecord],
    events: Optional[List[AssessmentEvent]] = None,
) -> None:
    """Renders the 7-stage Agent Activity Timeline with expandable operational event logs."""
    st.markdown(
        """
        <div style="margin-top:8px; margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Agent Activity Timeline</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Real-time operational stages &amp; telemetry</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if session is None:
        # Render idle 7-stage preview
        for idx, stg in enumerate(AssessmentStage, start=1):
            label = STAGE_LABELS[stg]
            st.markdown(
                f"""
                <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:10px 14px; margin-bottom:6px; display:flex; align-items:center; justify-content:space-between;">
                    <div>
                        <span style="color:#64748B; font-family:monospace; font-size:0.82rem; margin-right:8px;">0{idx}</span>
                        <span style="color:#94A3B8; font-weight:500; font-size:0.92rem;">{label}</span>
                    </div>
                    <span style="background-color:#1E293B; color:#64748B; font-size:0.74rem; font-weight:600; padding:2px 8px; border-radius:4px;">WAITING</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
        return

    all_events = events or []
    events_by_stage: Dict[str, List[AssessmentEvent]] = {}
    for evt in all_events:
        events_by_stage.setdefault(evt.stage, []).append(evt)

    for idx, stg in enumerate(AssessmentStage, start=1):
        stg_key = stg.value
        stg_rec: Optional[StageStateRecord] = session.stages.get(stg_key)
        if stg_rec is None:
            stg_rec = StageStateRecord(
                stage=stg,
                label=STAGE_LABELS[stg],
                status=StageStatus.WAITING,
                explanation="Waiting",
            )

        status_val = (
            stg_rec.status.value
            if isinstance(stg_rec.status, StageStatus)
            else str(stg_rec.status)
        )
        badge_text, fg_color, bg_color = STATUS_BADGE_CONFIG.get(
            status_val, ("WAITING", "#64748B", "#1E293B")
        )
        dur_text = f"{stg_rec.duration_ms:.1f} ms" if stg_rec.duration_ms is not None else "—"
        ts_text = stg_rec.started_at[11:19] + " UTC" if stg_rec.started_at and len(stg_rec.started_at) >= 19 else "—"

        stage_events = events_by_stage.get(stg_key, stg_rec.events)
        border_color = fg_color if status_val in ("running", "failed") else "#1E293B"

        st.markdown(
            f"""
            <div style="background-color:#111827; border:1px solid {border_color}; border-radius:8px; padding:12px 16px; margin-bottom:4px;">
                <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="color:#64748B; font-family:monospace; font-size:0.82rem;">0{idx}</span>
                        <span style="color:#F9FAFB; font-weight:600; font-size:0.95rem;">{stg_rec.label}</span>
                        <span style="background-color:{bg_color}; color:{fg_color}; border:1px solid {fg_color}44; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; font-family:monospace;">{badge_text}</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:14px; color:#94A3B8; font-size:0.78rem; font-family:monospace;">
                        <span>Started: {ts_text}</span>
                        <span>Duration: {dur_text}</span>
                        <span>Events: {len(stage_events)}</span>
                    </div>
                </div>
                <div style="color:#94A3B8; font-size:0.85rem; margin-top:6px;">
                    {stg_rec.explanation}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if stage_events:
            with st.expander(f"Inspect Stage 0{idx} Events ({len(stage_events)})", expanded=(status_val in ("running", "failed"))):
                for ev in stage_events:
                    ev_time = ev.timestamp[11:19] if len(ev.timestamp) >= 19 else ev.timestamp
                    ev_color = "#EF4444" if "failed" in ev.event_type else (
                        "#F59E0B" if "suspicious" in ev.event_type or "unavailable" in ev.event_type else (
                            "#22C55E" if "confirmed" in ev.event_type or "completed" in ev.event_type else "#3B82F6"
                        )
                    )
                    st.markdown(
                        f"<div style='font-family:monospace; font-size:0.81rem; padding:3px 0; color:#E5E7EB;'>"
                        f"<span style='color:#64748B;'>[{ev_time}]</span> "
                        f"<span style='color:{ev_color}; font-weight:600;'>{ev.event_type}</span> — "
                        f"{ev.message}</div>",
                        unsafe_allow_html=True,
                    )


def render_scan_panel() -> None:
    """Backwards-compatible entry point for standalone scan panel rendering."""
    render_stage_timeline(session=None, events=None)
