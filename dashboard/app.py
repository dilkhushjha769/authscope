"""AuthScope — Live AI Security Agent Interface (Streamlit Application).

Connects directly to the Python security engine (ScopeGuard, RequestExecutor,
EndpointDiscovery, AuthorizationTester, EvidenceValidator, FindingRepository)
via AssessmentEngine and AssessmentQueryAdapter.
"""

import sys
from pathlib import Path

# Ensure repository root is on sys.path when launched directly via `streamlit run dashboard/app.py`
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from typing import Dict, List, Optional
import streamlit as st

from backend.core.assessment_engine import (
    AssessmentEngine,
    AssessmentQueryAdapter,
    CancellationToken,
)
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import SessionManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import AssessmentEvent, ScanSessionRecord
from dashboard.components.evidence_viewer import (
    render_endpoint_explorer,
    render_evidence_viewer,
)
from dashboard.components.findings import render_findings_list
from dashboard.components.overview import render_overview
from dashboard.components.retest_panel import (
    render_documentation_panel,
    render_settings_panel,
)
from dashboard.components.scan_panel import (
    render_scope_validation_banner,
    render_stage_timeline,
)


st.set_page_config(
    page_title="AuthScope | AI Security Assessment Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Premium Dark Navy Cybersecurity Theme (#0B0F17 / #111827 / #1A2233 / #263248)
st.markdown(
    """
    <style>
        .stApp, .main {
            background-color: #0B0F17 !important;
            color: #F9FAFB !important;
        }
        section[data-testid="stSidebar"] {
            background-color: #111827 !important;
            border-right: 1px solid #263248 !important;
        }
        div[data-testid="stMetric"] {
            background-color: #111827;
            border: 1px solid #263248;
            border-radius: 8px;
            padding: 12px 16px;
        }
        div[data-testid="stExpander"] {
            background-color: #111827;
            border: 1px solid #263248;
            border-radius: 8px;
        }
        .stTextInput > div > div > input {
            background-color: #111827 !important;
            color: #F9FAFB !important;
            border: 1px solid #263248 !important;
            font-family: 'JetBrains Mono', monospace !important;
        }
        .stButton > button {
            border-radius: 6px !important;
            font-weight: 600 !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def _init_state() -> None:
    """Initializes Streamlit session state keys cleanly."""
    if "active_view" not in st.session_state:
        st.session_state.active_view = "Active Assessment"
    if "active_scan_id" not in st.session_state:
        repo = FindingRepository()
        recent = repo.list_scan_sessions(limit=1)
        st.session_state.active_scan_id = recent[0].id if recent else None
    if "target_url_input" not in st.session_state:
        st.session_state.target_url_input = "http://localhost:3000"
    if "cancel_token" not in st.session_state:
        st.session_state.cancel_token = CancellationToken()
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []


def _select_scan_session(scan_id: str) -> None:
    """Switches the active workspace to a stored historical scan session."""
    st.session_state.active_scan_id = scan_id
    st.session_state.active_view = "Active Assessment"


def _render_top_assessment_header(
    active_session: Optional[ScanSessionRecord],
    target_url: str,
) -> bool:
    """Renders the top assessment header with title, target, status badge, and Stop button.

    Returns True if the Stop Assessment button was clicked.
    """
    status_str = active_session.status if active_session else "IDLE"
    title_str = (
        f"Security Assessment · {active_session.id}"
        if active_session
        else "New Security Assessment"
    )
    disp_target = active_session.target_url if active_session else target_url

    badge_colors = {
        "IDLE": ("#94A3B8", "#1E293B"),
        "RUNNING": ("#3B82F6", "#172554"),
        "COMPLETED": ("#22C55E", "#052E16"),
        "FAILED": ("#EF4444", "#450A0A"),
        "CANCELLED": ("#F59E0B", "#451A03"),
    }
    fg, bg = badge_colors.get(status_str, ("#94A3B8", "#1E293B"))

    col_hdr, col_stop = st.columns([5, 1])
    with col_hdr:
        st.markdown(
            f"""
            <div style="background-color:#111827; border:1px solid #263248; border-radius:10px; padding:14px 18px; margin-bottom:14px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
                <div>
                    <div style="color:#F9FAFB; font-weight:700; font-size:1.15rem;">🛡️ {title_str}</div>
                    <div style="color:#94A3B8; font-size:0.84rem; margin-top:2px;">
                        Target: <code style="color:#E5E7EB;">{disp_target}</code> · Hard-Scoped Differential Engine
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="background-color:{bg}; color:{fg}; border:1px solid {fg}66; font-family:monospace; font-size:0.78rem; font-weight:700; padding:4px 10px; border-radius:6px;">
                        ● {status_str}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    stop_clicked = False
    with col_stop:
        if st.button("⏹ Stop Scan", use_container_width=True, help="Safely cancel an active assessment"):
            st.session_state.cancel_token.cancel()
            stop_clicked = True
    return stop_clicked


def main() -> None:
    """Main entry point for the AuthScope Live AI Security Agent Interface."""
    _init_state()

    repo = FindingRepository()
    scope_guard = ScopeGuard()
    session_manager = SessionManager(load_from_env=True)
    engine = AssessmentEngine(
        repository=repo,
        scope_guard=scope_guard,
        session_manager=session_manager,
    )
    query_adapter = AssessmentQueryAdapter(repository=repo)

    all_sessions = repo.list_scan_sessions(limit=25)

    # ==========================================================================
    # LEFT SIDEBAR
    # ==========================================================================
    with st.sidebar:
        st.markdown(
            """
            <div style="padding:4px 0 12px 0; border-bottom:1px solid #263248; margin-bottom:12px;">
                <div style="color:#F9FAFB; font-weight:700; font-size:1.25rem; letter-spacing:-0.01em;">🛡️ AuthScope</div>
                <div style="color:#94A3B8; font-size:0.78rem; margin-top:2px;">Evidence-Driven AI Security Agent</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.button("＋ New Assessment", use_container_width=True, type="primary"):
            st.session_state.active_scan_id = None
            st.session_state.active_view = "Active Assessment"
            st.session_state.chat_messages = []
            st.rerun()

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        nav_options = [
            "Active Assessment",
            "Assessment History",
            "Findings",
            "Endpoint Explorer",
            "Settings",
            "Documentation",
        ]
        selected_nav = st.radio(
            "Navigation",
            nav_options,
            index=nav_options.index(st.session_state.active_view)
            if st.session_state.active_view in nav_options
            else 0,
            label_visibility="collapsed",
        )
        st.session_state.active_view = selected_nav

        st.markdown(
            """
            <div style="margin-top:16px; padding-top:12px; border-top:1px solid #263248; color:#64748B; font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.05em;">
                Recent Scans
            </div>
            """,
            unsafe_allow_html=True,
        )
        if not all_sessions:
            st.caption("No scans run yet.")
        else:
            for s in all_sessions[:8]:
                icon = "🟢" if s.status == "COMPLETED" else ("🔴" if s.status == "FAILED" else "🟡")
                btn_label = f"{icon} {s.id[-13:]} ({s.confirmed_findings_count}C/{s.suspicious_results_count}S)"
                if st.button(btn_label, key=f"side_scan_{s.id}", use_container_width=True):
                    _select_scan_session(s.id)
                    st.rerun()

    # Load active scan data if selected
    active_scan_id: Optional[str] = st.session_state.active_scan_id
    active_session = repo.get_scan_session(active_scan_id) if active_scan_id else None
    active_events = repo.list_events(active_scan_id) if active_scan_id else []
    active_endpoints = repo.list_discovered_endpoints(active_scan_id) if active_scan_id else []
    active_findings = repo.list_findings(active_scan_id) if active_scan_id else []

    # ==========================================================================
    # MAIN WORKSPACE AREA
    # ==========================================================================
    stop_requested = _render_top_assessment_header(
        active_session=active_session,
        target_url=st.session_state.target_url_input,
    )
    if stop_requested and active_session and active_session.status == "RUNNING":
        st.warning("Stop signal sent to active assessment.")

    # View Router
    if st.session_state.active_view == "Assessment History":
        all_findings_global = repo.list_findings()
        render_overview(
            findings=all_findings_global,
            sessions=all_sessions,
            on_select_session=_select_scan_session,
        )
        return

    if st.session_state.active_view == "Findings":
        render_findings_list(
            findings=active_findings,
            query_adapter=query_adapter,
            scan_id=active_scan_id,
        )
        return

    if st.session_state.active_view == "Endpoint Explorer":
        render_endpoint_explorer(endpoints=active_endpoints, findings=active_findings)
        render_evidence_viewer(findings=active_findings)
        return

    if st.session_state.active_view == "Settings":
        render_settings_panel(session_manager=session_manager, scope_guard=scope_guard)
        return

    if st.session_state.active_view == "Documentation":
        render_documentation_panel()
        return

    # ==========================================================================
    # ACTIVE ASSESSMENT CONVERSATIONAL WORKSPACE
    # ==========================================================================
    col_url, col_start = st.columns([4, 1])
    with col_url:
        target_url_val = st.text_input(
            "Authorized Target URL",
            value=st.session_state.target_url_input,
            placeholder="http://localhost:3000",
            label_visibility="collapsed",
        )
        st.session_state.target_url_input = target_url_val
    with col_start:
        start_clicked = st.button(
            "▶ Start Assessment",
            type="primary",
            use_container_width=True,
        )

    # Real-time pre-scan ScopeGuard check
    scope_preview = engine.validate_target_url(target_url_val)
    render_scope_validation_banner(target_url=target_url_val, scope_result=scope_preview)

    timeline_container = st.empty()

    if start_clicked:
        st.session_state.cancel_token = CancellationToken()
        streamed_events: List[AssessmentEvent] = []
        gen = engine.stream_assessment(
            target_url=target_url_val,
            cancel_token=st.session_state.cancel_token,
        )
        latest_session: Optional[ScanSessionRecord] = None
        try:
            while True:
                evt = next(gen)
                streamed_events.append(evt)
                latest_session = repo.get_scan_session(evt.assessment_id)
                st.session_state.active_scan_id = evt.assessment_id
                with timeline_container.container():
                    render_stage_timeline(session=latest_session, events=streamed_events)
        except StopIteration as stop_iter:
            latest_session = stop_iter.value

        if latest_session:
            st.session_state.active_scan_id = latest_session.id
            active_scan_id = latest_session.id
            active_session = latest_session
            active_events = repo.list_events(latest_session.id)
            active_endpoints = repo.list_discovered_endpoints(latest_session.id)
            active_findings = repo.list_findings(latest_session.id)
            st.session_state.chat_messages.append(
                {
                    "role": "assistant",
                    "content": (
                        f"**Assessment `{latest_session.id}` ({latest_session.status})** — "
                        f"{latest_session.summary_text}"
                    ),
                }
            )
            st.rerun()
    else:
        with timeline_container.container():
            render_stage_timeline(session=active_session, events=active_events)

    # Show Findings & Discovered Endpoints inline below the timeline when an assessment is loaded
    if active_session is not None:
        st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)
        tab_fnd, tab_ep, tab_evi = st.tabs([
            f"🔍 Findings ({len(active_findings)})",
            f"🧭 Discovered Endpoints ({len(active_endpoints)})",
            "🔐 Signed Evidence Artifacts",
        ])
        with tab_fnd:
            render_findings_list(
                findings=active_findings,
                query_adapter=query_adapter,
                scan_id=active_scan_id,
            )
        with tab_ep:
            render_endpoint_explorer(endpoints=active_endpoints, findings=active_findings)
        with tab_evi:
            render_evidence_viewer(findings=active_findings)

    # ==========================================================================
    # CONVERSATIONAL AGENT INTERACTION (DETERMINISTIC ASSESSMENT QUERY ADAPTER)
    # ==========================================================================
    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.markdown(
        """
        <div style="border-top:1px solid #263248; padding-top:14px; margin-bottom:8px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.0rem;">💬 Ask AuthScope About This Assessment</span>
            <span style="background-color:#1E293B; color:#8B5CF6; border:1px solid #8B5CF655; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; margin-left:10px; font-family:monospace;">
                Deterministic AssessmentQueryAdapter
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    quick_questions = [
        "What has the agent completed?",
        "Which endpoints were discovered?",
        "Which endpoints were tested?",
        "Why was this result marked suspicious?",
        "Show me the evidence for this finding.",
        "What should I fix first?",
    ]
    q_cols = st.columns(3)
    triggered_question: Optional[str] = None
    for idx, q_text in enumerate(quick_questions):
        with q_cols[idx % 3]:
            if st.button(q_text, key=f"quick_q_{idx}", use_container_width=True):
                triggered_question = q_text

    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_chat_input = st.chat_input(
        "Ask a question about the current assessment (e.g., 'Why was this result marked suspicious?')..."
    )
    active_prompt = triggered_question or user_chat_input
    if active_prompt:
        st.session_state.chat_messages.append({"role": "user", "content": active_prompt})
        answer = query_adapter.answer_question(scan_id=active_scan_id, question=active_prompt)
        st.session_state.chat_messages.append({"role": "assistant", "content": answer})
        st.rerun()


if __name__ == "__main__":
    main()
