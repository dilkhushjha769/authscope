"""Dashboard Component: Settings, Scope Guard Configuration, Role Session Status & Documentation."""

from typing import List
import streamlit as st

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.storage.models import FindingRecord


def render_settings_panel(
    session_manager: SessionManager,
    scope_guard: ScopeGuard,
) -> None:
    """Renders hard ScopeGuard boundaries and role session readiness without exposing secrets."""
    st.markdown(
        """
        <div style="margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">Engine Settings &amp; Hard Scope Boundaries</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Read-only enforcement rules &amp; role session readiness</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_scope, col_roles = st.columns(2)

    with col_scope:
        st.markdown("##### 🔒 Hard Scope Guard (`backend/core/scope_guard.py`)")
        st.markdown(
            f"""
            <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:14px;">
                <div style="color:#E5E7EB; font-size:0.86rem; margin-bottom:6px;"><strong>Allowed Hosts:</strong> <code>{", ".join(sorted(scope_guard.allowed_hosts))}</code></div>
                <div style="color:#E5E7EB; font-size:0.86rem; margin-bottom:6px;"><strong>Allowed Ports:</strong> <code>{", ".join(str(p) for p in sorted(scope_guard.allowed_ports))}</code></div>
                <div style="color:#E5E7EB; font-size:0.86rem; margin-bottom:6px;"><strong>Allowed Schemes:</strong> <code>{", ".join(sorted(scope_guard.allowed_schemes))}</code></div>
                <div style="color:#E5E7EB; font-size:0.86rem; margin-bottom:6px;"><strong>Allowed HTTP Methods:</strong> <code>{", ".join(sorted(scope_guard.allowed_methods))}</code></div>
                <div style="color:#E5E7EB; font-size:0.86rem;"><strong>Follow Redirects:</strong> <code>False (Hard-Disabled)</code></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_roles:
        st.markdown("##### 👥 Role Session Readiness (`backend/core/session_manager.py`)")
        for role in (Role.ANONYMOUS, Role.USER_A, Role.USER_B, Role.ADMIN):
            is_auth = session_manager.is_authenticated(role)
            fg = "#22C55E" if is_auth else "#F59E0B"
            bg = "#052E16" if is_auth else "#451A03"
            status_label = "READY (AUTHENTICATED)" if is_auth else "UNCONFIGURED (SKIPPED)"
            if role == Role.ANONYMOUS:
                status_label = "READY (UNAUTHENTICATED BASELINE)"
            st.markdown(
                f"""
                <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:10px 14px; margin-bottom:6px; display:flex; align-items:center; justify-content:space-between;">
                    <span style="color:#F9FAFB; font-family:monospace; font-weight:600; font-size:0.88rem;">{role.value}</span>
                    <span style="background-color:{bg}; color:{fg}; font-size:0.72rem; font-weight:600; padding:2px 8px; border-radius:4px; font-family:monospace;">{status_label}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.caption(
            "Credential values, cookies, and JWTs are never rendered in the UI or stored in plain text in logs."
        )


def render_documentation_panel() -> None:
    """Renders in-app architectural and operational documentation."""
    st.markdown(
        """
        <div style="margin-bottom:10px;">
            <span style="color:#F9FAFB; font-weight:600; font-size:1.05rem;">AuthScope Operational Documentation</span>
            <span style="color:#94A3B8; font-size:0.83rem; margin-left:10px;">Evidence-driven authorization differential testing</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style="background-color:#111827; border:1px solid #1E293B; border-radius:8px; padding:18px; color:#E5E7EB; font-size:0.9rem; line-height:1.6;">
            <h4 style="color:#F9FAFB; margin-top:0;">1. Evidence-First Architecture</h4>
            <p style="color:#94A3B8;">
                AuthScope is a deterministic, hard-scoped security testing platform. Every stage event, endpoint discovery record,
                and finding card displayed in this interface is produced by real execution in the Python security engine
                (<code>ScopeGuard</code> → <code>RequestExecutor</code> → <code>EndpointDiscovery</code> → <code>AuthorizationTester</code> → <code>EvidenceValidator</code>).
            </p>
            <h4 style="color:#F9FAFB;">2. Confirmed vs. Suspicious Classification</h4>
            <ul style="color:#94A3B8;">
                <li><strong>CONFIRMED_UNAUTHORIZED_ACCESS:</strong> Assigned only when a legitimate resource owner's baseline response is compared against an unauthorized peer's response, protected resource fields match, and <code>EvidenceValidator</code> signs a complete SHA-256 artifact.</li>
                <li><strong>SUSPICIOUS_ACCESS:</strong> Assigned when an unauthenticated or unauthorized probe returns unexpected non-empty JSON data on a restricted route (such as <code>/rest/admin/application-configuration</code>), or when an authenticated baseline session is unavailable to complete cross-account verification.</li>
            </ul>
            <h4 style="color:#F9FAFB;">3. Configuring Multi-Role Sessions</h4>
            <p style="color:#94A3B8;">
                Set <code>USER_A_TOKEN</code>, <code>USER_B_TOKEN</code>, and <code>ADMIN_TOKEN</code> in your <code>.env</code> file to enable full cross-account BOLA/IDOR comparison across parameterized routes (such as <code>/rest/basket/{id}</code> and <code>/api/BasketItems/{id}</code>).
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_retest_panel(findings: List[FindingRecord]) -> None:
    """Renders retesting status for findings."""
    st.subheader("Automated Retesting & Patch Verification")
    if not findings:
        st.info("No findings recorded to retest.")
        return
    for finding in findings:
        st.markdown(f"- **{finding.title}** (`{finding.http_method} {finding.target_endpoint}`) — Retest status: `{finding.retest_status}`")
