"""Assessment Engine & Real-Time Event Streaming Orchestrator.

Coordinates the 7-stage security assessment lifecycle using the existing
ScopeGuard, SessionManager, RequestExecutor, EndpointDiscovery, ResponseAnalyzer,
AuthorizationTester, EvidenceValidator, SeverityEngine, RemediationEngine, and
FindingRepository.

Emits real-time, sanitized AssessmentEvent objects and supports safe cancellation
and deterministic assessment querying.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple
import json
import time
import uuid

from backend.config import settings
from backend.core.scope_guard import ScopeGuard, ScopeCheckResult
from backend.core.session_manager import Role, SessionManager
from backend.scanner.endpoint_discovery import (
    DiscoveredEndpoint,
    EndpointCategory,
    EndpointDiscovery,
    TEMPLATE_PARAM_REGEX,
)
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.scanner.authorization_tester import AuthorizationTester
from backend.agent.attack_chain import AttackChainPlanner
from backend.scanner.security_inspector import SecurityInspector
from backend.analysis.evidence_validator import (
    BEARER_REGEX,
    EvidenceArtifact,
    EvidenceValidationStatus,
    EvidenceValidator,
    JSON_SECRET_FIELD_REGEX,
    JWT_REGEX,
)
from backend.analysis.severity_engine import SeverityEngine, SeverityLevel
from backend.analysis.remediation import RemediationEngine
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    DiscoveredEndpointRecord,
    EventType,
    FindingRecord,
    STAGE_LABELS,
    ScanSessionRecord,
    StageStateRecord,
    StageStatus,
)
from backend.utils.helpers import (
    AuthScopeException,
    TargetUnreachableError,
    redact_sensitive_text,
    sanitize_headers_for_logging,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class CancellationToken:
    """Thread-safe cancellation token for stopping an active assessment cleanly."""

    def __init__(self) -> None:
        self._cancelled: bool = False

    def cancel(self) -> None:
        """Signals the assessment engine to stop safely at the next checkpoint."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


def sanitize_event_text(text: str) -> str:
    """Scrubs JWTs, Bearer tokens, and secret fields from event messages."""
    if not text:
        return ""
    cleaned = redact_sensitive_text(text)
    cleaned = JWT_REGEX.sub("[REDACTED_JWT]", cleaned)
    cleaned = BEARER_REGEX.sub("Bearer [REDACTED_TOKEN]", cleaned)
    cleaned = JSON_SECRET_FIELD_REGEX.sub(r'\1"[REDACTED_SECRET]"', cleaned)
    return cleaned


def sanitize_event_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively scrubs sensitive keys and tokens from event metadata dictionaries."""
    if not metadata:
        return {}
    sensitive_keys = {
        "password", "token", "jwt", "authorization", "cookie", "set-cookie",
        "secret", "api_key", "apikey", "totpsecret", "deluxetoken"
    }
    cleaned: Dict[str, Any] = {}
    for k, v in metadata.items():
        k_str = str(k)
        if k_str.lower() in sensitive_keys:
            cleaned[k_str] = "[REDACTED]"
        elif isinstance(v, dict):
            if k_str.lower() == "headers":
                cleaned[k_str] = sanitize_headers_for_logging(v)
            else:
                cleaned[k_str] = sanitize_event_metadata(v)
        elif isinstance(v, str):
            cleaned[k_str] = sanitize_event_text(v)
        elif isinstance(v, list):
            cleaned[k_str] = [_sanitize_event_value(item) for item in v]
        else:
            cleaned[k_str] = v
    return cleaned


def _sanitize_event_value(value: Any) -> Any:
    """Recursively scrubs nested event lists and mappings before persistence."""
    if isinstance(value, dict):
        return sanitize_event_metadata(value)
    if isinstance(value, list):
        return [_sanitize_event_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_event_text(value)
    return value


class AssessmentEngine:
    """Executes real-time, 7-stage authorization assessments and streams events."""

    def __init__(
        self,
        repository: Optional[FindingRepository] = None,
        scope_guard: Optional[ScopeGuard] = None,
        session_manager: Optional[SessionManager] = None,
        executor: Optional[RequestExecutor] = None,
    ):
        self.repository = repository or FindingRepository()
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager(load_from_env=True)
        self.executor = executor
        self.analyzer = ResponseAnalyzer()
        self.evidence_validator = EvidenceValidator()
        self.severity_engine = SeverityEngine()
        self.remediation_engine = RemediationEngine()

    def run_extended_security_checks(
        self,
        target_url: str,
        assessment_id: Optional[str] = None,
        cancel_token: Optional[CancellationToken] = None,
    ) -> Dict[str, Any]:
        """Runs Sprint 2 extended security checks (Auth, Session, Headers, CORS, Transport)."""
        inspector = SecurityInspector(
            executor=self.executor,
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
            cancel_token=cancel_token,
        )
        return inspector.run_comprehensive_inspection(
            endpoint=target_url,
            assessment_id=assessment_id or f"extended_sec_{uuid.uuid4().hex[:8]}",
        )

    def validate_target_url(self, target_url: str) -> ScopeCheckResult:
        """Pre-validates a user-supplied target URL via ScopeGuard without opening sockets."""
        return self.scope_guard.validate_request(url=target_url, method="GET")

    @staticmethod
    def _init_stages() -> Dict[str, StageStateRecord]:
        """Creates initial WAITING state records for all 7 stages."""
        stages: Dict[str, StageStateRecord] = {}
        for stg in AssessmentStage:
            stages[stg.value] = StageStateRecord(
                stage=stg,
                label=STAGE_LABELS[stg],
                status=StageStatus.WAITING,
                explanation="Waiting",
            )
        return stages

    def _emit_event(
        self,
        session: ScanSessionRecord,
        event_type: EventType | str,
        stage: AssessmentStage | str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssessmentEvent:
        """Creates, sanitizes, persists, and attaches an AssessmentEvent."""
        etype_str = event_type.value if isinstance(event_type, EventType) else str(event_type)
        stage_str = stage.value if isinstance(stage, AssessmentStage) else str(stage)
        clean_msg = sanitize_event_text(message)
        clean_meta = sanitize_event_metadata(metadata or {})

        event = AssessmentEvent(
            assessment_id=session.id,
            event_type=etype_str,
            stage=stage_str,
            message=clean_msg,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=clean_meta,
        )
        if stage_str in session.stages:
            session.stages[stage_str].events.append(event)
        self.repository.save_event(event)
        return event

    def _start_stage(
        self,
        session: ScanSessionRecord,
        stage: AssessmentStage,
        explanation: str,
    ) -> float:
        """Marks a stage as RUNNING and records its start timestamp."""
        rec = session.stages[stage.value]
        rec.status = StageStatus.RUNNING
        rec.explanation = sanitize_event_text(explanation)
        rec.started_at = datetime.now(timezone.utc).isoformat()
        session.updated_at = datetime.now(timezone.utc)
        self.repository.save_scan_session(session)
        return time.perf_counter()

    def _complete_stage(
        self,
        session: ScanSessionRecord,
        stage: AssessmentStage,
        start_perf: float,
        explanation: str,
        status: StageStatus = StageStatus.COMPLETED,
    ) -> None:
        """Marks a stage as COMPLETED/FAILED/SKIPPED and calculates its duration in ms."""
        rec = session.stages[stage.value]
        rec.status = status
        rec.explanation = sanitize_event_text(explanation)
        rec.completed_at = datetime.now(timezone.utc).isoformat()
        rec.duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
        session.updated_at = datetime.now(timezone.utc)
        self.repository.save_scan_session(session)

    def _skip_remaining_stages(self, session: ScanSessionRecord, reason: str) -> None:
        """Marks all remaining WAITING or RUNNING stages as SKIPPED."""
        now_iso = datetime.now(timezone.utc).isoformat()
        for stg_rec in session.stages.values():
            if stg_rec.status in (StageStatus.WAITING, StageStatus.RUNNING):
                stg_rec.status = StageStatus.SKIPPED
                stg_rec.explanation = sanitize_event_text(reason)
                stg_rec.completed_at = now_iso
        self.repository.save_scan_session(session)

    def stream_assessment(
        self,
        target_url: str,
        scan_id: Optional[str] = None,
        cancel_token: Optional[CancellationToken] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Generator[AssessmentEvent, None, ScanSessionRecord]:
        """Executes a complete 7-stage security assessment, yielding real-time events.

        Never fabricates progress or findings. Every event corresponds to a real
        backend step executed against the target or validated by the security engine.
        """
        normalized_target = (target_url or "").strip().rstrip("/")
        scan_id = scan_id or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        session = ScanSessionRecord(
            id=scan_id,
            target_url=normalized_target or target_url,
            status="RUNNING",
            started_at=datetime.now(timezone.utc),
            stages=self._init_stages(),
        )
        self.repository.save_scan_session(session)

        def is_cancelled() -> bool:
            if cancel_token and cancel_token.is_cancelled:
                return True
            if should_cancel and should_cancel():
                return True
            return False

        def handle_cancellation() -> AssessmentEvent:
            session.status = "CANCELLED"
            session.completed_at = datetime.now(timezone.utc)
            self._skip_remaining_stages(session, "Assessment stopped safely by user.")
            evt = self._emit_event(
                session,
                EventType.ASSESSMENT_CANCELLED,
                AssessmentStage.REPORT_PREPARATION,
                "Assessment cancelled safely by operator.",
            )
            self.repository.save_scan_session(session)
            return evt

        # Emit assessment_started
        yield self._emit_event(
            session,
            EventType.ASSESSMENT_STARTED,
            AssessmentStage.SCOPE_VALIDATION,
            f"Starting security assessment for {normalized_target or target_url}.",
            {"target_url": normalized_target or target_url},
        )

        if is_cancelled():
            yield handle_cancellation()
            return session

        # ======================================================================
        # STAGE 1: Validating Target Scope
        # ======================================================================
        t_stage1 = self._start_stage(
            session,
            AssessmentStage.SCOPE_VALIDATION,
            "Checking target host, port, scheme, and method against ScopeGuard allowlist.",
        )
        yield self._emit_event(
            session,
            EventType.SCOPE_VALIDATION_STARTED,
            AssessmentStage.SCOPE_VALIDATION,
            "Validating target scope against allowlist rules.",
            {"target_url": normalized_target},
        )

        scope_res = self.scope_guard.validate_request(url=normalized_target, method="GET")
        if not scope_res.is_allowed:
            self._complete_stage(
                session,
                AssessmentStage.SCOPE_VALIDATION,
                t_stage1,
                f"Scope validation failed: {scope_res.reason}",
                status=StageStatus.FAILED,
            )
            session.status = "FAILED"
            session.completed_at = datetime.now(timezone.utc)
            session.summary_text = f"Target rejected by ScopeGuard: {scope_res.reason}"
            self._skip_remaining_stages(session, "Skipped due to scope validation failure.")
            yield self._emit_event(
                session,
                EventType.ASSESSMENT_FAILED,
                AssessmentStage.SCOPE_VALIDATION,
                f"Target rejected by ScopeGuard: {scope_res.reason}",
                {"reason": scope_res.reason},
            )
            self.repository.save_scan_session(session)
            return session

        self._complete_stage(
            session,
            AssessmentStage.SCOPE_VALIDATION,
            t_stage1,
            "Target authorization validated.",
        )
        yield self._emit_event(
            session,
            EventType.SCOPE_VALIDATION_COMPLETED,
            AssessmentStage.SCOPE_VALIDATION,
            "Target authorization validated.",
            {
                "host": scope_res.normalized_host,
                "port": scope_res.normalized_port,
                "scheme": scope_res.normalized_scheme,
                "method": "GET",
            },
        )

        if is_cancelled():
            yield handle_cancellation()
            return session

        # Create or reuse RequestExecutor
        owns_executor = self.executor is None
        active_executor = self.executor or RequestExecutor(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
        )

        try:
            # ==================================================================
            # STAGE 2: Connecting to the Application
            # ==================================================================
            t_stage2 = self._start_stage(
                session,
                AssessmentStage.TARGET_CONNECTION,
                "Establishing HTTP GET connection to target application.",
            )
            try:
                conn_resp = active_executor.send_request(
                    role=Role.ANONYMOUS,
                    method="GET",
                    url=f"{normalized_target}/",
                )
            except TargetUnreachableError as exc:
                self._complete_stage(
                    session,
                    AssessmentStage.TARGET_CONNECTION,
                    t_stage2,
                    f"Application connection failed: {exc}",
                    status=StageStatus.FAILED,
                )
                session.status = "FAILED"
                session.completed_at = datetime.now(timezone.utc)
                session.summary_text = f"Target unreachable: {exc}"
                self._skip_remaining_stages(session, "Skipped because target application is unreachable.")
                yield self._emit_event(
                    session,
                    EventType.ASSESSMENT_FAILED,
                    AssessmentStage.TARGET_CONNECTION,
                    f"Application connection failed: {exc}",
                    {"error": str(exc)},
                )
                self.repository.save_scan_session(session)
                return session

            self._complete_stage(
                session,
                AssessmentStage.TARGET_CONNECTION,
                t_stage2,
                f"Application connection successful (HTTP {conn_resp.status_code}, {conn_resp.response_time_ms:.1f} ms).",
            )
            yield self._emit_event(
                session,
                EventType.CONNECTION_COMPLETED,
                AssessmentStage.TARGET_CONNECTION,
                "Application connection successful.",
                {
                    "status_code": conn_resp.status_code,
                    "response_time_ms": round(conn_resp.response_time_ms, 2),
                    "content_length": conn_resp.content_length,
                },
            )

            if is_cancelled():
                yield handle_cancellation()
                return session

            # ==================================================================
            # STAGE 3: Discovering Endpoints
            # ==================================================================
            t_stage3 = self._start_stage(
                session,
                AssessmentStage.ENDPOINT_DISCOVERY,
                "Reading an in-scope OpenAPI document for safe GET routes, with the configured Juice Shop route list as fallback.",
            )
            discovery = EndpointDiscovery(base_url=normalized_target, scope_guard=self.scope_guard)
            discovered_routes: List[DiscoveredEndpoint] = discovery.discover_from_openapi(
                executor=active_executor,
            )
            endpoint_records: Dict[str, DiscoveredEndpointRecord] = {}

            for idx, route in enumerate(discovered_routes, start=1):
                if is_cancelled():
                    yield handle_cancellation()
                    return session

                ep_rec = DiscoveredEndpointRecord(
                    id=f"ep_{scan_id}_{idx:02d}",
                    scan_id=scan_id,
                    path=route.path,
                    method=route.method,
                    category=route.category.value,
                    parameters=route.parameters,
                    requires_auth=route.requires_auth,
                    discovery_status="DISCOVERED",
                    test_status="UNTESTED",
                    summary=route.description,
                    planner_metadata={
                        key: value
                        for key, value in route.model_dump(mode="json").items()
                        if key not in {"path", "method", "category", "parameters", "requires_auth", "description"}
                    },
                )
                self.repository.save_discovered_endpoint(ep_rec)
                endpoint_records[route.path] = ep_rec

                yield self._emit_event(
                    session,
                    EventType.ENDPOINT_DISCOVERED,
                    AssessmentStage.ENDPOINT_DISCOVERY,
                    f"Discovered route: {route.method} {route.path} [{route.category.value}]",
                    {
                        "path": route.path,
                        "method": route.method,
                        "category": route.category.value,
                        "parameters": route.parameters,
                        "requires_auth": route.requires_auth,
                    },
                )

            session.endpoints_discovered_count = len(discovered_routes)
            # Planning is part of the assessment inventory path. It produces
            # untrusted candidates only; execution still requires an explicit
            # operator action through the validated chain API.
            chain_plan = AttackChainPlanner().plan(discovered_routes, max_steps=5, max_candidates=25)
            if session.config is None:
                session.config = {}
            session.config["attack_chain_candidates"] = [
                candidate.model_dump(mode="json") for candidate in chain_plan.candidates
            ]
            session.config["attack_chain_graph"] = chain_plan.graph.model_dump(mode="json")
            self.repository.save_scan_session(session)
            self._complete_stage(
                session,
                AssessmentStage.ENDPOINT_DISCOVERY,
                t_stage3,
                f"{len(discovered_routes)} GET routes discovered.",
            )
            yield self._emit_event(
                session,
                EventType.ENDPOINT_DISCOVERY_COMPLETED,
                AssessmentStage.ENDPOINT_DISCOVERY,
                f"{len(discovered_routes)} GET routes discovered.",
                {"count": len(discovered_routes)},
            )
            yield self._emit_event(
                session,
                EventType.ATTACK_CHAIN_CANDIDATES_PLANNED,
                AssessmentStage.ENDPOINT_DISCOVERY,
                f"Built endpoint graph and planned {len(chain_plan.candidates)} unverified chain candidates.",
                {
                    "endpoint_count": len(chain_plan.graph.nodes),
                    "relationship_count": len(chain_plan.graph.relationships),
                    "candidate_count": len(chain_plan.candidates),
                    "candidates_are_unverified": True,
                },
            )

            if is_cancelled():
                yield handle_cancellation()
                return session

            # ==================================================================
            # STAGE 4: Verifying Authentication Sessions
            # ==================================================================
            t_stage4 = self._start_stage(
                session,
                AssessmentStage.SESSION_VERIFICATION,
                "Checking configured test role sessions (User A, User B, Admin).",
            )
            yield self._emit_event(
                session,
                EventType.SESSION_VALIDATION_STARTED,
                AssessmentStage.SESSION_VERIFICATION,
                "Verifying configured role sessions in SessionManager.",
            )

            user_a_ok = self.session_manager.is_authenticated(Role.USER_A)
            user_b_ok = self.session_manager.is_authenticated(Role.USER_B)
            admin_ok = self.session_manager.is_authenticated(Role.ADMIN)

            if user_a_ok:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "User A session verified.",
                    {"role": Role.USER_A.value, "authenticated": True},
                )
            else:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "User A session unavailable.",
                    {"role": Role.USER_A.value, "authenticated": False},
                )

            if user_b_ok:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "User B session verified.",
                    {"role": Role.USER_B.value, "authenticated": True},
                )
            else:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "User B session unavailable. Account comparison cannot proceed.",
                    {"role": Role.USER_B.value, "authenticated": False},
                )

            if admin_ok:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "Admin session verified.",
                    {"role": Role.ADMIN.value, "authenticated": True},
                )
            else:
                yield self._emit_event(
                    session,
                    EventType.STAGE_UPDATED,
                    AssessmentStage.SESSION_VERIFICATION,
                    "Admin session unavailable.",
                    {"role": Role.ADMIN.value, "authenticated": False},
                )

            active_roles_list = ["anonymous"]
            if user_a_ok:
                active_roles_list.append("user_a")
            if user_b_ok:
                active_roles_list.append("user_b")
            if admin_ok:
                active_roles_list.append("admin")

            session_summary_msg = (
                "All test role sessions verified (User A, User B, Admin)."
                if (user_a_ok and user_b_ok and admin_ok)
                else f"Active sessions verified: {', '.join(active_roles_list)}."
            )
            self._complete_stage(
                session,
                AssessmentStage.SESSION_VERIFICATION,
                t_stage4,
                session_summary_msg,
            )
            cred_report = self.session_manager.validate_configured_credentials()
            yield self._emit_event(
                session,
                EventType.SESSION_VALIDATION_COMPLETED,
                AssessmentStage.SESSION_VERIFICATION,
                session_summary_msg,
                {
                    "user_a_authenticated": user_a_ok,
                    "user_b_authenticated": user_b_ok,
                    "admin_authenticated": admin_ok,
                    "authenticated_roles": active_roles_list,
                    "multi_role_ready": cred_report["multi_role_ready"],
                    "anonymous_baseline_ready": True,
                },
            )

            if is_cancelled():
                yield handle_cancellation()
                return session

            # ==================================================================
            # STAGE 5: Comparing Authorization Behavior
            # ==================================================================
            t_stage5 = self._start_stage(
                session,
                AssessmentStage.AUTHORIZATION_TESTING,
                "Executing authorization-differential and boundary checks across discovered routes.",
            )
            yield self._emit_event(
                session,
                EventType.AUTHORIZATION_TEST_STARTED,
                AssessmentStage.AUTHORIZATION_TESTING,
                "Starting authorization behavior evaluation on discovered GET endpoints.",
            )

            tester = AuthorizationTester(
                executor=active_executor,
                session_manager=self.session_manager,
                scope_guard=self.scope_guard,
                base_url=normalized_target,
            )

            candidate_findings: List[FindingRecord] = []
            tested_endpoints_count = 0

            for route in discovered_routes:
                if is_cancelled():
                    yield handle_cancellation()
                    return session

                ep_rec = endpoint_records[route.path]
                is_parameterized = bool(TEMPLATE_PARAM_REGEX.search(route.path))

                # Determine whether full cross-account comparison can proceed for this route
                owner_role = Role.ADMIN if route.category == EndpointCategory.ADMIN_FUNCTION else Role.USER_A
                owner_authenticated = self.session_manager.is_authenticated(owner_role)

                # Check if owner has a registered resource ID for parameterized routes
                owner_session = self.session_manager.get_session(owner_role)
                registered_res_id: Optional[str] = route.extracted_resource_id
                if not registered_res_id and is_parameterized and route.resource_type:
                    owned_ids = owner_session.owned_resources.get(route.resource_type.lower(), set())
                    if owned_ids:
                        registered_res_id = sorted(owned_ids)[0]

                can_run_full_differential = False
                test_roles_for_route: List[Role] = []

                if route.category == EndpointCategory.PUBLIC:
                    can_run_full_differential = True
                    owner_role = Role.ANONYMOUS
                    test_roles_for_route = [Role.USER_A] if user_a_ok else [Role.ANONYMOUS]
                elif route.category == EndpointCategory.ADMIN_FUNCTION and admin_ok:
                    can_run_full_differential = True
                    owner_role = Role.ADMIN
                    test_roles_for_route = [r for r in (Role.USER_A, Role.ANONYMOUS) if self.session_manager.is_authenticated(r)]
                elif not is_parameterized and user_a_ok and user_b_ok:
                    can_run_full_differential = True
                    owner_role = Role.USER_A
                    test_roles_for_route = [Role.USER_B, Role.ANONYMOUS]
                elif is_parameterized and user_a_ok and user_b_ok and registered_res_id:
                    can_run_full_differential = True
                    owner_role = Role.USER_A
                    test_roles_for_route = [Role.USER_B, Role.ANONYMOUS]

                if can_run_full_differential:
                    yield self._emit_event(
                        session,
                        EventType.STAGE_UPDATED,
                        AssessmentStage.AUTHORIZATION_TESTING,
                        f"Checking resource ownership and comparing responses for {route.method} {route.path}.",
                        {"endpoint": route.path, "owner_role": owner_role.value},
                    )
                    diff_res = tester.test_resource_access(
                        endpoint=route,
                        owner_role=owner_role,
                        test_roles=test_roles_for_route,
                        resource_id=registered_res_id,
                        method=route.method,
                    )
                    tested_endpoints_count += 1
                    ep_rec.test_status = "TESTED"
                    ep_rec.verdict = diff_res.overall_verdict.value
                    ep_rec.summary = diff_res.summary

                    if diff_res.is_discrepancy_detected:
                        yield self._emit_event(
                            session,
                            EventType.SUSPICIOUS_BEHAVIOR_DETECTED,
                            AssessmentStage.AUTHORIZATION_TESTING,
                            f"Response received on {route.path}. Protected-data validation pending ({diff_res.overall_verdict.value}).",
                            {
                                "endpoint": route.path,
                                "verdict": diff_res.overall_verdict.value,
                                "vulnerability_candidate": diff_res.vulnerability_candidate,
                            },
                        )
                        for evi in diff_res.evidence_artifacts:
                            outcome = diff_res.probe_outcomes.get(evi.test_role)
                            exposed_fields = (
                                set(outcome.comparison.test_inspection.sensitive_fields_found)
                                if outcome and outcome.comparison
                                else set()
                            )
                            exposed_fields_lower = {field.lower() for field in exposed_fields}
                            exposes_pii = bool(
                                exposed_fields_lower.intersection(
                                    {"email", "address", "streetaddress", "mobile", "phone", "ssn", "cardnum", "cardnumber", "cvv"}
                                )
                                or (
                                    outcome
                                    and outcome.comparison
                                    and outcome.comparison.test_inspection.extracted_emails
                                )
                            )
                            exposes_credentials = any(
                                any(marker in field for marker in ("password", "secret", "token", "apikey", "credential"))
                                for field in exposed_fields_lower
                            )
                            sev = self.severity_engine.calculate_severity(
                                vulnerability_type=diff_res.vulnerability_candidate or "BOLA_IDOR",
                                exposes_pii=exposes_pii,
                                exposes_credentials=exposes_credentials,
                                allows_privilege_escalation=(route.category == EndpointCategory.ADMIN_FUNCTION),
                            )
                            rem = self.remediation_engine.generate_patch(
                                vulnerability_type=diff_res.vulnerability_candidate or "BOLA_IDOR"
                            )
                            is_conf = evi.validation_status == EvidenceValidationStatus.CONFIRMED
                            fnd = FindingRecord(
                                id=evi.finding_id,
                                scan_id=scan_id,
                                title=(
                                    f"Confirmed {diff_res.vulnerability_candidate or 'Access Control Flaw'} on {route.path}"
                                    if is_conf
                                    else f"Suspicious Access Behavior on {route.path}"
                                ),
                                vulnerability_type=diff_res.vulnerability_candidate or "BROKEN_ACCESS_CONTROL",
                                severity=sev if is_conf else SeverityLevel.MEDIUM,
                                status="confirmed" if is_conf else "suspected",
                                validation_status=evi.validation_status.value,
                                access_verdict=(
                                    AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
                                    if is_conf
                                    else AccessVerdict.SUSPICIOUS_ACCESS.value
                                ),
                                target_endpoint=route.path,
                                http_method=route.method,
                                resource_id=evi.resource_id,
                                expected_behavior=evi.expected_behavior,
                                actual_behavior=evi.actual_behavior,
                                description=diff_res.summary,
                                remediation_guidance=rem,
                                evidence=evi,
                            )
                            candidate_findings.append(fnd)
                            ep_rec.associated_finding_ids.append(fnd.id)
                    else:
                        yield self._emit_event(
                            session,
                            EventType.STAGE_UPDATED,
                            AssessmentStage.AUTHORIZATION_TESTING,
                            f"No confirmed issue found in this test ({route.path} -> {diff_res.overall_verdict.value}).",
                            {"endpoint": route.path, "verdict": diff_res.overall_verdict.value},
                        )
                    self.repository.save_discovered_endpoint(ep_rec)

                else:
                    # Sessions or registered resource ownership unavailable for cross-user comparison.
                    # Execute a safe unauthenticated boundary check if non-parameterized, or skip cross-user comparison honestly.
                    if is_parameterized:
                        ep_rec.test_status = "SKIPPED_MISSING_SESSION"
                        ep_rec.verdict = None
                        ep_rec.summary = (
                            "Cross-account object comparison skipped: User A / User B sessions and owned resource IDs "
                            "are not configured."
                        )
                        self.repository.save_discovered_endpoint(ep_rec)
                        yield self._emit_event(
                            session,
                            EventType.STAGE_UPDATED,
                            AssessmentStage.AUTHORIZATION_TESTING,
                            f"Skipping cross-account comparison for {route.path}: User A/B sessions and resource ownership unavailable.",
                            {"endpoint": route.path, "test_status": ep_rec.test_status},
                        )
                    else:
                        # Non-parameterized route (e.g. /api/Users, /rest/admin/application-configuration, /rest/user/whoami)
                        concrete_url = discovery.build_concrete_url(route)
                        anon_resp = active_executor.send_request(
                            role=Role.ANONYMOUS,
                            method=route.method,
                            url=concrete_url,
                        )
                        tested_endpoints_count += 1
                        insp = self.analyzer.inspect_response(anon_resp)

                        is_admin_candidate = (
                            route.category == EndpointCategory.ADMIN_FUNCTION
                            or "/admin/" in route.path.lower()
                        )
                        if (
                            is_admin_candidate
                            and insp.is_http_success
                            and not insp.is_empty_payload
                            and not insp.is_spa_html_fallback
                        ):
                            # Inspect response content: does it disclose privileged administrative controls/secrets or public UI configuration?
                            # A single anonymous response cannot establish a role boundary.
                            # Keyword matching is not proof that the response is protected
                            # data or that the caller crossed an authorization boundary.
                            fnd_val_status = EvidenceValidationStatus.SUSPICIOUS
                            fnd_access_verdict = AccessVerdict.SUSPICIOUS_ACCESS
                            fnd_status_str = "suspected"
                            fnd_sev = SeverityLevel.LOW
                            fnd_title_str = f"Suspicious Unauthenticated Access to Admin Route {route.path}"
                            fnd_summary = (
                                f"Unauthenticated GET request to administrative route {route.path} returned HTTP {anon_resp.status_code} "
                                f"({anon_resp.content_length} bytes). This single-role response has no authenticated admin baseline, "
                                "so the access-control behavior remains suspicious and unconfirmed."
                            )

                            ep_rec.test_status = "PARTIAL_UNAUTH_ONLY"
                            ep_rec.verdict = fnd_access_verdict.value
                            ep_rec.summary = fnd_summary

                            rem_preview = self.remediation_engine.generate_patch("BFLA")
                            yield self._emit_event(
                                session,
                                EventType.SUSPICIOUS_BEHAVIOR_DETECTED,
                                AssessmentStage.AUTHORIZATION_TESTING,
                                f"Response received on {route.path}. Protected-data validation pending (unauthenticated HTTP {anon_resp.status_code} on admin route).",
                                {
                                    "endpoint": route.path,
                                    "status_code": anon_resp.status_code,
                                    "verdict": fnd_access_verdict.value,
                                    "actual_behavior": f"Anonymous request received HTTP {anon_resp.status_code} response ({anon_resp.content_length} bytes).",
                                    "expected_behavior": f"Administrative route '{route.path}' should restrict unauthenticated access (HTTP 401/403).",
                                    "validation_status": fnd_val_status.value,
                                    "remediation": rem_preview,
                                },
                            )
                            evi = self.evidence_validator.create_and_sign_evidence(
                                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                                test_role=Role.ANONYMOUS,
                                authorized_role=Role.ADMIN,
                                method=route.method,
                                url=concrete_url,
                                headers={},
                                response=anon_resp,
                                endpoint=route.path,
                                resource_id=None,
                                expected_behavior=(
                                    f"Administrative route '{route.path}' should restrict unauthenticated access (HTTP 401/403)."
                                ),
                                actual_behavior=(
                                    f"Anonymous request received HTTP {anon_resp.status_code} JSON response "
                                    f"({anon_resp.content_length} bytes)."
                                ),
                                validation_status=fnd_val_status,
                            )
                            rem = self.remediation_engine.generate_patch("BFLA")
                            fnd = FindingRecord(
                                id=evi.finding_id,
                                scan_id=session.id,
                                title=fnd_title_str,
                                vulnerability_type="BFLA",
                                severity=fnd_sev,
                                status=fnd_status_str,
                                validation_status=fnd_val_status.value,
                                access_verdict=fnd_access_verdict.value,
                                target_endpoint=route.path,
                                http_method=route.method,
                                resource_id=None,
                                expected_behavior=evi.expected_behavior,
                                actual_behavior=evi.actual_behavior,
                                description=fnd_summary,
                                remediation_guidance=rem,
                                evidence=evi,
                            )
                            candidate_findings.append(fnd)
                            ep_rec.associated_finding_ids.append(fnd.id)
                        else:
                            ep_rec.test_status = "PARTIAL_UNAUTH_ONLY"
                            ep_rec.verdict = AccessVerdict.CORRECTLY_DENIED.value
                            ep_rec.summary = (
                                f"Unauthenticated boundary check passed (HTTP {anon_resp.status_code}); "
                                f"authenticated role comparison skipped because sessions were unavailable."
                            )
                            yield self._emit_event(
                                session,
                                EventType.STAGE_UPDATED,
                                AssessmentStage.AUTHORIZATION_TESTING,
                                f"No confirmed issue found in this test ({route.path} -> HTTP {anon_resp.status_code}).",
                                {
                                    "endpoint": route.path,
                                    "status_code": anon_resp.status_code,
                                    "verdict": AccessVerdict.CORRECTLY_DENIED.value,
                                },
                            )
                        self.repository.save_discovered_endpoint(ep_rec)

            session.endpoints_tested_count = tested_endpoints_count
            self.repository.save_scan_session(session)
            self._complete_stage(
                session,
                AssessmentStage.AUTHORIZATION_TESTING,
                t_stage5,
                f"Evaluated {tested_endpoints_count} of {len(discovered_routes)} routes.",
            )
            yield self._emit_event(
                session,
                EventType.AUTHORIZATION_TEST_COMPLETED,
                AssessmentStage.AUTHORIZATION_TESTING,
                f"Authorization behavior testing completed ({tested_endpoints_count} routes probed).",
                {"tested_count": tested_endpoints_count, "total_routes": len(discovered_routes)},
            )

            if is_cancelled():
                yield handle_cancellation()
                return session

            # ==================================================================
            # STAGE 6: Validating Evidence
            # ==================================================================
            t_stage6 = self._start_stage(
                session,
                AssessmentStage.EVIDENCE_VALIDATION,
                "Validating cryptographic SHA-256 signatures and completeness of candidate findings.",
            )
            yield self._emit_event(
                session,
                EventType.EVIDENCE_VALIDATION_STARTED,
                AssessmentStage.EVIDENCE_VALIDATION,
                "Checking finding evidence integrity and validation status.",
                {"candidate_count": len(candidate_findings)},
            )

            confirmed_count = 0
            suspicious_count = 0

            for fnd in candidate_findings:
                if is_cancelled():
                    yield handle_cancellation()
                    return session

                if fnd.evidence is not None:
                    is_complete = self.evidence_validator.validate_artifact_completeness(fnd.evidence)
                    if not is_complete and fnd.validation_status == EvidenceValidationStatus.CONFIRMED.value:
                        # Downgrade if evidence completeness fails
                        fnd.validation_status = EvidenceValidationStatus.SUSPICIOUS.value
                        fnd.access_verdict = AccessVerdict.SUSPICIOUS_ACCESS.value
                        fnd.status = "suspected"
                        fnd.evidence.validation_status = EvidenceValidationStatus.SUSPICIOUS

                if (
                    fnd.validation_status == EvidenceValidationStatus.CONFIRMED.value
                    and fnd.access_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
                ):
                    confirmed_count += 1
                    self.repository.save_finding(fnd)
                    yield self._emit_event(
                        session,
                        EventType.FINDING_CONFIRMED,
                        AssessmentStage.EVIDENCE_VALIDATION,
                        f"Evidence validated. Confirmed vulnerability: {fnd.title}",
                        {
                            "finding_id": fnd.id,
                            "endpoint": fnd.target_endpoint,
                            "severity": fnd.severity.value if hasattr(fnd.severity, "value") else str(fnd.severity),
                            "sha256": fnd.evidence.evidence_sha256 if fnd.evidence else "",
                            "title": fnd.title,
                            "category": fnd.vulnerability_category or fnd.vulnerability_type,
                            "actual_behavior": fnd.actual_behavior,
                            "expected_behavior": fnd.expected_behavior,
                            "impact": fnd.impact_explanation or fnd.description,
                            "remediation": fnd.remediation_guidance or fnd.remediation_recommendation,
                            "access_verdict": fnd.access_verdict,
                            "validation_status": fnd.validation_status,
                        },
                    )
                else:
                    suspicious_count += 1
                    self.repository.save_finding(fnd)
                    yield self._emit_event(
                        session,
                        EventType.STAGE_UPDATED,
                        AssessmentStage.EVIDENCE_VALIDATION,
                        f"Evidence validated for suspicious result on {fnd.target_endpoint} (requires authenticated baseline review).",
                        {
                            "finding_id": fnd.id,
                            "endpoint": fnd.target_endpoint,
                            "validation_status": fnd.validation_status,
                        },
                    )

            session.confirmed_findings_count = confirmed_count
            session.suspicious_results_count = suspicious_count

            evi_msg = (
                f"Evidence validated ({confirmed_count} confirmed, {suspicious_count} suspicious)."
                if candidate_findings
                else "Evidence validation completed (0 discrepancies required signing)."
            )
            self._complete_stage(
                session,
                AssessmentStage.EVIDENCE_VALIDATION,
                t_stage6,
                evi_msg,
            )
            yield self._emit_event(
                session,
                EventType.EVIDENCE_VALIDATION_COMPLETED,
                AssessmentStage.EVIDENCE_VALIDATION,
                evi_msg,
                {"confirmed_count": confirmed_count, "suspicious_count": suspicious_count},
            )

            if is_cancelled():
                yield handle_cancellation()
                return session

            # ==================================================================
            # STAGE 7: Preparing Final Findings
            # ==================================================================
            t_stage7 = self._start_stage(
                session,
                AssessmentStage.REPORT_PREPARATION,
                "Compiling persisted assessment report, endpoint matrix, and evidence records.",
            )
            session.status = "COMPLETED"
            session.completed_at = datetime.now(timezone.utc)
            session.summary_text = (
                f"Assessment completed against {normalized_target}. "
                f"Discovered {session.endpoints_discovered_count} routes, probed {session.endpoints_tested_count} routes, "
                f"identified {session.confirmed_findings_count} confirmed finding(s) and "
                f"{session.suspicious_results_count} suspicious result(s)."
            )
            self._complete_stage(
                session,
                AssessmentStage.REPORT_PREPARATION,
                t_stage7,
                session.summary_text,
            )
            yield self._emit_event(
                session,
                EventType.ASSESSMENT_COMPLETED,
                AssessmentStage.REPORT_PREPARATION,
                session.summary_text,
                {
                    "endpoints_discovered": session.endpoints_discovered_count,
                    "endpoints_tested": session.endpoints_tested_count,
                    "confirmed_findings": session.confirmed_findings_count,
                    "suspicious_results": session.suspicious_results_count,
                },
            )
            self.repository.save_scan_session(session)
            return session

        except Exception as exc:
            safe_error = sanitize_event_text(str(exc))
            logger.error("Assessment halted due to error", extra={"error": safe_error})
            session.status = "FAILED"
            session.completed_at = datetime.now(timezone.utc)
            is_persist = "database" in str(exc).lower() or "no column" in str(exc).lower() or "sqlite" in str(type(exc)).lower() or "persistence" in str(exc).lower()
            session.failure_reason = "PERSISTENCE_ERROR" if is_persist else "EXECUTION_ERROR"
            session.summary_text = f"Assessment halted due to error: {safe_error}"
            self._skip_remaining_stages(session, f"Halted: {safe_error}")
            yield self._emit_event(
                session,
                EventType.ASSESSMENT_FAILED,
                AssessmentStage.REPORT_PREPARATION,
                f"Assessment failed: {safe_error}",
                {"error": safe_error, "failure_reason": session.failure_reason},
            )
            try:
                self.repository.save_scan_session(session)
            except Exception as save_err:
                logger.error(f"Failed to record session failure state: {save_err}")
            return session
        finally:
            if owns_executor:
                active_executor.close()

    def run_assessment_sync(
        self,
        target_url: str,
        cancel_token: Optional[CancellationToken] = None,
    ) -> Tuple[ScanSessionRecord, List[AssessmentEvent]]:
        """Runs the full assessment stream synchronously and returns the session and all emitted events."""
        events: List[AssessmentEvent] = []
        gen = self.stream_assessment(target_url=target_url, cancel_token=cancel_token)
        session: Optional[ScanSessionRecord] = None
        try:
            while True:
                evt = next(gen)
                events.append(evt)
        except StopIteration as stop:
            session = stop.value

        if session is None:
            sessions = self.repository.list_scan_sessions(limit=1)
            session = sessions[0] if sessions else ScanSessionRecord(id="unknown", target_url=target_url, status="FAILED")
        return session, events


class AssessmentQueryAdapter:
    """Deterministic Assessment-Query Adapter for answering user questions over actual scan data.

    Note: Claude LLM conversational reasoning is not integrated in Phase 3.5.
    This adapter inspects persisted ScanSessionRecord, DiscoveredEndpointRecord,
    FindingRecord, and AssessmentEvent data to provide factual, hallucination-free answers.
    """

    def __init__(self, repository: FindingRepository):
        self.repository = repository

    def answer_question(self, scan_id: Optional[str], question: str) -> str:
        """Answers user questions deterministically using persisted assessment records."""
        q_clean = (question or "").strip()
        if not q_clean:
            return "Please enter a question about the current security assessment."

        if not scan_id:
            return (
                "**[Deterministic Assessment Query Adapter]** No active assessment is loaded. "
                "Enter `http://localhost:3000` above and click **Start Assessment**, or select a past scan from the sidebar."
            )

        session = self.repository.get_scan_session(scan_id)
        if not session:
            return f"**[Deterministic Assessment Query Adapter]** Assessment `{scan_id}` could not be found in SQLite storage."

        endpoints = self.repository.list_discovered_endpoints(scan_id)
        findings = self.repository.list_findings(scan_id)
        confirmed = [
            f for f in findings
            if f.validation_status == EvidenceValidationStatus.CONFIRMED.value
            and f.access_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
        ]
        suspicious = [f for f in findings if f not in confirmed]

        q_lower = q_clean.lower()

        # 1. "What has the agent completed?"
        if any(p in q_lower for p in ("what has the agent completed", "completed", "status", "progress", "stages")):
            lines = [
                f"**Assessment Status (`{session.id}`):** `{session.status}` on target `{session.target_url}`",
                "",
                "**Stage Execution Summary:**",
            ]
            for stg_rec in session.stages.values():
                dur_str = f" ({stg_rec.duration_ms:.1f} ms)" if stg_rec.duration_ms is not None else ""
                lines.append(f"- **{stg_rec.label}**: `{stg_rec.status.value.upper()}`{dur_str} — {stg_rec.explanation}")
            lines.append("")
            lines.append(
                f"**Totals:** `{session.endpoints_discovered_count}` routes discovered, "
                f"`{session.endpoints_tested_count}` routes probed, "
                f"`{len(confirmed)}` confirmed finding(s), `{len(suspicious)}` suspicious result(s)."
            )
            return "\n".join(lines)

        # 2. "Which endpoints were discovered?"
        if "discovered" in q_lower or ("which endpoints" in q_lower and "tested" not in q_lower):
            if not endpoints:
                return f"No endpoints were discovered for assessment `{session.id}`."
            lines = [f"**Discovered Endpoints ({len(endpoints)} total):**", ""]
            for ep in endpoints:
                auth_tag = "Auth Required" if ep.requires_auth else "Public"
                lines.append(f"- `{ep.method} {ep.path}` — Category: `{ep.category}` ({auth_tag})")
            return "\n".join(lines)

        # 3. "Which endpoints were tested?"
        if "tested" in q_lower or "probed" in q_lower or "skipped" in q_lower:
            if not endpoints:
                return f"No endpoints were recorded for assessment `{session.id}`."
            tested = [e for e in endpoints if e.test_status in ("TESTED", "PARTIAL_UNAUTH_ONLY")]
            skipped = [e for e in endpoints if e not in tested]
            lines = [f"**Endpoint Testing Breakdown ({len(tested)} probed, {len(skipped)} skipped):**", ""]
            for ep in tested:
                verdict_str = ep.verdict or "N/A"
                lines.append(f"- **Probed (`{ep.test_status}`):** `{ep.method} {ep.path}` → Verdict: `{verdict_str}` — {ep.summary}")
            for ep in skipped:
                lines.append(f"- **Skipped (`{ep.test_status}`):** `{ep.method} {ep.path}` — {ep.summary}")
            return "\n".join(lines)

        # 4. "Why was this result marked suspicious?"
        if "suspicious" in q_lower or "why was" in q_lower:
            if not suspicious:
                return (
                    "There are currently **0 suspicious results** in this assessment. "
                    + (f"There are **{len(confirmed)} confirmed finding(s)**." if confirmed else "")
                )
            lines = [f"**Why {len(suspicious)} Result(s) Were Marked `SUSPICIOUS_ACCESS` Instead of `CONFIRMED`:**", ""]
            for f in suspicious:
                lines.append(f"### `{f.http_method} {f.target_endpoint}` ({f.title})")
                lines.append(f"- **Access Verdict:** `{f.access_verdict}` (`Validation: {f.validation_status}`)")
                lines.append(f"- **Expected Behavior:** {f.expected_behavior}")
                lines.append(f"- **Actual Behavior:** {f.actual_behavior}")
                lines.append(f"- **Reasoning:** {f.description}")
                lines.append(
                    "- **Policy Note:** AuthScope never marks an issue `CONFIRMED` based solely on HTTP 200 without "
                    "a verified cross-account baseline ownership match."
                )
            return "\n".join(lines)

        # 5. "Show me the evidence for this finding."
        if "evidence" in q_lower or "proof" in q_lower or "sha" in q_lower:
            if not findings:
                return "No findings or evidence artifacts were generated during this assessment."
            lines = [f"**Validated Evidence Artifacts ({len(findings)} record(s)):**", ""]
            for f in findings:
                evi = f.evidence
                lines.append(f"### `{f.id}` — {f.title}")
                lines.append(f"- **Endpoint:** `{f.http_method} {f.target_endpoint}` (Resource ID: `{f.resource_id or 'N/A'}`)")
                lines.append(f"- **Validation Status:** `{f.validation_status}` | **Verdict:** `{f.access_verdict}`")
                if evi:
                    t_role = evi.test_role.value if hasattr(evi.test_role, "value") else str(evi.test_role)
                    a_role = evi.authorized_role.value if hasattr(evi.authorized_role, "value") else str(evi.authorized_role)
                    lines.append(f"- **Roles:** Tested as `{t_role}` vs. Authorized `{a_role}`")
                    lines.append(f"- **Evidence SHA-256:** `{evi.evidence_sha256}`")
                    lines.append(f"- **Sanitized Response Excerpt (HTTP {evi.response_status}):**")
                    lines.append(f"```json\n{evi.sanitized_response_evidence[:600]}\n```")
            return "\n".join(lines)

        # 6. "What should I fix first?"
        if "fix" in q_lower or "remediat" in q_lower or "priorit" in q_lower or "recommend" in q_lower:
            if not findings:
                return (
                    "No confirmed or suspicious authorization flaws were detected in this run. "
                    "To perform full cross-account BOLA/IDOR verification on parameterized object routes (`/rest/basket/{id}`), "
                    "configure `USER_A_TOKEN` and `USER_B_TOKEN` in `.env` and re-run the assessment."
                )
            severity_rank = {
                SeverityLevel.CRITICAL: 1,
                SeverityLevel.HIGH: 2,
                SeverityLevel.MEDIUM: 3,
                SeverityLevel.LOW: 4,
                SeverityLevel.INFO: 5,
            }
            ordered = sorted(
                findings,
                key=lambda item: (
                    0 if item.validation_status == EvidenceValidationStatus.CONFIRMED.value else 1,
                    severity_rank.get(item.severity, 99),
                ),
            )
            top = ordered[0]
            top_sev = top.severity.value if hasattr(top.severity, "value") else str(top.severity)
            lines = [
                "**Remediation Priority Plan:**",
                "",
                f"1. **Top Priority:** `{top.title}` (`{top.http_method} {top.target_endpoint}`)",
                f"   - **Severity:** `{top_sev}` | **Status:** `{top.validation_status}` (`{top.access_verdict}`)",
                f"   - **Issue:** {top.actual_behavior or top.description}",
                "   - **Recommended Code Fix:**",
                f"```javascript\n{top.remediation_guidance}\n```",
            ]
            if len(ordered) > 1:
                lines.append("")
                lines.append("**Subsequent Items:**")
                for idx, item in enumerate(ordered[1:], start=2):
                    item_sev = item.severity.value if hasattr(item.severity, "value") else str(item.severity)
                    lines.append(
                        f"{idx}. `{item.http_method} {item.target_endpoint}` — `{item_sev}` (`{item.validation_status}`)"
                    )
            return "\n".join(lines)

        # Fallback deterministic response
        return (
            f"**[Deterministic Assessment Query Adapter]** *(Claude LLM integration is not enabled in Phase 3.5)*\n\n"
            f"**Current Assessment (`{session.id}`):** `{session.status}` on `{session.target_url}`\n"
            f"- **Routes Discovered:** `{session.endpoints_discovered_count}` | **Routes Probed:** `{session.endpoints_tested_count}`\n"
            f"- **Confirmed Findings:** `{len(confirmed)}` | **Suspicious Results:** `{len(suspicious)}`\n\n"
            f"You can ask deterministic questions such as:\n"
            f"- *\"What has the agent completed?\"*\n"
            f"- *\"Which endpoints were discovered?\"*\n"
            f"- *\"Which endpoints were tested?\"*\n"
            f"- *\"Why was this result marked suspicious?\"*\n"
            f"- *\"Show me the evidence for this finding.\"*\n"
            f"- *\"What should I fix first?\"*"
        )

    def export_report_json(self, scan_id: str) -> str:
        """Exports the complete persisted assessment report as formatted, sanitized JSON."""
        session = self.repository.get_scan_session(scan_id)
        if not session:
            return json.dumps({"error": f"Assessment {scan_id} not found."}, indent=2)
        endpoints = self.repository.list_discovered_endpoints(scan_id)
        findings = self.repository.list_findings(scan_id)
        events = self.repository.list_events(scan_id)
        payload = {
            "report_metadata": {
                "platform": "AuthScope Security Assessment Platform",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_id": session.id,
            },
            "session": session.model_dump(mode="json"),
            "discovered_endpoints": [ep.model_dump(mode="json") for ep in endpoints],
            "findings": [f.model_dump(mode="json") for f in findings],
            "events": [e.model_dump(mode="json") for e in events],
        }
        return json.dumps(payload, indent=2)

    def export_report_markdown(self, scan_id: str) -> str:
        """Exports the complete persisted assessment report as structured Markdown."""
        session = self.repository.get_scan_session(scan_id)
        if not session:
            return f"# Assessment Report Not Found (`{scan_id}`)\n"
        endpoints = self.repository.list_discovered_endpoints(scan_id)
        findings = self.repository.list_findings(scan_id)
        confirmed = [
            f for f in findings
            if f.validation_status == EvidenceValidationStatus.CONFIRMED.value
            and f.access_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
        ]
        suspicious = [f for f in findings if f not in confirmed]

        disc_count = session.endpoints_discovered_count or len(endpoints)
        probed_count = session.endpoints_tested_count or len([ep for ep in endpoints if (ep.test_status or "").upper() not in ("UNTESTED", "SKIPPED_MISSING_SESSION", "SKIPPED")])
        conf_count = session.confirmed_findings_count or len(confirmed)
        susp_count = session.suspicious_results_count or len(suspicious)

        md = [
            f"# AuthScope Security Assessment Report — `{session.id}`",
            "",
            f"- **Target URL:** `{session.target_url}`",
            f"- **Status:** `{session.status}`",
            f"- **Started At:** `{session.started_at.isoformat()}`",
            f"- **Completed At:** `{session.completed_at.isoformat() if session.completed_at else 'N/A'}`",
            f"- **Routes Discovered:** `{disc_count}`",
            f"- **Routes Probed:** `{probed_count}`",
            f"- **Confirmed Vulnerabilities:** `{conf_count}`",
            f"- **Suspicious Results:** `{susp_count}`",
            "",
            "## 1. Stage Timeline",
            "",
            "| Stage | Status | Duration (ms) | Explanation |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for stg_rec in session.stages.values():
            dur = f"{stg_rec.duration_ms:.1f}" if stg_rec.duration_ms is not None else "—"
            md.append(f"| {stg_rec.label} | `{stg_rec.status.value.upper()}` | {dur} | {stg_rec.explanation} |")

        md.extend([
            "",
            "## 2. Discovered Endpoints",
            "",
            "| Method | Path | Category | Test Status | Verdict |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for ep in endpoints:
            md.append(
                f"| `{ep.method}` | `{ep.path}` | `{ep.category}` | `{ep.test_status}` | `{ep.verdict or 'N/A'}` |"
            )

        md.extend([
            "",
            f"## 3. Confirmed Vulnerabilities ({len(confirmed)})",
            "",
        ])
        if not confirmed:
            md.append("_No confirmed cross-account authorization vulnerabilities recorded in this run._")
        for f in confirmed:
            f_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            md.extend([
                f"### [{f_sev}] {f.title}",
                f"- **Finding ID:** `{f.id}`",
                f"- **Endpoint:** `{f.http_method} {f.target_endpoint}` (Resource ID: `{f.resource_id or 'N/A'}`)",
                f"- **Access Verdict:** `{f.access_verdict}` (`Validation: {f.validation_status}`)",
                f"- **Expected Behavior:** {f.expected_behavior}",
                f"- **Actual Behavior:** {f.actual_behavior}",
                f"- **Evidence SHA-256:** `{f.evidence.evidence_sha256 if f.evidence else 'N/A'}`",
                f"- **Remediation:**",
                f"```javascript\n{f.remediation_guidance}\n```",
                "",
            ])

        md.extend([
            "",
            f"## 4. Suspicious Results ({len(suspicious)})",
            "",
        ])
        if not suspicious:
            md.append("_No suspicious access behaviors recorded in this run._")
        for f in suspicious:
            f_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            md.extend([
                f"### [{f_sev}] {f.title}",
                f"- **Finding ID:** `{f.id}`",
                f"- **Endpoint:** `{f.http_method} {f.target_endpoint}`",
                f"- **Access Verdict:** `{f.access_verdict}` (`Validation: {f.validation_status}`)",
                f"- **Expected Behavior:** {f.expected_behavior}",
                f"- **Actual Behavior:** {f.actual_behavior}",
                f"- **Evidence SHA-256:** `{f.evidence.evidence_sha256 if f.evidence else 'N/A'}`",
                f"- **Remediation:**",
                f"```javascript\n{f.remediation_guidance}\n```",
                "",
            ])

        return "\n".join(md)

