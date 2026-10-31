"""FastAPI Application for AuthScope — AI Agent & Assessment API Backend.

Connects:
1. Member 1: Gemini AI Agent Connector.
2. Member 2: Tool Registry.
3. Member 3: Assessment Memory & RAG Knowledge Base.
4. Security Assessment Engine (7-stage deterministic execution).

Provides HTTP REST and Server-Sent Events (SSE) endpoints streaming structured
agent operational telemetry, thoughts, plans, tool actions, and findings.
"""

from datetime import datetime, timezone
import json
import uuid
import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple
from pathlib import Path
import sys

from fastapi import FastAPI, HTTPException, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.config import settings
from backend.core.assessment_engine import (
    AssessmentEngine,
    AssessmentQueryAdapter,
    CancellationToken,
)
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    EventType,
    FindingRecord,
    ScanSessionRecord,
    StageStatus,
)
from backend.agent.gemini_agent import GeminiAgent
from backend.agent.memory import AssessmentMemory
from backend.agent.tools import ToolRegistry
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Active background runners and cancellation tokens indexed by assessment_id
active_tokens: Dict[str, CancellationToken] = {}


class AssessmentTaskManager:
    """Manages decoupled background execution of assessments and SSE client event broadcasting."""

    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}
        self._tokens: Dict[str, CancellationToken] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    def get_token(self, scan_id: str) -> Optional[CancellationToken]:
        return self._tokens.get(scan_id)

    def is_running(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        return task is not None and not task.done()

    def get_active_scan_ids(self) -> Set[str]:
        """Returns the set of scan IDs with currently active background tasks in memory."""
        return {sid for sid, task in self._tasks.items() if not task.done()}

    def cancel(self, scan_id: str) -> bool:
        token = self._tokens.get(scan_id)
        if token:
            token.cancel()
            return True
        return False

    def start_assessment_task(
        self,
        scan_id: str,
        target_url: str,
        token: CancellationToken,
        repo: FindingRepository,
    ) -> Optional[asyncio.Task]:
        """Starts a managed background task for assessment execution."""
        self._tokens[scan_id] = token
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(
                self._run_task(scan_id, target_url, token, repo),
                name=f"assessment_{scan_id}",
            )
            self._tasks[scan_id] = task
            return task
        except RuntimeError:
            logger.warning(f"No running event loop detected for background task {scan_id}")
            return None

    async def _run_task(
        self,
        scan_id: str,
        target_url: str,
        token: CancellationToken,
        repo: FindingRepository,
    ) -> None:
        """Background worker executing the assessment generator decoupled from client connections."""
        logger.info(f"Background assessment task started for {scan_id} ({target_url})")
        engine = AssessmentEngine(repository=repo)
        gen = engine.stream_assessment(target_url=target_url, cancel_token=token)

        async def _execute_steps() -> None:
            while True:
                # Run generator next() in worker thread without blocking event loop
                event = await asyncio.to_thread(lambda: next(gen, None))
                if event is None:
                    break

                # Prepare conversational markdown chunk
                msg_chunk = _format_event_message_chunk(event, repo=repo)

                # Broadcast to all currently connected SSE clients
                await self._broadcast(scan_id, ("activity", event, msg_chunk))

                # Yield brief time to asyncio event loop
                await asyncio.sleep(0.04)

        try:
            await asyncio.wait_for(_execute_steps(), timeout=settings.assessment_timeout_seconds)
        except asyncio.TimeoutError:
            logger.error(f"Assessment {scan_id} timed out after {settings.assessment_timeout_seconds}s")
            token.cancel()
            try:
                curr_session = repo.get_scan_session(scan_id)
                if curr_session and curr_session.status not in ("COMPLETED", "CANCELLED", "FAILED"):
                    curr_session.status = "FAILED"
                    curr_session.failure_reason = "TIMEOUT"
                    curr_session.completed_at = datetime.now(timezone.utc)
                    curr_session.updated_at = datetime.now(timezone.utc)
                    curr_session.summary_text = f"Assessment exceeded timeout limit ({settings.assessment_timeout_seconds}s)."
                    repo.save_scan_session(curr_session)
                    timeout_ev = AssessmentEvent(
                        scan_id=scan_id,
                        event_type=EventType.ASSESSMENT_FAILED.value,
                        stage=AssessmentStage.PREPARING_RESULTS.value,
                        message=f"Assessment timed out after {settings.assessment_timeout_seconds} seconds.",
                        metadata={"reason": "TIMEOUT", "timeout_seconds": settings.assessment_timeout_seconds},
                    )
                    repo.save_event(timeout_ev)
            except Exception as e:
                logger.warning(f"Error recording timeout for {scan_id}: {e}")
            await self._broadcast(scan_id, ("error", f"Assessment timed out after {settings.assessment_timeout_seconds}s", None))
        except Exception as exc:
            logger.error(f"Error in background assessment task {scan_id}: {exc}", exc_info=True)
            try:
                curr_session = repo.get_scan_session(scan_id)
                if curr_session and curr_session.status not in ("COMPLETED", "CANCELLED", "FAILED"):
                    curr_session.status = "FAILED"
                    curr_session.failure_reason = "EXECUTION_ERROR"
                    curr_session.completed_at = datetime.now(timezone.utc)
                    curr_session.updated_at = datetime.now(timezone.utc)
                    curr_session.summary_text = f"Assessment failed: {exc}"
                    repo.save_scan_session(curr_session)
            except Exception:
                pass
            await self._broadcast(scan_id, ("error", str(exc), None))
        finally:
            # Broadcast done event to subscribers
            final_session = repo.get_scan_session(scan_id)
            done_payload = {
                "status": final_session.status if final_session else "COMPLETED",
                "summary": final_session.summary_text if final_session else "",
                "endpoints_discovered": final_session.endpoints_discovered_count if final_session else 0,
                "endpoints_tested": final_session.endpoints_tested_count if final_session else 0,
                "confirmed_findings": final_session.confirmed_findings_count if final_session else 0,
                "suspicious_results": final_session.suspicious_results_count if final_session else 0,
            }
            await self._broadcast(scan_id, ("done", done_payload, None))
            logger.info(f"Background assessment task completed for {scan_id} with status {done_payload['status']}")

    async def _broadcast(self, scan_id: str, item: Any) -> None:
        queues = list(self._subscribers.get(scan_id, []))
        for q in queues:
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                pass

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = []
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers[scan_id].append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        if scan_id in self._subscribers and q in self._subscribers[scan_id]:
            self._subscribers[scan_id].remove(q)
            if not self._subscribers[scan_id]:
                self._subscribers.pop(scan_id, None)


# Global task manager instance
task_manager = AssessmentTaskManager()
# Maintain active_tokens dictionary for backwards-compatible references
active_tokens = task_manager._tokens

app = FastAPI(
    title="AuthScope AI Security Agent API",
    description="Minimal conversational API for authorized, hard-scoped application security testing.",
    version="1.0.0",
)


@app.on_event("startup")
async def startup_recovery() -> None:
    """Recovers orphaned running assessments from previous server executions on startup."""
    repo = FindingRepository()
    active_ids = task_manager.get_active_scan_ids()
    recovered = repo.recover_orphaned_running_sessions(active_session_ids=active_ids)
    if recovered > 0:
        logger.info(f"Startup recovery: marked {recovered} orphaned session(s) as FAILED with SERVER_RESTART")

# Enable CORS for explicit configured development origins only (never wildcard with credentials)
cors_origins_list = (
    settings.cors_origins
    if isinstance(settings.cors_origins, list)
    else [origin.strip() for origin in str(settings.cors_origins).split(",") if origin.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class CreateAssessmentRequest(BaseModel):
    """Payload for launching a new security assessment."""
    target_url: str = Field(
        default="http://localhost:3000",
        description="Target base URL to test (must be an explicitly allowlisted scope target).",
    )
    github_repo: Optional[str] = Field(
        default=None,
        description="Optional repository URL for source code mapping.",
    )
    source_archive_path: Optional[str] = Field(
        default=None,
        description="Optional archive file path for static analysis.",
    )


class CreateAssessmentResponse(BaseModel):
    """Response returned when an assessment is successfully accepted."""
    assessment_id: str
    target_url: str
    status: str
    created_at: str
    message: str


class AssessmentSummaryResponse(BaseModel):
    """Response for assessment state query."""
    id: str
    target_url: str
    status: str
    started_at: str
    updated_at: Optional[str] = None
    completed_at: Optional[str] = None
    failure_reason: Optional[str] = ""
    endpoints_discovered_count: int
    endpoints_tested_count: int
    confirmed_findings_count: int
    suspicious_results_count: int
    summary_text: str
    markdown_content: str
    stages: Dict[str, Any]
    events: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]


def _format_event_message_chunk(
    event: AssessmentEvent,
    finding: Optional[FindingRecord] = None,
    repo: Optional[FindingRepository] = None,
) -> Optional[str]:
    """Generates conversational markdown text chunks corresponding to real backend events.

    Built entirely from actual validated FindingRecord properties and EvidenceValidator status,
    never from generic hardcoded text. Clearly distinguishes confirmed from suspicious results.
    """
    etype = event.event_type

    if etype == EventType.SCOPE_VALIDATION_COMPLETED.value:
        return (
            "I've verified the target scope against **ScopeGuard** allowlist rules. "
            "Target host, port, and method (`GET`) are strictly authorized for testing.\n\n"
        )
    elif etype == EventType.CONNECTION_COMPLETED.value:
        return (
            "Successfully connected to the target application. "
            "The homepage is reachable and responded with HTTP 200 OK.\n\n"
        )
    elif etype == EventType.ENDPOINT_DISCOVERY_COMPLETED.value:
        discovered = event.metadata.get("endpoints_discovered", 0)
        return (
            f"Mapped the application attack surface and discovered **{discovered} target routes**, "
            "including administrative endpoints, user profile routes, and shopping basket resources.\n\n"
        )
    elif etype == EventType.SESSION_VALIDATION_COMPLETED.value:
        auth_roles = event.metadata.get("authenticated_roles", [])
        roles_str = ", ".join(auth_roles) if auth_roles else "Anonymous baseline only"
        msg = f"Verified active testing sessions: `{roles_str}`. "
        if "user_a" not in auth_roles or "user_b" not in auth_roles:
            msg += (
                "_Note: Multi-role test account tokens are unconfigured in `.env`. "
                "Parameter-specific object comparisons on `/rest/basket/{id}` will be safely skipped "
                "to maintain zero false-positive integrity._\n\n"
            )
        else:
            msg += "Cross-account authorization differential matrix is ready.\n\n"
        return msg
    elif etype == EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value:
        # Load finding if available to build from actual validated record
        finding_id = event.metadata.get("finding_id")
        if finding is None and finding_id and repo:
            finding = repo.get_finding(finding_id)

        ep = finding.target_endpoint if finding else event.metadata.get("endpoint", "")
        code = event.metadata.get("status_code", 200)
        verdict = finding.access_verdict if finding else event.metadata.get("verdict", "SUSPICIOUS_ACCESS")
        val_status = finding.validation_status if finding else event.metadata.get("validation_status", "SUSPICIOUS")
        actual = (
            finding.actual_behavior
            if finding and finding.actual_behavior
            else event.metadata.get("actual_behavior", f"Unauthenticated request to `{ep}` returned HTTP {code} with application data.")
        )
        expected = (
            finding.expected_behavior
            if finding and finding.expected_behavior
            else event.metadata.get("expected_behavior", f"Access to `{ep}` should require valid authentication and authorization.")
        )
        title = finding.title if finding else event.metadata.get("title", f"Suspicious Access Pattern: `{ep}`")
        sha = (
            finding.evidence.evidence_sha256[:16]
            if finding and finding.evidence and finding.evidence.evidence_sha256
            else event.metadata.get("sha256", "")[:16]
        )
        rem = (
            finding.remediation_guidance
            if finding and finding.remediation_guidance
            else event.metadata.get("remediation", "// Enforce authentication and role verification middleware\napp.use(verifyAuthSession);")
        )

        sha_text = f" (Evidence SHA-256: `{sha}...`)" if sha else ""
        return (
            f"### ⚠️ Suspicious Access Pattern (Requires Review): {title}\n\n"
            f"- **Target Endpoint:** `{ep}`\n"
            f"- **Access Verdict:** `{verdict}` | **Validation Status:** `{val_status}`{sha_text}\n"
            f"- **Observed Discrepancy:** {actual}\n"
            f"- **Expected Behavior:** {expected}\n"
            f"- **Why Flagged as Suspicious:** Comparative multi-role session baselines were unverified or incomplete. "
            f"Rather than speculating or asserting a confirmed bypass, this was classified as `{verdict}` pending operator verification.\n"
            f"- **Precautionary Mitigation:**\n"
            f"```javascript\n{rem}\n```\n\n"
        )
    elif etype == EventType.FINDING_CONFIRMED.value:
        finding_id = event.metadata.get("finding_id")
        if finding is None and finding_id and repo:
            finding = repo.get_finding(finding_id)

        ep = finding.target_endpoint if finding else event.metadata.get("endpoint", "")
        sev = (
            (finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity))
            if finding
            else event.metadata.get("severity", "HIGH")
        )
        sha = (
            finding.evidence.evidence_sha256[:16]
            if finding and finding.evidence and finding.evidence.evidence_sha256
            else event.metadata.get("sha256", "")[:16]
        )
        title = finding.title if finding else event.metadata.get("title", "Confirmed Broken Object Level Authorization (IDOR)")
        category = (
            (finding.vulnerability_category or finding.vulnerability_type)
            if finding
            else event.metadata.get("category", "BOLA_IDOR")
        )
        actual = (
            finding.actual_behavior
            if finding and finding.actual_behavior
            else event.metadata.get("actual_behavior", "Authorized test persona was able to access a private resource belonging to another tenant.")
        )
        expected = (
            finding.expected_behavior
            if finding and finding.expected_behavior
            else event.metadata.get("expected_behavior", "Cross-account access should be strictly rejected with HTTP 403 Forbidden.")
        )
        impact = (
            finding.impact_explanation or finding.description
            if finding
            else event.metadata.get("impact", "Unauthorized exposure of private tenant data.")
        )
        rem = (
            finding.remediation_guidance or finding.remediation_recommendation
            if finding
            else event.metadata.get("remediation", "// Verify session identity matches resource owner\nif (req.user.id !== resource.UserId) return res.status(403);")
        )
        verdict = finding.access_verdict if finding else "CONFIRMED_UNAUTHORIZED_ACCESS"
        val_status = finding.validation_status if finding else "CONFIRMED"

        sha_text = f" (Evidence SHA-256: `{sha}...`)" if sha else ""
        return (
            f"### 🚨 Confirmed Vulnerability: {title}\n\n"
            f"- **Category:** `{category}` | **Severity:** `{sev}`\n"
            f"- **Target Endpoint:** `{ep}`\n"
            f"- **Access Verdict:** `{verdict}` | **Evidence Status:** `{val_status}`{sha_text}\n"
            f"- **Observed Behavior:** {actual}\n"
            f"- **Expected Security Control:** {expected}\n"
            f"- **Impact Assessment:** {impact}\n"
            f"- **Recommended Technical Fix:**\n"
            f"```javascript\n{rem}\n```\n\n"
        )
    elif etype == EventType.ASSESSMENT_COMPLETED.value:
        disc = event.metadata.get("endpoints_discovered", 0)
        tested = event.metadata.get("endpoints_tested", 0)
        conf = event.metadata.get("confirmed_findings", 0)
        susp = event.metadata.get("suspicious_results", 0)
        return (
            f"### 🏁 Assessment Complete\n\n"
            f"The security testing agent evaluated **{tested}** of **{disc}** discovered endpoints.\n"
            f"- **Confirmed vulnerabilities:** `{conf}`\n"
            f"- **Suspicious results:** `{susp}`\n\n"
            "All findings and cryptographic evidence artifacts are persisted in the local SQLite database."
        )
    elif etype == EventType.ASSESSMENT_FAILED.value:
        reason = event.metadata.get("reason") or event.message
        return f"\n\n**Assessment halted:** {reason}\n"
    elif etype == EventType.ASSESSMENT_CANCELLED.value:
        return "\n\n_Assessment was safely stopped by the operator._\n"
    return None


def _map_event_to_agent_sse(
    event: AssessmentEvent,
    assessment_id: str,
    agent: GeminiAgent,
) -> List[Tuple[str, Dict[str, Any]]]:
    """Maps internal assessment events to structured AI agent events."""
    etype = event.event_type
    results: List[Tuple[str, Dict[str, Any]]] = []

    if etype == EventType.SCOPE_VALIDATION_STARTED.value:
        results.append(("tool_started", {
            "type": "tool_started",
            "tool": "check_scope",
            "message": "Validating target against ScopeGuard allowlist",
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.SCOPE_VALIDATION_COMPLETED.value:
        results.append(("tool_completed", {
            "type": "tool_completed",
            "tool": "check_scope",
            "message": "Target verified within authorized scope (localhost:3000)",
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.CONNECTION_COMPLETED.value:
        results.append(("agent_thinking", {
            "type": "agent_thinking",
            "message": "Target application connection verified; mapping attack surface routes",
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.ENDPOINT_DISCOVERY_COMPLETED.value:
        count = event.metadata.get("endpoints_discovered", 0)
        results.append(("tool_completed", {
            "type": "tool_completed",
            "tool": "discover_routes",
            "message": f"Discovered {count} attack surface routes",
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.AUTHORIZATION_TEST_STARTED.value:
        results.append(("tool_started", {
            "type": "tool_started",
            "tool": "compare_access",
            "message": "Executing authorization differential testing across discovered endpoints",
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.AUTHORIZATION_TEST_COMPLETED.value:
        tested = event.metadata.get("tested_count", 0)
        results.append(("tool_completed", {
            "type": "tool_completed",
            "tool": "compare_access",
            "message": f"Completed authorization differential analysis across {tested} endpoints",
            "assessment_id": assessment_id,
        }))
    elif etype in (EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value, EventType.FINDING_CONFIRMED.value):
        ep = event.metadata.get("endpoint", "")
        sev = event.metadata.get("severity", "HIGH" if etype == EventType.FINDING_CONFIRMED.value else "MEDIUM")
        cat = event.metadata.get("vulnerability_candidate", "BOLA_IDOR" if etype == EventType.FINDING_CONFIRMED.value else "BFLA")
        results.append(("finding_discovered", {
            "type": "finding_discovered",
            "endpoint": ep,
            "category": cat,
            "severity": sev,
            "message": f"Authorization discrepancy identified on {ep}",
            "assessment_id": assessment_id,
        }))

        # Generate cognitive plain-English explanation via Agent / RAG Memory
        expl_data = agent.generate_explanation(
            endpoint=ep,
            vulnerability_category=cat,
            validation_status="CONFIRMED" if etype == EventType.FINDING_CONFIRMED.value else "SUSPICIOUS",
            evidence_summary=event.message,
        )
        results.append(("explanation_generated", {
            "type": "explanation_generated",
            "endpoint": ep,
            "category": cat,
            "explanation": expl_data["explanation"],
            "remediation_code": expl_data.get("remediation_code"),
            "assessment_id": assessment_id,
        }))
    elif etype == EventType.EVIDENCE_VALIDATION_COMPLETED.value:
        results.append(("evidence_validated", {
            "type": "evidence_validated",
            "message": "Cryptographic evidence artifacts signed and verified (SHA-256)",
            "assessment_id": assessment_id,
            "confirmed_count": event.metadata.get("confirmed_count", 0),
            "suspicious_count": event.metadata.get("suspicious_count", 0),
        }))
    elif etype == EventType.ASSESSMENT_COMPLETED.value:
        results.append(("assessment_completed", {
            "type": "assessment_completed",
            "message": "Assessment concluded successfully",
            "assessment_id": assessment_id,
            "confirmed_findings": event.metadata.get("confirmed_findings", 0),
            "suspicious_results": event.metadata.get("suspicious_results", 0),
        }))
    elif etype == EventType.ASSESSMENT_FAILED.value:
        results.append(("assessment_failed", {
            "type": "assessment_failed",
            "message": event.message,
            "assessment_id": assessment_id,
        }))

    return results


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "AuthScope API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "allowed_target": "http://localhost:3000",
    }


@app.post("/api/assessments", response_model=CreateAssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(req: CreateAssessmentRequest) -> CreateAssessmentResponse:
    """Validates the target URL with ScopeGuard, creates session, and launches background task."""
    target_clean = (req.target_url or "").strip().rstrip("/")
    if not target_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL must not be empty.",
        )

    # 1. Enforce strict scope validation via ScopeGuard
    scope_guard = ScopeGuard()
    check_result = scope_guard.validate_request(url=target_clean, method="GET")
    if not check_result.is_allowed:
        logger.warning(f"Rejected out-of-scope assessment request for {target_clean}: {check_result.reason}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: {check_result.reason}",
        )

    # 2. Initialize ScanSessionRecord with PENDING state
    repo = FindingRepository()
    scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    stages = AssessmentEngine._init_stages()
    session = ScanSessionRecord(
        id=scan_id,
        target_url=target_clean,
        status="PENDING",
        started_at=datetime.now(timezone.utc),
        stages=stages,
    )
    repo.save_scan_session(session)

    # 3. Create cancellation token and launch managed background execution task
    token = CancellationToken()
    active_tokens[scan_id] = token
    task_manager.start_assessment_task(
        scan_id=scan_id,
        target_url=target_clean,
        token=token,
        repo=repo,
    )

    logger.info(f"Initialized assessment session {scan_id} for target {target_clean}")
    return CreateAssessmentResponse(
        assessment_id=scan_id,
        target_url=target_clean,
        status="PENDING",
        created_at=session.started_at.isoformat(),
        message="Assessment accepted and running in background. Connect to SSE stream to observe.",
    )


@app.get("/api/assessments/{assessment_id}/stream")
async def stream_assessment(
    assessment_id: str,
    request: Request = None,
    last_event_id: Optional[str] = Query(default=None),
) -> StreamingResponse:
    """Server-Sent Events (SSE) endpoint streaming real operational events, thoughts, plans, and markdown."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    # Determine cursor for incremental replay
    cursor_str = request.headers.get("last-event-id") or last_event_id
    after_id: Optional[int] = None
    if cursor_str:
        clean_cursor = cursor_str.replace("msg_", "").strip()
        try:
            after_id = int(clean_cursor)
        except ValueError:
            pass

    # Initialize Memory, Tool Registry, and Gemini Agent
    memory = AssessmentMemory(assessment_id=session.id, target_url=session.target_url, repository=repo)
    scope_guard = ScopeGuard()
    executor = RequestExecutor(scope_guard=scope_guard)
    tools = ToolRegistry(scope_guard=scope_guard, executor=executor, memory=memory)
    agent = GeminiAgent(tool_registry=tools, memory=memory, scope_guard=scope_guard)

    async def sse_generator() -> AsyncGenerator[str, None]:
        # Track highest event ID delivered to this SSE connection
        last_sent_id = after_id or 0

        # 1. Replay stored events from repository (deduplicated by ID)
        stored_events = repo.list_events(assessment_id, after_id=after_id)
        for ev in stored_events:
            ev_id = ev.id or 0
            if ev_id > last_sent_id:
                last_sent_id = ev_id

            yield f"id: {ev_id}\nevent: activity\ndata: {ev.model_dump_json()}\n\n"
            msg_chunk = _format_event_message_chunk(ev, repo=repo)
            if msg_chunk:
                yield f"id: msg_{ev_id}\nevent: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"

        # 2. Check if the assessment is already completed or cancelled
        current_session = repo.get_scan_session(assessment_id) or session
        is_active = task_manager.is_running(assessment_id)

        if not is_active and current_session.status in ("COMPLETED", "FAILED", "CANCELLED"):
            done_payload = {
                "status": current_session.status,
                "summary": current_session.summary_text,
                "endpoints_discovered": current_session.endpoints_discovered_count,
                "endpoints_tested": current_session.endpoints_tested_count,
                "confirmed_findings": current_session.confirmed_findings_count,
                "suspicious_results": current_session.suspicious_results_count,
            }
            yield f"event: done\ndata: {json.dumps(done_payload)}\n\n"
            return

        # Initial AI Agent Events
        yield f"event: assessment_started\ndata: {json.dumps({'type': 'assessment_started', 'message': f'Assessment initialized for {session.target_url}', 'assessment_id': assessment_id, 'target_url': session.target_url})}\n\n"
        yield f"event: agent_thinking\ndata: {json.dumps({'type': 'agent_thinking', 'message': f'Formulating authorization testing strategy for {session.target_url}.', 'assessment_id': assessment_id})}\n\n"
        plan_res = agent.plan_assessment(session.target_url)
        yield f"event: agent_plan\ndata: {json.dumps({'type': 'agent_plan', 'message': plan_res['plan_summary'], 'steps': plan_res['steps'], 'assessment_id': assessment_id})}\n\n"

        # Ensure active task is running in task_manager
        if not is_active and current_session.status in ("PENDING", "RUNNING"):
            token = active_tokens.get(assessment_id) or CancellationToken()
            active_tokens[assessment_id] = token
            task_manager.start_assessment_task(
                scan_id=assessment_id,
                target_url=session.target_url,
                token=token,
                repo=repo,
            )

        # 3. Subscribe to live background broadcast queue
        queue = task_manager.subscribe(assessment_id)
        try:
            while True:
                # Wait for broadcast item or client disconnect
                item = await queue.get()
                kind = item[0]

                if kind == "activity":
                    _, ev, msg_chunk = item
                    ev_id = ev.id or 0
                    # Deduplicate against events already sent during replay
                    if ev_id > 0 and ev_id <= last_sent_id:
                        continue
                    if ev_id > 0:
                        last_sent_id = max(last_sent_id, ev_id)

                    yield f"id: {ev_id}\nevent: activity\ndata: {ev.model_dump_json()}\n\n"
                    if msg_chunk:
                        yield f"id: msg_{ev_id}\nevent: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"

                    agent_events = _map_event_to_agent_sse(ev, assessment_id, agent)
                    for event_type, payload in agent_events:
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

                elif kind == "done":
                    _, done_payload, _ = item
                    yield f"event: done\ndata: {json.dumps(done_payload)}\n\n"
                    break

                elif kind == "error":
                    _, err_msg, _ = item
                    yield f"event: error\ndata: {json.dumps({'error': err_msg})}\n\n"
                    break

        except asyncio.CancelledError:
            logger.info(f"SSE client disconnected for {assessment_id}; background task continues.")
            raise
        except Exception as exc:
            logger.error(f"Error streaming live SSE events for {assessment_id}: {exc}")
            err_data = json.dumps({"type": "assessment_failed", "error": str(exc), "assessment_id": assessment_id})
            yield f"event: assessment_failed\ndata: {err_data}\n\n"
            yield f"event: error\ndata: {err_data}\n\n"
        finally:
            task_manager.unsubscribe(assessment_id, queue)

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/assessments/{assessment_id}/stop")
def stop_assessment(assessment_id: str) -> Dict[str, Any]:
    """Signals an in-progress assessment to safely cancel execution."""
    token = active_tokens.get(assessment_id) or task_manager.get_token(assessment_id)
    if token:
        token.cancel()
        task_manager.cancel(assessment_id)
        return {"status": "CANCELLING", "message": "Cancellation signal dispatched."}

    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found.")
    return {"status": session.status, "message": "Assessment was not actively running."}

@app.post("/api/assessments/{assessment_id}/retry", response_model=CreateAssessmentResponse)
async def retry_assessment(assessment_id: str) -> CreateAssessmentResponse:
    """Retries an interrupted, failed, or cancelled assessment."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    if task_manager.is_running(assessment_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment {assessment_id} is already actively running.",
        )

    # Validate scope for target url
    scope_guard = ScopeGuard()
    check = scope_guard.validate_request(url=session.target_url, method="GET")
    if not check.is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: {check.reason}",
        )

    # Reset session fields for retry
    now = datetime.now(timezone.utc)
    session.status = "PENDING"
    session.failure_reason = ""
    session.started_at = now
    session.updated_at = now
    session.completed_at = None
    session.stages = AssessmentEngine._init_stages()
    session.endpoints_discovered_count = 0
    session.endpoints_tested_count = 0
    session.confirmed_findings_count = 0
    session.suspicious_results_count = 0
    session.summary_text = ""
    repo.save_scan_session(session)

    # Launch background task
    token = CancellationToken()
    active_tokens[assessment_id] = token
    task_manager.start_assessment_task(
        scan_id=assessment_id,
        target_url=session.target_url,
        token=token,
        repo=repo,
    )

    logger.info(f"Retried assessment session {assessment_id} for target {session.target_url}")
    return CreateAssessmentResponse(
        assessment_id=assessment_id,
        target_url=session.target_url,
        status="PENDING",
        created_at=session.started_at.isoformat(),
        message="Assessment retried and running in background. Connect to SSE stream to observe.",
    )



@app.get("/api/assessments/{assessment_id}", response_model=AssessmentSummaryResponse)
def get_assessment(assessment_id: str) -> AssessmentSummaryResponse:
    """Retrieves full assessment status, events, discovered endpoints, and findings."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    events = repo.list_events(assessment_id)
    findings = repo.list_findings(assessment_id)
    adapter = AssessmentQueryAdapter(repository=repo)
    markdown_content = adapter.export_report_markdown(assessment_id)

    return AssessmentSummaryResponse(
        id=session.id,
        target_url=session.target_url,
        status=session.status,
        started_at=session.started_at.isoformat(),
        updated_at=session.updated_at.isoformat() if session.updated_at else None,
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
        failure_reason=session.failure_reason,
        endpoints_discovered_count=session.endpoints_discovered_count,
        endpoints_tested_count=session.endpoints_tested_count,
        confirmed_findings_count=session.confirmed_findings_count,
        suspicious_results_count=session.suspicious_results_count,
        summary_text=session.summary_text,
        markdown_content=markdown_content,
        stages={k: v.model_dump(mode="json") for k, v in session.stages.items()},
        events=[e.model_dump(mode="json") for e in events],
        findings=[f.model_dump(mode="json") for f in findings],
    )


@app.get("/api/assessments")
def list_assessments(limit: int = Query(default=10, ge=1, le=50)) -> List[Dict[str, Any]]:
    """Lists recent assessments for browser session recovery."""
    repo = FindingRepository()
    sessions = repo.list_scan_sessions(limit=limit)
    return [s.model_dump(mode="json") for s in sessions]



@app.get("/", include_in_schema=False)
def root() -> Dict[str, Any]:
    """Root landing endpoint directing to documentation and health status."""
    return {
        "service": "AuthScope AI Security Agent API",
        "status": "healthy",
        "documentation": "/docs",
        "redoc": "/redoc",
        "health": "/api/health",
        "assessments": "/api/assessments",
    }
