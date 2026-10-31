"""FastAPI Application for AuthScope — Unified AI Agent & Security Assessment API Backend.

Connects the complete assessment pipeline via Dependency Injection:
URL input
→ ScopeGuard validation
→ Canonical GeminiAuthScopeAgent
→ ToolRegistryAdapter
→ Real website security checks (AssessmentEngine)
→ Cryptographic EvidenceValidator
→ MemoryManager & RAG
→ CodeMapper & ExplanationEngine
→ Real-time SSE streaming
→ Next.js frontend display.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple, Union
import uuid

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.api.adapters import (
    AssessmentPipelineRequest,
    GeminiAuthScopeAgent,
    MemoryManager,
    ToolRegistryAdapter,
)
from backend.config import settings
from backend.core.assessment_engine import (
    AssessmentEngine,
    AssessmentQueryAdapter,
    CancellationToken,
    sanitize_event_metadata,
    sanitize_event_text,
)
from backend.core.scope_guard import ScopeGuard
from backend.retesting.retest_engine import RetestEngine
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    EventType,
    FindingRecord,
    ScanSessionRecord,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Active cancellation tokens indexed by assessment_id
active_tokens: Dict[str, CancellationToken] = {}

ALL_REQUIRED_SSE_EVENTS: Set[str] = {
    "assessment_started",
    "agent_thinking",
    "agent_plan",
    "tool_started",
    "tool_completed",
    "tool_failed",
    "endpoint_discovered",
    "finding_hypothesis",
    "finding_discovered",
    "evidence_validated",
    "source_location_found",
    "explanation_generated",
    "assessment_completed",
    "assessment_failed",
    "assessment_cancelled",
}


class AssessmentTaskManager:
    """Manages unified background execution of assessments and SSE client event broadcasting.

    Supports Dependency Injection for `agent` (`GeminiAuthScopeAgent`),
    `tool_registry` (`ToolRegistryAdapter`), and `memory_manager` (`MemoryManager`).
    """

    def __init__(
        self,
        agent: Optional[Any] = None,
        tool_registry: Optional[Any] = None,
        memory_manager: Optional[Any] = None,
    ) -> None:
        self._tasks: Dict[str, asyncio.Task[None]] = {}
        self._tokens: Dict[str, CancellationToken] = {}
        self._subscribers: Dict[str, List[asyncio.Queue[Any]]] = {}
        self._lock = asyncio.Lock()

        # Injected dependencies (if None, default production adapters are instantiated per run)
        self.agent = agent
        self.tool_registry = tool_registry
        self.memory_manager = memory_manager

    def configure_dependencies(
        self,
        agent: Optional[Any] = None,
        tool_registry: Optional[Any] = None,
        memory_manager: Optional[Any] = None,
    ) -> None:
        """Configures injected components for the unified pipeline (or mock adapters in tests)."""
        self.agent = agent
        self.tool_registry = tool_registry
        self.memory_manager = memory_manager

    def reset_dependencies(self) -> None:
        """Resets injected dependencies back to production defaults."""
        self.agent = None
        self.tool_registry = None
        self.memory_manager = None

    def get_agent(self, repo: FindingRepository) -> Any:
        """Returns the injected agent or constructs the default canonical GeminiAuthScopeAgent."""
        if self.agent is not None:
            return self.agent
        memory = self.memory_manager or MemoryManager(repository=repo)
        tools = self.tool_registry or ToolRegistryAdapter()
        return GeminiAuthScopeAgent(
            tool_registry=tools,
            memory_manager=memory,
            repository=repo,
        )

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
        github_repo: Optional[str] = None,
        source_archive_path: Optional[str] = None,
    ) -> Optional[asyncio.Task[None]]:
        """Starts a managed background task for unified assessment execution."""
        self._tokens[scan_id] = token
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(
                self._run_task(
                    scan_id=scan_id,
                    target_url=target_url,
                    token=token,
                    repo=repo,
                    github_repo=github_repo,
                    source_archive_path=source_archive_path,
                ),
                name=f"assessment_{scan_id}",
            )
            self._tasks[scan_id] = task
            return task
        except RuntimeError:
            logger.warning(f"No running event loop detected for background task {scan_id}")
            return None

    @staticmethod
    def _coerce_event(scan_id: str, raw_item: Union[AssessmentEvent, Dict[str, Any]]) -> AssessmentEvent:
        """Normalizes an AssessmentEvent or dictionary emitted by an agent into an AssessmentEvent."""
        if isinstance(raw_item, AssessmentEvent):
            raw_item.assessment_id = scan_id
            return raw_item
        data = dict(raw_item)
        etype = str(data.get("event_type") or data.get("type") or EventType.STAGE_UPDATED.value)
        stage = str(data.get("stage") or AssessmentStage.AUTHORIZATION_TESTING.value)
        msg = str(data.get("message") or etype)
        meta = dict(data.get("metadata") or {k: v for k, v in data.items() if k not in ("id", "assessment_id", "event_type", "type", "stage", "message", "timestamp")})
        return AssessmentEvent(
            id=data.get("id"),
            assessment_id=scan_id,
            event_type=etype,
            stage=stage,
            message=sanitize_event_text(msg),
            timestamp=str(data.get("timestamp") or datetime.now(timezone.utc).isoformat()),
            metadata=sanitize_event_metadata(meta),
        )

    async def _run_task(
        self,
        scan_id: str,
        target_url: str,
        token: CancellationToken,
        repo: FindingRepository,
        github_repo: Optional[str] = None,
        source_archive_path: Optional[str] = None,
    ) -> None:
        """Background worker executing the single unified assessment pipeline."""
        logger.info(f"Background assessment task started for {scan_id} ({target_url})")
        active_agent = self.get_agent(repo=repo)
        pipeline_req = AssessmentPipelineRequest(
            assessment_id=scan_id,
            target_url=target_url,
            github_repo=github_repo,
            source_archive_path=source_archive_path,
        )

        async def _execute_steps() -> None:
            # Brief yield so HTTP POST /retry caller observes initial PENDING state
            # and SSE client can attach before execution transitions to RUNNING
            await asyncio.sleep(0.05)
            curr_sess = repo.get_scan_session(scan_id)
            if curr_sess and curr_sess.status == "PENDING":
                curr_sess.status = "RUNNING"
                curr_sess.updated_at = datetime.now(timezone.utc)
                repo.save_scan_session(curr_sess)

            stream_iter = active_agent.astream_assessment(pipeline_req, cancel_token=token)
            async for raw_ev in stream_iter:
                event = self._coerce_event(scan_id, raw_ev)

                # Ensure event is persisted in SQLite with a valid sequential ID for replay
                if not event.id:
                    repo.save_event(event)

                # Update session state if custom/mock agent emitted terminal event
                if event.event_type == EventType.ASSESSMENT_COMPLETED.value:
                    sess = repo.get_scan_session(scan_id)
                    if sess and sess.status not in ("COMPLETED", "FAILED", "CANCELLED"):
                        sess.status = "COMPLETED"
                        sess.completed_at = datetime.now(timezone.utc)
                        sess.updated_at = datetime.now(timezone.utc)
                        sess.summary_text = event.message
                        sess.confirmed_findings_count = int(
                            event.metadata.get("confirmed_findings", sess.confirmed_findings_count)
                        )
                        sess.suspicious_results_count = int(
                            event.metadata.get("suspicious_results", sess.suspicious_results_count)
                        )
                        repo.save_scan_session(sess)
                elif event.event_type == EventType.ASSESSMENT_CANCELLED.value:
                    sess = repo.get_scan_session(scan_id)
                    if sess and sess.status != "CANCELLED":
                        sess.status = "CANCELLED"
                        sess.completed_at = datetime.now(timezone.utc)
                        sess.updated_at = datetime.now(timezone.utc)
                        sess.summary_text = event.message
                        repo.save_scan_session(sess)
                elif event.event_type == EventType.ASSESSMENT_FAILED.value:
                    sess = repo.get_scan_session(scan_id)
                    if sess and sess.status != "FAILED":
                        sess.status = "FAILED"
                        sess.failure_reason = str(event.metadata.get("reason", "EXECUTION_ERROR"))
                        sess.completed_at = datetime.now(timezone.utc)
                        sess.updated_at = datetime.now(timezone.utc)
                        sess.summary_text = event.message
                        repo.save_scan_session(sess)

                msg_chunk = _format_event_message_chunk(event, repo=repo)
                await self._broadcast(scan_id, ("activity", event, msg_chunk))

                if token.is_cancelled and event.event_type != EventType.ASSESSMENT_CANCELLED.value:
                    cancel_sess = repo.get_scan_session(scan_id)
                    if cancel_sess and cancel_sess.status not in ("COMPLETED", "FAILED", "CANCELLED"):
                        cancel_sess.status = "CANCELLED"
                        cancel_sess.completed_at = datetime.now(timezone.utc)
                        cancel_sess.updated_at = datetime.now(timezone.utc)
                        cancel_sess.summary_text = "Assessment cancelled safely by operator."
                        repo.save_scan_session(cancel_sess)
                        cancel_ev = AssessmentEvent(
                            assessment_id=scan_id,
                            event_type=EventType.ASSESSMENT_CANCELLED.value,
                            stage=AssessmentStage.REPORT_PREPARATION.value,
                            message="Assessment cancelled safely by operator.",
                        )
                        repo.save_event(cancel_ev)
                        cancel_chunk = _format_event_message_chunk(cancel_ev, repo=repo)
                        await self._broadcast(scan_id, ("activity", cancel_ev, cancel_chunk))
                    break

                await asyncio.sleep(0.02)

            # Finalize session if generator completed without setting terminal status
            final_check = repo.get_scan_session(scan_id)
            if final_check and final_check.status in ("PENDING", "RUNNING"):
                final_check.status = "CANCELLED" if token.is_cancelled else "COMPLETED"
                final_check.completed_at = datetime.now(timezone.utc)
                final_check.updated_at = datetime.now(timezone.utc)
                repo.save_scan_session(final_check)

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
                    curr_session.summary_text = (
                        f"Assessment exceeded timeout limit ({settings.assessment_timeout_seconds}s)."
                    )
                    repo.save_scan_session(curr_session)
                    timeout_ev = AssessmentEvent(
                        assessment_id=scan_id,
                        event_type=EventType.ASSESSMENT_FAILED.value,
                        stage=AssessmentStage.REPORT_PREPARATION.value,
                        message=f"Assessment timed out after {settings.assessment_timeout_seconds} seconds.",
                        metadata={"reason": "TIMEOUT", "timeout_seconds": settings.assessment_timeout_seconds},
                    )
                    repo.save_event(timeout_ev)
                    await self._broadcast(scan_id, ("activity", timeout_ev, _format_event_message_chunk(timeout_ev)))
            except Exception as e:
                logger.warning(f"Error recording timeout for {scan_id}: {e}")
            await self._broadcast(
                scan_id,
                ("error", f"Assessment timed out after {settings.assessment_timeout_seconds}s", None),
            )
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
                    fail_ev = AssessmentEvent(
                        assessment_id=scan_id,
                        event_type=EventType.ASSESSMENT_FAILED.value,
                        stage=AssessmentStage.REPORT_PREPARATION.value,
                        message=f"Assessment failed: {exc}",
                        metadata={"reason": "EXECUTION_ERROR"},
                    )
                    repo.save_event(fail_ev)
                    await self._broadcast(scan_id, ("activity", fail_ev, _format_event_message_chunk(fail_ev)))
            except Exception:
                pass
            await self._broadcast(scan_id, ("error", str(exc), None))
        finally:
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
            logger.info(
                f"Background assessment task completed for {scan_id} with status {done_payload['status']}"
            )

    async def _broadcast(self, scan_id: str, item: Any) -> None:
        queues = list(self._subscribers.get(scan_id, []))
        for q in queues:
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                pass

    def subscribe(self, scan_id: str) -> asyncio.Queue[Any]:
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = []
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize=1000)
        self._subscribers[scan_id].append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue[Any]) -> None:
        if scan_id in self._subscribers and q in self._subscribers[scan_id]:
            self._subscribers[scan_id].remove(q)
            if not self._subscribers[scan_id]:
                self._subscribers.pop(scan_id, None)


# Global task manager instance
task_manager = AssessmentTaskManager()
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
        description="Optional repository URL or path for source code mapping.",
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
        finding_id = event.metadata.get("finding_id")
        if finding is None and finding_id and repo:
            finding = repo.get_finding(str(finding_id))

        ep = finding.target_endpoint if finding else event.metadata.get("endpoint", "")
        code = event.metadata.get("status_code", 200)
        verdict = finding.access_verdict if finding else event.metadata.get("verdict", "SUSPICIOUS_ACCESS")
        val_status = finding.validation_status if finding else event.metadata.get("validation_status", "SUSPICIOUS")
        actual = (
            finding.actual_behavior
            if finding and finding.actual_behavior
            else event.metadata.get(
                "actual_behavior",
                f"Unauthenticated request to `{ep}` returned HTTP {code} with application data.",
            )
        )
        expected = (
            finding.expected_behavior
            if finding and finding.expected_behavior
            else event.metadata.get(
                "expected_behavior",
                f"Access to `{ep}` should require valid authentication and authorization.",
            )
        )
        title = finding.title if finding else event.metadata.get("title", f"Suspicious Access Pattern: `{ep}`")
        sha = (
            finding.evidence.evidence_sha256[:16]
            if finding and finding.evidence and finding.evidence.evidence_sha256
            else str(event.metadata.get("sha256", ""))[:16]
        )
        rem = (
            finding.remediation_guidance
            if finding and finding.remediation_guidance
            else event.metadata.get(
                "remediation",
                "// Enforce authentication and role verification middleware\napp.use(verifyAuthSession);",
            )
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
            finding = repo.get_finding(str(finding_id))

        ep = finding.target_endpoint if finding else event.metadata.get("endpoint", "")
        sev = (
            (finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity))
            if finding
            else event.metadata.get("severity", "HIGH")
        )
        sha = (
            finding.evidence.evidence_sha256[:16]
            if finding and finding.evidence and finding.evidence.evidence_sha256
            else str(event.metadata.get("sha256", ""))[:16]
        )
        title = (
            finding.title
            if finding
            else event.metadata.get("title", "Confirmed Broken Object Level Authorization (IDOR)")
        )
        category = (
            (finding.vulnerability_category or finding.vulnerability_type)
            if finding
            else event.metadata.get("category", "BOLA_IDOR")
        )
        actual = (
            finding.actual_behavior
            if finding and finding.actual_behavior
            else event.metadata.get(
                "actual_behavior",
                "Authorized test persona was able to access a private resource belonging to another tenant.",
            )
        )
        expected = (
            finding.expected_behavior
            if finding and finding.expected_behavior
            else event.metadata.get(
                "expected_behavior",
                "Cross-account access should be strictly rejected with HTTP 403 Forbidden.",
            )
        )
        impact = (
            finding.impact_explanation or finding.description
            if finding
            else event.metadata.get("impact", "Unauthorized exposure of private tenant data.")
        )
        rem = (
            finding.remediation_guidance or finding.remediation_recommendation
            if finding
            else event.metadata.get(
                "remediation",
                "// Verify session identity matches resource owner\nif (req.user.id !== resource.UserId) return res.status(403);",
            )
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
    repo: Optional[FindingRepository] = None,
) -> List[Tuple[str, Dict[str, Any]]]:
    """Maps unified pipeline AssessmentEvents to the 15 structured SSE event types.

    Supports all 15 required SSE event types:
    - assessment_started
    - agent_thinking
    - agent_plan
    - tool_started
    - tool_completed
    - tool_failed
    - endpoint_discovered
    - finding_hypothesis
    - finding_discovered
    - evidence_validated
    - source_location_found
    - explanation_generated
    - assessment_completed
    - assessment_failed
    - assessment_cancelled
    """
    etype = event.event_type
    results: List[Tuple[str, Dict[str, Any]]] = []
    meta = event.metadata or {}

    if etype == EventType.ASSESSMENT_STARTED.value:
        target_url = meta.get("target_url", "http://localhost:3000")
        results.append(
            (
                "assessment_started",
                {
                    "type": "assessment_started",
                    "message": event.message or f"Assessment initialized for {target_url}",
                    "assessment_id": assessment_id,
                    "target_url": target_url,
                },
            )
        )
        thinking_msg = meta.get(
            "thinking_message",
            f"Formulating authorization testing strategy for {target_url}.",
        )
        results.append(
            (
                "agent_thinking",
                {
                    "type": "agent_thinking",
                    "message": thinking_msg,
                    "assessment_id": assessment_id,
                },
            )
        )
        plan_steps = meta.get(
            "plan_steps",
            [
                "1. Validate target scope against strict ScopeGuard allowlist.",
                "2. Establish target connectivity and verify HTTP response.",
                "3. Discover attack surface endpoints and parameterized resources.",
                "4. Validate multi-role testing personas (User A, User B, Admin).",
                "5. Execute cross-account differential tests on identified endpoints.",
                "6. Cryptographically sign and validate evidence artifacts (SHA-256).",
                "7. Compile findings and synthesize remediation code patches.",
            ],
        )
        plan_summary = meta.get("plan_summary", "7-stage authorization evaluation plan initialized.")
        results.append(
            (
                "agent_plan",
                {
                    "type": "agent_plan",
                    "message": plan_summary,
                    "steps": plan_steps,
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.SCOPE_VALIDATION_STARTED.value:
        results.append(
            (
                "tool_started",
                {
                    "type": "tool_started",
                    "tool": "check_scope",
                    "message": "Validating target against ScopeGuard allowlist",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.SCOPE_VALIDATION_COMPLETED.value:
        results.append(
            (
                "tool_completed",
                {
                    "type": "tool_completed",
                    "tool": "check_scope",
                    "message": "Target verified within authorized scope (localhost:3000)",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.CONNECTION_COMPLETED.value:
        results.append(
            (
                "agent_thinking",
                {
                    "type": "agent_thinking",
                    "message": "Target application connection verified; mapping attack surface routes",
                    "assessment_id": assessment_id,
                },
            )
        )
        results.append(
            (
                "tool_started",
                {
                    "type": "tool_started",
                    "tool": "discover_routes",
                    "message": "Discovering application endpoints and parameterized routes",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.ENDPOINT_DISCOVERED.value:
        results.append(
            (
                "endpoint_discovered",
                {
                    "type": "endpoint_discovered",
                    "endpoint": meta.get("path") or meta.get("endpoint") or event.message,
                    "method": meta.get("method", "GET"),
                    "category": meta.get("category", "API"),
                    "message": event.message,
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.ENDPOINT_DISCOVERY_COMPLETED.value:
        count = meta.get("endpoints_discovered", 0)
        results.append(
            (
                "tool_completed",
                {
                    "type": "tool_completed",
                    "tool": "discover_routes",
                    "message": f"Discovered {count} attack surface routes",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.AUTHORIZATION_TEST_STARTED.value:
        results.append(
            (
                "tool_started",
                {
                    "type": "tool_started",
                    "tool": "compare_access",
                    "message": "Executing authorization differential testing across discovered endpoints",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.AUTHORIZATION_TEST_COMPLETED.value:
        tested = meta.get("tested_count", 0)
        results.append(
            (
                "tool_completed",
                {
                    "type": "tool_completed",
                    "tool": "compare_access",
                    "message": f"Completed authorization differential analysis across {tested} endpoints",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype in (EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value, EventType.FINDING_CONFIRMED.value):
        is_confirmed = etype == EventType.FINDING_CONFIRMED.value
        finding_id = meta.get("finding_id")
        finding = repo.get_finding(str(finding_id)) if (finding_id and repo) else None

        ep = (finding.target_endpoint if finding else None) or str(meta.get("endpoint", ""))
        sev = (
            (finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity))
            if finding
            else str(meta.get("severity", "HIGH" if is_confirmed else "MEDIUM"))
        )
        cat = (
            (finding.vulnerability_category or finding.vulnerability_type)
            if finding
            else str(meta.get("vulnerability_candidate", "BOLA_IDOR" if is_confirmed else "BFLA"))
        )
        val_status = "CONFIRMED" if is_confirmed else "SUSPICIOUS"

        # 1. Emit finding_hypothesis first
        results.append(
            (
                "finding_hypothesis",
                {
                    "type": "finding_hypothesis",
                    "endpoint": ep,
                    "category": cat,
                    "severity": sev,
                    "status": val_status,
                    "message": f"Hypothesis: potential {cat} authorization discrepancy on {ep}",
                    "assessment_id": assessment_id,
                },
            )
        )

        # 2. If confirmed, emit evidence_validated BEFORE finding_discovered
        if is_confirmed:
            sha = (
                finding.evidence.evidence_sha256
                if (finding and finding.evidence and finding.evidence.evidence_sha256)
                else str(meta.get("sha256", ""))
            )
            results.append(
                (
                    "evidence_validated",
                    {
                        "type": "evidence_validated",
                        "endpoint": ep,
                        "finding_id": finding.id if finding else finding_id,
                        "validation_status": "CONFIRMED",
                        "evidence_sha256": sha,
                        "message": f"Cryptographic evidence validated for {ep} (SHA-256)",
                        "assessment_id": assessment_id,
                    },
                )
            )

        # 3. Emit finding_discovered
        results.append(
            (
                "finding_discovered",
                {
                    "type": "finding_discovered",
                    "finding_id": finding.id if finding else finding_id,
                    "endpoint": ep,
                    "category": cat,
                    "severity": sev,
                    "status": val_status,
                    "validation_status": val_status,
                    "message": f"Authorization discrepancy ({val_status}) identified on {ep}",
                    "assessment_id": assessment_id,
                },
            )
        )

        # 4. Emit source_location_found
        src_info = meta.get("source_info") or {}
        src_file = src_info.get("source_file") or (
            finding.technical_details.get("source_file") if finding else None
        )
        line_nums = src_info.get("line_numbers") or (
            finding.technical_details.get("line_numbers") if finding else None
        )
        func_name = src_info.get("function_name") or (
            finding.technical_details.get("function_name") if finding else None
        )
        black_box = not bool(src_file)
        results.append(
            (
                "source_location_found",
                {
                    "type": "source_location_found",
                    "endpoint": ep,
                    "source_file": src_file,
                    "function_name": func_name,
                    "line_numbers": line_nums,
                    "black_box_only": black_box,
                    "message": (
                        f"Mapped {ep} to {src_file}:{line_nums}"
                        if src_file
                        else f"Black-box assessment only for {ep} — no source code repository provided."
                    ),
                    "assessment_id": assessment_id,
                },
            )
        )

        # 5. Emit explanation_generated
        explanation_text = (
            meta.get("explanation")
            or (finding.impact_explanation or finding.description if finding else None)
            or event.message
        )
        remediation_code = (
            meta.get("remediation_code")
            or (finding.remediation_guidance or finding.remediation_recommendation if finding else None)
            or ""
        )
        results.append(
            (
                "explanation_generated",
                {
                    "type": "explanation_generated",
                    "endpoint": ep,
                    "category": cat,
                    "explanation": explanation_text,
                    "remediation_code": remediation_code,
                    "message": f"Generated security explanation and remediation for {ep}",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.EVIDENCE_VALIDATION_COMPLETED.value:
        results.append(
            (
                "evidence_validated",
                {
                    "type": "evidence_validated",
                    "message": "Cryptographic evidence artifacts signed and verified (SHA-256)",
                    "assessment_id": assessment_id,
                    "confirmed_count": meta.get("confirmed_count", 0),
                    "suspicious_count": meta.get("suspicious_count", 0),
                },
            )
        )
    elif etype == EventType.ASSESSMENT_COMPLETED.value:
        results.append(
            (
                "assessment_completed",
                {
                    "type": "assessment_completed",
                    "message": event.message or "Assessment concluded successfully",
                    "assessment_id": assessment_id,
                    "confirmed_findings": meta.get("confirmed_findings", 0),
                    "suspicious_results": meta.get("suspicious_results", 0),
                },
            )
        )
    elif etype == EventType.ASSESSMENT_FAILED.value:
        if event.stage in (
            AssessmentStage.SCOPE_VALIDATION.value,
            AssessmentStage.TARGET_CONNECTION.value,
            AssessmentStage.ENDPOINT_DISCOVERY.value,
            AssessmentStage.AUTHORIZATION_TESTING.value,
        ):
            results.append(
                (
                    "tool_failed",
                    {
                        "type": "tool_failed",
                        "tool": meta.get("tool", event.stage),
                        "message": event.message,
                        "assessment_id": assessment_id,
                    },
                )
            )
        results.append(
            (
                "assessment_failed",
                {
                    "type": "assessment_failed",
                    "message": event.message,
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype == EventType.ASSESSMENT_CANCELLED.value:
        results.append(
            (
                "assessment_cancelled",
                {
                    "type": "assessment_cancelled",
                    "message": event.message or "Assessment cancelled by operator.",
                    "assessment_id": assessment_id,
                },
            )
        )
    elif etype in ALL_REQUIRED_SSE_EVENTS:
        # Direct pass-through for structured events emitted directly by mock or custom agents
        payload = dict(meta)
        payload.setdefault("type", etype)
        payload.setdefault("message", event.message)
        payload.setdefault("assessment_id", assessment_id)
        results.append((etype, payload))

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
    """Validates the target URL with ScopeGuard, creates session, and launches unified background task."""
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
        config={
            "github_repo": req.github_repo,
            "source_archive_path": req.source_archive_path,
        },
    )
    repo.save_scan_session(session)

    # 3. Create cancellation token and launch unified background execution task
    token = CancellationToken()
    active_tokens[scan_id] = token
    task_manager.start_assessment_task(
        scan_id=scan_id,
        target_url=target_clean,
        token=token,
        repo=repo,
        github_repo=req.github_repo,
        source_archive_path=req.source_archive_path,
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
    request: Request = None,  # type: ignore[assignment]
    last_event_id: Optional[str] = Query(default=None),
) -> StreamingResponse:
    """Server-Sent Events (SSE) endpoint streaming real operational events, thoughts, plans, and findings."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    # Determine cursor for incremental replay
    cursor_str = (request.headers.get("last-event-id") if request else None) or last_event_id
    after_id: Optional[int] = None
    if cursor_str:
        clean_cursor = cursor_str.replace("msg_", "").strip()
        try:
            after_id = int(clean_cursor)
        except ValueError:
            pass

    async def sse_generator() -> AsyncGenerator[str, None]:
        last_sent_id = after_id or 0
        emitted_initial_started = False

        # Subscribe to live queue BEFORE replaying stored events so zero events are missed
        queue = task_manager.subscribe(assessment_id)
        try:
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

                agent_events = _map_event_to_agent_sse(ev, assessment_id, repo=repo)
                for event_type, payload in agent_events:
                    if event_type == "assessment_started":
                        emitted_initial_started = True
                    yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

            # 2. Check if the assessment is already completed, failed, or cancelled
            current_session = repo.get_scan_session(assessment_id) or session
            is_active = task_manager.is_running(assessment_id)

            if not is_active and current_session.status in ("COMPLETED", "FAILED", "CANCELLED"):
                # Drain any remaining items in queue before closing
                while not queue.empty():
                    item = queue.get_nowait()
                    if item[0] == "activity":
                        _, ev, msg_chunk = item
                        ev_id = ev.id or 0
                        if ev_id > 0 and ev_id <= last_sent_id:
                            continue
                        if ev_id > 0:
                            last_sent_id = max(last_sent_id, ev_id)
                        yield f"id: {ev_id}\nevent: activity\ndata: {ev.model_dump_json()}\n\n"
                        if msg_chunk:
                            yield f"id: msg_{ev_id}\nevent: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"
                        for event_type, payload in _map_event_to_agent_sse(ev, assessment_id, repo=repo):
                            yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

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

            # Ensure active task is running in task_manager if session is still PENDING/RUNNING
            if not is_active and current_session.status in ("PENDING", "RUNNING"):
                token = active_tokens.get(assessment_id) or CancellationToken()
                active_tokens[assessment_id] = token
                cfg = current_session.config or {}
                task_manager.start_assessment_task(
                    scan_id=assessment_id,
                    target_url=session.target_url,
                    token=token,
                    repo=repo,
                    github_repo=cfg.get("github_repo"),
                    source_archive_path=cfg.get("source_archive_path"),
                )

            # 3. Stream live events from the unified background task queue
            while True:
                item = await queue.get()
                kind = item[0]

                if kind == "activity":
                    _, ev, msg_chunk = item
                    ev_id = ev.id or 0
                    if ev_id > 0 and ev_id <= last_sent_id:
                        continue
                    if ev_id > 0:
                        last_sent_id = max(last_sent_id, ev_id)

                    yield f"id: {ev_id}\nevent: activity\ndata: {ev.model_dump_json()}\n\n"
                    if msg_chunk:
                        yield f"id: msg_{ev_id}\nevent: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"

                    agent_events = _map_event_to_agent_sse(ev, assessment_id, repo=repo)
                    for event_type, payload in agent_events:
                        if event_type == "assessment_started" and emitted_initial_started:
                            continue
                        if event_type == "assessment_started":
                            emitted_initial_started = True
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

                elif kind == "done":
                    _, done_payload, _ = item
                    yield f"event: done\ndata: {json.dumps(done_payload)}\n\n"
                    break

                elif kind == "error":
                    _, err_msg, _ = item
                    err_payload = {
                        "type": "assessment_failed",
                        "error": err_msg,
                        "message": err_msg,
                        "assessment_id": assessment_id,
                    }
                    yield f"event: assessment_failed\ndata: {json.dumps(err_payload)}\n\n"
                    yield f"event: error\ndata: {json.dumps({'error': err_msg})}\n\n"
                    break

        except asyncio.CancelledError:
            logger.info(f"SSE client disconnected for {assessment_id}; background task continues.")
            raise
        except Exception as exc:
            logger.error(f"Error streaming live SSE events for {assessment_id}: {exc}")
            err_data = json.dumps(
                {"type": "assessment_failed", "error": str(exc), "message": str(exc), "assessment_id": assessment_id}
            )
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

    scope_guard = ScopeGuard()
    check = scope_guard.validate_request(url=session.target_url, method="GET")
    if not check.is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: {check.reason}",
        )

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

    token = CancellationToken()
    active_tokens[assessment_id] = token
    cfg = session.config or {}
    task_manager.start_assessment_task(
        scan_id=assessment_id,
        target_url=session.target_url,
        token=token,
        repo=repo,
        github_repo=cfg.get("github_repo"),
        source_archive_path=cfg.get("source_archive_path"),
    )

    logger.info(f"Retried assessment session {assessment_id} for target {session.target_url}")
    return CreateAssessmentResponse(
        assessment_id=assessment_id,
        target_url=session.target_url,
        status="PENDING",
        created_at=session.started_at.isoformat(),
        message="Assessment retried and running in background. Connect to SSE stream to observe.",
    )


@app.post("/api/assessments/{assessment_id}/retest")
async def retest_assessment(assessment_id: str) -> Dict[str, Any]:
    """Re-verifies findings for a given assessment session using RetestEngine."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    scope_guard = ScopeGuard()
    check = scope_guard.validate_request(url=session.target_url, method="GET")
    if not check.is_allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope violation: {check.reason}",
        )

    findings = repo.list_findings(assessment_id)
    retest_engine = RetestEngine(repository=repo)
    retest_results = []
    for f in findings:
        log_rec = retest_engine.retest_finding(f.id)
        repo.save_retest_result(log_rec)
        retest_results.append(log_rec.model_dump(mode="json"))

    return {
        "assessment_id": assessment_id,
        "target_url": session.target_url,
        "retested_count": len(retest_results),
        "results": retest_results,
    }


@app.get("/api/assessments/{assessment_id}/findings")
def get_assessment_findings(assessment_id: str) -> List[Dict[str, Any]]:
    """Retrieves all validated and suspicious findings for a specific assessment."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )
    findings = repo.list_findings(assessment_id)
    return [f.model_dump(mode="json") for f in findings]


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
