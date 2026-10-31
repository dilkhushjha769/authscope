"""FastAPI Application for AuthScope — Minimal Agent Interface Backend.

Provides HTTP REST and Server-Sent Events (SSE) endpoints for launching security assessments,
streaming real-time operational events and markdown text chunks, and retrieving persisted
assessment reports.
"""

from datetime import datetime, timezone
import json
import uuid
import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional
from pathlib import Path
import sys

from fastapi import FastAPI, HTTPException, status, Query
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
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Active background runners and cancellation tokens indexed by assessment_id
active_tokens: Dict[str, CancellationToken] = {}

app = FastAPI(
    title="AuthScope AI Security Agent API",
    description="Minimal conversational API for authorized, hard-scoped application security testing.",
    version="1.0.0",
)

# Enable CORS for Next.js frontend (default port 3000 or 3001)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CreateAssessmentRequest(BaseModel):
    """Payload for launching a new security assessment."""
    target_url: str = Field(
        default="http://localhost:3000",
        description="Target base URL to test (must be an explicitly allowlisted scope target).",
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
    completed_at: Optional[str]
    endpoints_discovered_count: int
    endpoints_tested_count: int
    confirmed_findings_count: int
    suspicious_results_count: int
    summary_text: str
    markdown_content: str
    stages: Dict[str, Any]
    events: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]


def _format_event_message_chunk(event: AssessmentEvent, finding: Optional[FindingRecord] = None) -> Optional[str]:
    """Generates conversational markdown text chunks corresponding to real backend events."""
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
        ep = event.metadata.get("endpoint", "")
        code = event.metadata.get("status_code", 200)
        verdict = event.metadata.get("verdict", "SUSPICIOUS_ACCESS")
        return (
            f"### ⚠️ Potential Security Issue Observed: `{ep}`\n\n"
            f"- **What happened:** An unauthenticated request to an administrative route returned HTTP {code} with non-empty application data.\n"
            f"- **Affected endpoint:** `{ep}`\n"
            f"- **Why this behavior is suspicious:** Administrative endpoints typically require elevated privilege. Because an Admin baseline session was unavailable for cross-verification, this was flagged as `{verdict}` rather than assuming full authorization bypass.\n"
            f"- **Evidence collected:** Cryptographic evidence artifact signed with SHA-256.\n"
            f"- **Recommended fix:** Restrict access using authentication and role-checking middleware:\n"
            "```javascript\n"
            "// Enforce administrative authentication before handler execution\n"
            "app.use('/rest/admin', verifyAdminSession);\n"
            "```\n\n"
        )
    elif etype == EventType.FINDING_CONFIRMED.value:
        ep = event.metadata.get("endpoint", "")
        sev = event.metadata.get("severity", "HIGH")
        sha = event.metadata.get("sha256", "")[:16]
        return (
            f"### 🚨 Confirmed Vulnerability: Broken Object Level Authorization (IDOR)\n\n"
            f"- **What happened:** An authorized test persona was able to access a private resource belonging to another user.\n"
            f"- **Affected endpoint:** `{ep}`\n"
            f"- **Severity:** `{sev}`\n"
            f"- **Why this is vulnerable:** The server responds with identical private data across different user sessions without verifying object ownership.\n"
            f"- **Evidence integrity:** SHA-256: `{sha}...` [CONFIRMED]\n"
            f"- **Recommended fix:** Enforce strict ownership validation on resource retrieval:\n"
            "```javascript\n"
            "if (req.user.id !== resource.UserId) {\n"
            "    return res.status(403).json({ error: 'Access denied' });\n"
            "}\n"
            "```\n\n"
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
def create_assessment(req: CreateAssessmentRequest) -> CreateAssessmentResponse:
    """Validates the target URL with ScopeGuard and initializes an assessment session."""
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

    # 2. Initialize ScanSessionRecord
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

    # 3. Create cancellation token
    active_tokens[scan_id] = CancellationToken()

    logger.info(f"Initialized assessment session {scan_id} for target {target_clean}")
    return CreateAssessmentResponse(
        assessment_id=scan_id,
        target_url=target_clean,
        status="PENDING",
        created_at=session.started_at.isoformat(),
        message="Assessment session created. Connect to SSE stream to execute.",
    )


@app.get("/api/assessments/{assessment_id}/stream")
async def stream_assessment(assessment_id: str) -> StreamingResponse:
    """Server-Sent Events (SSE) endpoint streaming real operational events and markdown text."""
    repo = FindingRepository()
    session = repo.get_scan_session(assessment_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment {assessment_id} not found.",
        )

    token = active_tokens.get(assessment_id)
    if not token:
        token = CancellationToken()
        active_tokens[assessment_id] = token

    async def sse_generator() -> AsyncGenerator[str, None]:
        # If the assessment is already completed or cancelled, replay stored events & markdown
        if session.status in ("COMPLETED", "FAILED", "CANCELLED"):
            stored_events = repo.list_events(assessment_id)
            for ev in stored_events:
                yield f"event: activity\ndata: {ev.model_dump_json()}\n\n"
                msg_chunk = _format_event_message_chunk(ev)
                if msg_chunk:
                    yield f"event: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"
            yield f"event: done\ndata: {json.dumps({'status': session.status, 'summary': session.summary_text})}\n\n"
            return

        # Otherwise, run live assessment engine stream
        engine = AssessmentEngine(repository=repo)
        gen = engine.stream_assessment(target_url=session.target_url, cancel_token=token)

        try:
            while True:
                # Run generator step without blocking the async event loop
                event = await asyncio.to_thread(lambda: next(gen, None))
                if event is None:
                    break

                # 1. Stream structured operational activity event
                event_json = event.model_dump_json()
                yield f"event: activity\ndata: {event_json}\n\n"

                # 2. Stream conversational markdown chunk
                msg_chunk = _format_event_message_chunk(event)
                if msg_chunk:
                    yield f"event: message\ndata: {json.dumps({'text': msg_chunk})}\n\n"

                # Brief async pause to yield to event loop and simulate natural reading cadence
                await asyncio.sleep(0.08)

        except Exception as exc:
            logger.error(f"Error during SSE assessment stream: {exc}")
            err_data = json.dumps({"error": str(exc)})
            yield f"event: error\ndata: {err_data}\n\n"
        finally:
            active_tokens.pop(assessment_id, None)
            final_session = repo.get_scan_session(assessment_id) or session
            done_data = json.dumps({
                "status": final_session.status,
                "summary": final_session.summary_text,
                "endpoints_discovered": final_session.endpoints_discovered_count,
                "endpoints_tested": final_session.endpoints_tested_count,
                "confirmed_findings": final_session.confirmed_findings_count,
                "suspicious_results": final_session.suspicious_results_count,
            })
            yield f"event: done\ndata: {done_data}\n\n"

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
    token = active_tokens.get(assessment_id)
    if not token:
        repo = FindingRepository()
        session = repo.get_scan_session(assessment_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found.")
        return {"status": session.status, "message": "Assessment was not actively running."}

    token.cancel()
    return {"status": "CANCELLING", "message": "Cancellation signal dispatched."}


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
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
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

