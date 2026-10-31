"""Short-term assessment memory.

Provides isolated, in-process, per-assessment context storage.
Each assessment has its own AssessmentContext with no cross-contamination.
Observations are sanitized before storage to prevent credential leakage.
"""

import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Secret redaction patterns (belt-and-suspenders; EvidenceArtifact also does this)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9\-_\.]+\.[A-Za-z0-9\-_\.]+\.[A-Za-z0-9\-_\.]+"),
    re.compile(r"(?i)(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)"),  # JWT
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(api[_\-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)[A-Za-z0-9\-_\.]+"),
    re.compile(r"(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+"),
    re.compile(r"(?i)(Cookie:\s*)\S+"),
    re.compile(r"(?i)(Set-Cookie:\s*)\S+"),
]


def _sanitize_observation(text: str) -> str:
    """Remove secrets from free-text observation strings."""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m: m.group(0).split(m.group(m.lastindex or 1))[0] + "[REDACTED]", result)
    return result


class AssessmentContext(BaseModel):
    """Isolated in-memory context for a single security assessment."""

    assessment_id: str = Field(description="Unique assessment identifier")
    target_url: str = Field(description="Authorised target URL")
    stage: str = Field(default="initialization", description="Current assessment stage label")
    discovered_endpoints: List[str] = Field(default_factory=list, description="Paths / routes discovered")
    tested_endpoints: List[str] = Field(default_factory=list, description="Paths / routes exercised in tests")
    tool_results: List[Dict[str, Any]] = Field(default_factory=list, description="Sanitized tool call results")
    observations: List[str] = Field(default_factory=list, description="Sanitized security observations")
    confirmed_finding_ids: List[str] = Field(default_factory=list, description="IDs of confirmed findings only")
    conversation_context: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Recent conversation messages relevant to this assessment",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ShortTermMemory:
    """Thread-safe per-assessment context store backed by an in-process dictionary.

    Each assessment_id maps to an independent AssessmentContext.
    No data leaks between assessments.
    """

    def __init__(self) -> None:
        self._store: Dict[str, AssessmentContext] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def create(self, assessment_id: str, target_url: str) -> AssessmentContext:
        """Create a fresh context for *assessment_id*. Overwrites any existing context."""
        ctx = AssessmentContext(assessment_id=assessment_id, target_url=target_url)
        with self._lock:
            self._store[assessment_id] = ctx
            logger.debug("ShortTermMemory: created context", extra={"assessment_id": assessment_id})
        return ctx

    def get(self, assessment_id: str) -> Optional[AssessmentContext]:
        """Return context for *assessment_id*, or ``None`` if not found."""
        with self._lock:
            return self._store.get(assessment_id)

    def clear(self, assessment_id: str) -> None:
        """Remove context for *assessment_id* from memory."""
        with self._lock:
            self._store.pop(assessment_id, None)
            logger.debug("ShortTermMemory: cleared context", extra={"assessment_id": assessment_id})

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def add_observation(self, assessment_id: str, observation: str) -> None:
        """Sanitize and append *observation* to context.

        Creates a minimal context automatically if *assessment_id* is unknown.
        """
        sanitized = _sanitize_observation(observation)
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                ctx = AssessmentContext(assessment_id=assessment_id, target_url="unknown")
                self._store[assessment_id] = ctx
            ctx.observations.append(sanitized)
            ctx.updated_at = datetime.now(timezone.utc)

    def add_endpoint(self, assessment_id: str, path: str, *, tested: bool = False) -> None:
        """Register a discovered or tested endpoint."""
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                return
            if path not in ctx.discovered_endpoints:
                ctx.discovered_endpoints.append(path)
            if tested and path not in ctx.tested_endpoints:
                ctx.tested_endpoints.append(path)
            ctx.updated_at = datetime.now(timezone.utc)

    def add_finding_id(self, assessment_id: str, finding_id: str) -> None:
        """Record a confirmed finding ID (no raw finding data stored here)."""
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                return
            if finding_id not in ctx.confirmed_finding_ids:
                ctx.confirmed_finding_ids.append(finding_id)
            ctx.updated_at = datetime.now(timezone.utc)

    def add_tool_result(self, assessment_id: str, result: Dict[str, Any]) -> None:
        """Append a sanitized tool result dict to context."""
        # Strip sensitive keys from result dict before storing
        safe_result = {
            k: v for k, v in result.items()
            if k.lower() not in ("password", "token", "secret", "api_key", "authorization", "cookie")
        }
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                return
            ctx.tool_results.append(safe_result)
            ctx.updated_at = datetime.now(timezone.utc)

    def update_stage(self, assessment_id: str, stage: str) -> None:
        """Update the current assessment stage label."""
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                return
            ctx.stage = stage
            ctx.updated_at = datetime.now(timezone.utc)

    def add_conversation_turn(self, assessment_id: str, role: str, content: str) -> None:
        """Append a sanitized conversation turn to context."""
        sanitized_content = _sanitize_observation(content)
        with self._lock:
            ctx = self._store.get(assessment_id)
            if ctx is None:
                return
            ctx.conversation_context.append(
                {
                    "role": role,
                    "content": sanitized_content,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            # Keep only the 50 most recent turns
            if len(ctx.conversation_context) > 50:
                ctx.conversation_context = ctx.conversation_context[-50:]
            ctx.updated_at = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def get_context_dict(self, assessment_id: str) -> Dict[str, Any]:
        """Return a plain-dict representation of the context for *assessment_id*.

        Returns an empty dict if the assessment has no context yet.
        """
        with self._lock:
            ctx = self._store.get(assessment_id)
        if ctx is None:
            return {}
        return ctx.model_dump(mode="json")

    def list_assessment_ids(self) -> List[str]:
        """Return all tracked assessment IDs."""
        with self._lock:
            return list(self._store.keys())

