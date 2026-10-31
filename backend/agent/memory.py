"""AuthScope Assessment Memory & Knowledge Retrieval (RAG) System.

Provides contextual persistence and knowledge augmentation for the AI agent:
1. Current Assessment Context: Active target, discovered attack surface, testing stage, telemetry.
2. Conversation Context: Chronological stream of agent thoughts, plans, and operator interactions.
3. Previous Assessment Metadata: Historical scan summaries and finding records queried from FindingRepository.
4. Security Knowledge Retrieval (RAG): Curated vulnerability intelligence covering OWASP API Security Top 10,
   root causes, real-world impact, framework-tailored patches, and retesting procedures.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re
from pydantic import BaseModel, Field

from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord, ScanSessionRecord
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Domain Models for Memory & Retrieval
# ==============================================================================


class MemoryEntry(BaseModel):
    """An individual conversational or operational memory entry."""
    entry_id: str = Field(description="Unique identifier for the memory entry")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    category: str = Field(description="Category: 'thought', 'plan', 'tool_action', 'explanation', 'operator'")
    content: str = Field(description="Sanitized textual content")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CurrentAssessmentContext(BaseModel):
    """Active runtime context for the current security assessment."""
    assessment_id: str
    target_url: str
    stage: str = "initialization"
    discovered_endpoints_count: int = 0
    tested_endpoints_count: int = 0
    confirmed_findings_count: int = 0
    suspicious_results_count: int = 0
    active_roles: List[str] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityKnowledgeItem(BaseModel):
    """Structured security knowledge document for RAG retrieval."""
    vulnerability_id: str
    category: str
    title: str
    description: str
    root_cause: str
    threat_impact: str
    remediation_guidance: str
    code_pattern_vulnerable: str
    code_pattern_secure: str
    retesting_procedure: str
    keywords: List[str] = Field(default_factory=list)


# ==============================================================================
# Curated Security Knowledge Base (OWASP API Top 10 & Authorization)
# ==============================================================================

KNOWLEDGE_BASE: List[SecurityKnowledgeItem] = [
    SecurityKnowledgeItem(
        vulnerability_id="API1:2023-BOLA",
        category="BOLA_IDOR",
        title="Broken Object Level Authorization (IDOR)",
        description=(
            "Occurs when an API endpoint handles object identifiers supplied by clients "
            "without validating whether the requesting user has legitimate ownership or authorization."
        ),
        root_cause=(
            "Implicit trust of client-side identifiers (e.g., /rest/basket/{id}) coupled with "
            "direct database lookups missing tenant or user scoping."
        ),
        threat_impact=(
            "Unauthorized horizontal privilege escalation allowing attackers to read, modify, "
            "or delete sensitive data belonging to other accounts."
        ),
        remediation_guidance=(
            "Validate resource ownership at the server-side controller or query level using "
            "session identity (e.g., WHERE user_id = req.user.id). Deny access by default."
        ),
        code_pattern_vulnerable="const basket = await Basket.findByPk(req.params.id);\nreturn res.json(basket);",
        code_pattern_secure=(
            "const basket = await Basket.findOne({ where: { id: req.params.id, UserId: req.user.id } });\n"
            "if (!basket) return res.status(403).json({ error: 'Access denied' });\n"
            "return res.json(basket);"
        ),
        retesting_procedure=(
            "Authenticate as User B and request a resource owned by User A. "
            "Verify the server returns HTTP 403 Forbidden or 404 Not Found."
        ),
        keywords=["bola", "idor", "basket", "cross-user", "object-level", "ownership", "horizontal"],
    ),
    SecurityKnowledgeItem(
        vulnerability_id="API5:2023-BFLA",
        category="BFLA",
        title="Broken Function Level Authorization (Privilege Escalation)",
        description=(
            "Occurs when an administrative or privileged API function is reachable by an unauthenticated "
            "or low-privileged role because access control checks are absent."
        ),
        root_cause="Relying on security-through-obscurity or client-side UI hiding rather than server-side role enforcement.",
        threat_impact="Vertical privilege escalation enabling regular users or attackers to perform administrative operations.",
        remediation_guidance=(
            "Implement mandatory role-based access control (RBAC) middleware on all administrative route handlers."
        ),
        code_pattern_vulnerable="app.get('/rest/admin/application-configuration', handler);",
        code_pattern_secure=(
            "app.get('/rest/admin/application-configuration', verifyAuth, requireRole('admin'), handler);"
        ),
        retesting_procedure=(
            "Send an unauthenticated GET request and an authenticated low-privileged user request. "
            "Verify that both receive HTTP 401 Unauthorized or HTTP 403 Forbidden."
        ),
        keywords=["bfla", "admin", "privilege", "vertical", "role", "elevation", "unauthorized"],
    ),
    SecurityKnowledgeItem(
        vulnerability_id="API2:2023-AUTH",
        category="MISSING_AUTH",
        title="Missing or Broken Authentication",
        description="Endpoints that expose sensitive user profiles or data without verifying caller credentials.",
        root_cause="Endpoints left publicly exposed without session authentication middleware.",
        threat_impact="Total exposure of internal application state, customer PII, and sensitive records.",
        remediation_guidance="Enforce strong JWT/session authentication on all non-public routes.",
        code_pattern_vulnerable="router.get('/api/Users', (req, res) => res.json(users));",
        code_pattern_secure="router.get('/api/Users', verifyToken, (req, res) => res.json(users));",
        retesting_procedure="Request the resource without an Authorization header; assert HTTP 401.",
        keywords=["auth", "missing_auth", "unauthenticated", "token", "jwt", "session"],
    ),
    SecurityKnowledgeItem(
        vulnerability_id="API3:2023-BOPC",
        category="MASS_ASSIGNMENT",
        title="Broken Object Property Level Authorization (Mass Assignment)",
        description="Allows callers to modify object properties they should not access (e.g., isAdmin, role, balance).",
        root_cause="Binding raw client JSON payloads directly into database records without property allowlisting.",
        threat_impact="Privilege escalation, unauthorized balance adjustments, or system parameter tampering.",
        remediation_guidance="Use strict DTO validation (Pydantic, Joi) and explicit field allowlists when updating models.",
        code_pattern_vulnerable="await User.update(req.body, { where: { id: req.user.id } });",
        code_pattern_secure=(
            "const { username, email } = req.body;\n"
            "await User.update({ username, email }, { where: { id: req.user.id } });"
        ),
        retesting_procedure="Submit an update payload containing 'isAdmin: true' or 'role: admin'; verify the property is ignored.",
        keywords=["mass_assignment", "property", "bopc", "role_tampering", "allowlist"],
    ),
]


# ==============================================================================
# Assessment Memory Implementation
# ==============================================================================


class AssessmentMemory:
    """Manages short-term operational memory, conversation history, and RAG retrieval."""

    def __init__(self, assessment_id: str, target_url: str, repository: Optional[FindingRepository] = None):
        self.assessment_id = assessment_id
        self.target_url = target_url
        self.repository = repository or FindingRepository()
        self.context = CurrentAssessmentContext(assessment_id=assessment_id, target_url=target_url)
        self.history: List[MemoryEntry] = []

    def record_thought(self, thought: str, metadata: Optional[Dict[str, Any]] = None) -> MemoryEntry:
        """Records a concise agent reasoning step."""
        entry = MemoryEntry(
            entry_id=f"mem_th_{len(self.history) + 1}",
            category="thought",
            content=thought,
            metadata=metadata or {},
        )
        self.history.append(entry)
        logger.debug(f"[Memory] Recorded thought: {thought}")
        return entry

    def record_plan(self, plan_summary: str, metadata: Optional[Dict[str, Any]] = None) -> MemoryEntry:
        """Records an agent testing plan or strategic direction."""
        entry = MemoryEntry(
            entry_id=f"mem_pl_{len(self.history) + 1}",
            category="plan",
            content=plan_summary,
            metadata=metadata or {},
        )
        self.history.append(entry)
        logger.debug(f"[Memory] Recorded plan: {plan_summary}")
        return entry

    def record_tool_action(self, tool_name: str, message: str, metadata: Optional[Dict[str, Any]] = None) -> MemoryEntry:
        """Records an executed tool action and outcome."""
        meta = metadata or {}
        meta["tool_name"] = tool_name
        entry = MemoryEntry(
            entry_id=f"mem_tl_{len(self.history) + 1}",
            category="tool_action",
            content=message,
            metadata=meta,
        )
        self.history.append(entry)
        return entry

    def record_explanation(self, explanation: str, metadata: Optional[Dict[str, Any]] = None) -> MemoryEntry:
        """Records a generated root-cause explanation."""
        entry = MemoryEntry(
            entry_id=f"mem_ex_{len(self.history) + 1}",
            category="explanation",
            content=explanation,
            metadata=metadata or {},
        )
        self.history.append(entry)
        return entry

    def update_stage(self, stage: str, **kwargs: Any) -> None:
        """Updates current execution stage and telemetry metrics."""
        self.context.stage = stage
        for k, v in kwargs.items():
            if hasattr(self.context, k):
                setattr(self.context, k, v)

    def get_current_context(self) -> Dict[str, Any]:
        """Returns snapshot of active assessment context."""
        return self.context.model_dump()

    def get_conversation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent memory entries."""
        return [e.model_dump() for e in self.history[-limit:]]

    def get_previous_assessment_metadata(self) -> List[Dict[str, Any]]:
        """Queries repository for past assessment sessions and findings matching target URL."""
        try:
            sessions: List[ScanSessionRecord] = self.repository.list_scan_sessions(limit=10)
            past_data: List[Dict[str, Any]] = []
            for s in sessions:
                if s.id != self.assessment_id and self._is_same_target(s.target_url, self.target_url):
                    past_findings: List[FindingRecord] = self.repository.list_findings(s.id)
                    past_data.append({
                        "assessment_id": s.id,
                        "started_at": s.started_at.isoformat() if s.started_at else None,
                        "status": s.status,
                        "confirmed_findings_count": s.confirmed_findings_count,
                        "findings": [
                            {"title": f.title, "endpoint": f.target_endpoint, "severity": str(f.severity)}
                            for f in past_findings
                        ],
                    })
            return past_data
        except Exception as exc:
            logger.warning(f"Failed to query previous assessment metadata: {exc}")
            return []

    def retrieve_security_knowledge(self, query: str, category: Optional[str] = None) -> List[SecurityKnowledgeItem]:
        """RAG knowledge retrieval matching query keywords and vulnerability categories."""
        q_tokens = set(re.findall(r"\w+", query.lower()))
        matched_items: List[Tuple[int, SecurityKnowledgeItem]] = []

        for item in KNOWLEDGE_BASE:
            score = 0
            if category and item.category.lower() == category.lower():
                score += 10

            for kw in item.keywords:
                if kw in q_tokens:
                    score += 5

            for token in q_tokens:
                if token in item.title.lower():
                    score += 3
                if token in item.description.lower():
                    score += 1

            if score > 0:
                matched_items.append((score, item))

        matched_items.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in matched_items[:3]]

    @staticmethod
    def _is_same_target(url1: str, url2: str) -> bool:
        """Checks if two URLs point to the same host and port."""
        from urllib.parse import urlparse
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return (p1.hostname or "").lower() == (p2.hostname or "").lower() and p1.port == p2.port

