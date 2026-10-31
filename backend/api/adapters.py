"""Unified API Integration Adapters for AuthScope (Member 4).

Connects the agreed cross-team public interfaces via Dependency Injection:
- Group 1: `GeminiAuthScopeAgent` (`astream_assessment(request, cancel_token=None)`)
- Group 2: `ToolRegistryAdapter` (`list_tools()`, `execute_tool_call(tool_name, arguments, context)`)
- Group 3: `MemoryManager` (`get_context(assessment_id)`, `save_observation(assessment_id, observation)`,
  `search_knowledge(query, category=None, limit=5)`, `save_finding(assessment_id, finding)`)

Unifies the Gemini AI Agent, Approved Tool Registry, Memory/RAG system, CodeMapper,
ExplanationEngine, and deterministic AssessmentEngine into a single non-duplicating
assessment pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from backend.ai_agent.agent import GeminiAuthScopeAgent as CanonicalGeminiAgent
from backend.ai_agent.orchestrator import DefaultMemoryBridge
from backend.ai_agent.planner import AssessmentPlan, AssessmentRequest
from backend.analysis.code_mapper import CodeMapper, MappingStatus
from backend.analysis.explanation_engine import ExplanationEngine
from backend.analysis.finding_review import FindingReviewService, ReviewProvider
from backend.core.assessment_engine import (
    AssessmentEngine,
    CancellationToken,
    sanitize_event_metadata,
    sanitize_event_text,
)
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import SessionManager
from backend.scanner.request_executor import RequestExecutor
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    AssessmentEvent,
    AssessmentStage,
    DiscoveredEndpointRecord,
    EventType,
    FindingRecord,
    ScanSessionRecord,
)
from backend.tools.registry import ToolRegistry as CanonicalToolRegistry
from backend.tools.schemas import ToolExecutionContext, ToolExecutionStatus
from backend.utils.helpers import AuthScopeException, ScopeViolationError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class APIIntegrationError(AuthScopeException):
    """Raised when an API pipeline integration error occurs."""


class SessionBoundRepositoryProxy:
    """Wraps FindingRepository so AssessmentEngine persists all records under the API's scan_id.

    Prevents AssessmentEngine.stream_assessment() from creating a duplicate orphan
    ScanSessionRecord with a mismatched scan_id in SQLite.
    """

    def __init__(self, repository: FindingRepository, bound_scan_id: str) -> None:
        self._repo = repository
        self.bound_scan_id = bound_scan_id

    @property
    def db(self) -> Any:
        return self._repo.db

    def initialize_database(self) -> None:
        self._repo.initialize_database()

    def save_scan_session(self, session: ScanSessionRecord) -> str:
        session.id = self.bound_scan_id
        return self._repo.save_scan_session(session)

    def get_scan_session(self, scan_id: str) -> Optional[ScanSessionRecord]:
        target_id = self.bound_scan_id if scan_id != self.bound_scan_id else scan_id
        return self._repo.get_scan_session(target_id)

    def list_scan_sessions(self, limit: int = 50) -> List[ScanSessionRecord]:
        return self._repo.list_scan_sessions(limit=limit)

    def save_event(self, event: AssessmentEvent) -> int:
        event.assessment_id = self.bound_scan_id
        return self._repo.save_event(event)

    def list_events(self, scan_id: str, after_id: Optional[int] = None) -> List[AssessmentEvent]:
        return self._repo.list_events(self.bound_scan_id, after_id=after_id)

    def save_discovered_endpoint(self, endpoint: DiscoveredEndpointRecord) -> str:
        endpoint.scan_id = self.bound_scan_id
        if endpoint.id and not endpoint.id.startswith(f"ep_{self.bound_scan_id}"):
            suffix = endpoint.id.rsplit("_", 1)[-1]
            endpoint.id = f"ep_{self.bound_scan_id}_{suffix}"
        return self._repo.save_discovered_endpoint(endpoint)

    def list_discovered_endpoints(self, scan_id: str) -> List[DiscoveredEndpointRecord]:
        return self._repo.list_discovered_endpoints(self.bound_scan_id)

    def save_finding(self, finding: FindingRecord) -> str:
        finding.scan_id = self.bound_scan_id
        return self._repo.save_finding(finding)

    def update_finding(self, finding: FindingRecord) -> bool:
        finding.scan_id = self.bound_scan_id
        return self._repo.update_finding(finding)

    def get_finding(self, finding_id: str) -> Optional[FindingRecord]:
        return self._repo.get_finding(finding_id)

    def list_findings(self, scan_id: Optional[str] = None) -> List[FindingRecord]:
        return self._repo.list_findings(scan_id or self.bound_scan_id)

    def get_all_findings(self, **kwargs: Any) -> List[FindingRecord]:
        return self._repo.get_all_findings(**kwargs)

    def delete_finding(self, finding_id: str) -> bool:
        return self._repo.delete_finding(finding_id)

    def save_retest_result(self, retest: Any) -> str:
        return self._repo.save_retest_result(retest)

    def get_retest_history(self, finding_id: Optional[str] = None) -> List[Any]:
        return self._repo.get_retest_history(finding_id=finding_id)

    def recover_orphaned_running_sessions(self, active_session_ids: Optional[Any] = None) -> int:
        return self._repo.recover_orphaned_running_sessions(active_session_ids=active_session_ids)


# ==============================================================================
# Group 2 Integration Contract: ToolRegistryAdapter
# ==============================================================================


class ToolRegistryAdapter:
    """Adapter implementing the Group 2 ToolRegistryAdapter public contract.

    Exposes:
    - `list_tools()`
    - `execute_tool_call(tool_name, arguments, context)`
    Backed by Member 2's `backend.tools.registry.ToolRegistry` and `ScopeGuard`.
    """

    TOOL_ALIASES: Dict[str, str] = {
        "check_scope": "validate_target",
        "discover_routes": "discover_endpoints",
        "compare_access": "compare_endpoint_access",
        "validate_evidence_artifact": "validate_evidence",
    }

    def __init__(
        self,
        registry: Optional[CanonicalToolRegistry] = None,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        session_manager: Optional[SessionManager] = None,
    ) -> None:
        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor or RequestExecutor(scope_guard=self.scope_guard)
        self.session_manager = session_manager
        self._registry = registry or CanonicalToolRegistry(
            scope_guard=self.scope_guard,
            executor=self.executor,
            session_manager=self.session_manager,
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns metadata and schemas for all approved tools in the registry."""
        return self._registry.list_tools()

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Union[ToolExecutionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validates and executes a tool call through the canonical ToolRegistry."""
        resolved_name = self.TOOL_ALIASES.get(tool_name, tool_name)
        normalized_args = dict(arguments or {})

        # Normalize common argument aliases for seamless cross-module compatibility
        if resolved_name == "validate_target":
            if "target_url" in normalized_args and "url" not in normalized_args:
                normalized_args["url"] = normalized_args.pop("target_url")
            if "http_method" in normalized_args and "method" not in normalized_args:
                normalized_args["method"] = normalized_args.pop("http_method")

        exec_ctx: Optional[ToolExecutionContext] = None
        if isinstance(context, ToolExecutionContext):
            exec_ctx = context
        elif isinstance(context, dict):
            exec_ctx = ToolExecutionContext(
                assessment_id=str(context.get("assessment_id", "default")),
                target_url=str(context.get("target_url", "http://localhost:3000")),
                agent_step=int(context.get("agent_step", 1)),
            )

        result = self._registry.execute_tool(
            name=resolved_name,
            arguments=normalized_args,
            context=exec_ctx,
        )
        res_output = getattr(result, "output", None) or getattr(result, "data", None) or {}
        return {
            "tool_name": tool_name,
            "resolved_tool_name": resolved_name,
            "execution_id": result.execution_id,
            "status": result.status.value if hasattr(result.status, "value") else str(result.status),
            "success": result.status == ToolExecutionStatus.SUCCESS,
            "output": sanitize_event_metadata(res_output),
            "error": result.error,
            "duration_ms": result.duration_ms,
        }


# ==============================================================================
# Group 3 Integration Contract: MemoryManager
# ==============================================================================


class MemoryManager:
    """Adapter implementing the Group 3 MemoryManager public contract.

    Exposes:
    - `get_context(assessment_id)`
    - `save_observation(assessment_id, observation)`
    - `search_knowledge(query, category=None, limit=5)`
    - `save_finding(assessment_id, finding)`

    Also satisfies `MemorySystemInterface` so it can be injected directly into
    `backend.ai_agent.GeminiAuthScopeAgent`.
    """

    def __init__(
        self,
        bridge: Optional[DefaultMemoryBridge] = None,
        repository: Optional[FindingRepository] = None,
    ) -> None:
        self._bridge = bridge or DefaultMemoryBridge()
        self._repository = repository or FindingRepository()
        self._saved_findings: Dict[str, List[Dict[str, Any]]] = {}

    def get_context(self, assessment_id: str) -> Dict[str, Any]:
        """Retrieves accumulated session context, observations, and persisted findings."""
        ctx = self._bridge.read_assessment_context(assessment_id)
        ctx["assessment_id"] = assessment_id
        ctx["findings"] = list(self._saved_findings.get(assessment_id, []))
        try:
            session = self._repository.get_scan_session(assessment_id)
            if session:
                ctx["target_url"] = session.target_url
                ctx["status"] = session.status
        except Exception as exc:
            logger.debug(f"Could not read scan session {assessment_id} in get_context: {exc}")
        return ctx

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        """Persists a sanitized tool or assessment observation into session memory."""
        self._bridge.store_observation(assessment_id, sanitize_event_metadata(observation))

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Searches the curated OWASP authorization knowledge base."""
        return self._bridge.retrieve_security_knowledge(
            query=query,
            category=category,
            top_k=max(1, limit),
        )

    def save_finding(
        self,
        assessment_id: str,
        finding: Union[FindingRecord, Dict[str, Any]],
    ) -> str:
        """Records a validated finding in memory and persists it if a FindingRecord is provided."""
        if isinstance(finding, FindingRecord):
            finding.scan_id = assessment_id
            finding_id = self._repository.save_finding(finding)
            finding_dict = finding.model_dump(mode="json")
        else:
            finding_dict = sanitize_event_metadata(dict(finding))
            finding_id = str(finding_dict.get("id") or finding_dict.get("finding_id") or f"fnd_{len(self._saved_findings.get(assessment_id, [])) + 1}")
            finding_dict["id"] = finding_id

        if assessment_id not in self._saved_findings:
            self._saved_findings[assessment_id] = []
        self._saved_findings[assessment_id].append(finding_dict)
        self._bridge.store_observation(
            assessment_id,
            {"type": "finding_recorded", "finding_id": finding_id, "finding": finding_dict},
        )
        return finding_id

    # --------------------------------------------------------------------------
    # MemorySystemInterface compatibility methods for CanonicalGeminiAgent
    # --------------------------------------------------------------------------

    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        return self.get_context(assessment_id)

    def update_assessment_context(self, assessment_id: str, data: Dict[str, Any]) -> None:
        self._bridge.update_assessment_context(assessment_id, data)

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        self.save_observation(assessment_id, observation)

    def retrieve_security_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        return self.search_knowledge(query=query, category=category, limit=top_k)

    def get_conversation_context(self, assessment_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        return self._bridge.get_conversation_context(assessment_id, limit=limit)

    def append_conversation_turn(
        self,
        assessment_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._bridge.append_conversation_turn(assessment_id, role=role, content=content, metadata=metadata)


# ==============================================================================
# Group 1 Integration Contract: GeminiAuthScopeAgent
# ==============================================================================


class AssessmentPipelineRequest(BaseModel):
    """Normalized request contract passed to `GeminiAuthScopeAgent.astream_assessment`."""

    assessment_id: str = Field(..., description="Unique scan session ID.")
    target_url: str = Field(default="http://localhost:3000", description="Authorized target URL.")
    objective: str = Field(
        default="Identify Broken Object Level Authorization (BOLA/IDOR) and Broken Function Level Authorization (BFLA) vulnerabilities.",
        description="Assessment security objective.",
    )
    github_repo: Optional[str] = Field(default=None, description="Optional repository URL or local path.")
    source_archive_path: Optional[str] = Field(default=None, description="Optional source archive/directory path.")


class GeminiAuthScopeAgent:
    """Unified Gemini AI Security Agent implementing Group 1's `astream_assessment` contract.

    Coordinates:
    1. ScopeGuard target validation.
    2. Canonical Gemini planner (`backend.ai_agent.GeminiAuthScopeAgent`).
    3. Approved Tool Registry (`ToolRegistryAdapter`).
    4. Real website security checks (`AssessmentEngine`).
    5. Cryptographic Evidence Validation (`EvidenceValidator`).
    6. Memory & RAG (`MemoryManager`).
    7. Source Code Mapping (`CodeMapper`) and Explanation Generation (`ExplanationEngine`).
    """

    def __init__(
        self,
        canonical_agent: Optional[CanonicalGeminiAgent] = None,
        tool_registry: Optional[ToolRegistryAdapter] = None,
        memory_manager: Optional[MemoryManager] = None,
        repository: Optional[FindingRepository] = None,
        scope_guard: Optional[ScopeGuard] = None,
        code_mapper: Optional[CodeMapper] = None,
        explanation_engine: Optional[ExplanationEngine] = None,
        finding_review_provider: Optional[ReviewProvider] = None,
    ) -> None:
        self.scope_guard = scope_guard or ScopeGuard()
        self.repository = repository or FindingRepository()
        self.memory_manager = memory_manager or MemoryManager(repository=self.repository)
        self.tool_registry = tool_registry or ToolRegistryAdapter(scope_guard=self.scope_guard)
        self.canonical_agent = canonical_agent or CanonicalGeminiAgent(
            scope_guard=self.scope_guard,
            memory=self.memory_manager,
        )
        self.code_mapper = code_mapper or CodeMapper()
        self.explanation_engine = explanation_engine or ExplanationEngine()
        # Provider injection keeps model transport under host policy control.
        self.finding_review_service = FindingReviewService(
            provider=finding_review_provider,
            scope_guard=self.scope_guard,
        )

    def create_plan(self, target_url: str, assessment_id: str, objective: str = "") -> AssessmentPlan:
        """Generates a bounded assessment plan via the canonical Gemini planner."""
        req = AssessmentRequest(
            assessment_id=assessment_id,
            target_url=target_url,
            objective=objective or f"Evaluate authorization controls on {target_url}",
        )
        return self.canonical_agent.create_plan(req)

    def enrich_finding_with_source_and_explanation(
        self,
        finding: FindingRecord,
        source_root: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Enriches a validated or suspicious finding with CodeMapper and ExplanationEngine."""
        source_info: Dict[str, Any] = {
            "source_file": None,
            "function_name": None,
            "line_numbers": None,
            "vulnerable_code": None,
            "black_box_only": True,
            "mapping_status": MappingStatus.UNAVAILABLE.value,
        }

        # 1. Attempt source code mapping if a local repository/source directory is provided
        if source_root:
            candidate_path = Path(source_root)
            if candidate_path.exists() and candidate_path.is_dir():
                try:
                    mapper = CodeMapper(repo_root=candidate_path)
                    mapping = mapper.map_runtime_finding(finding)
                    if mapping.status == MappingStatus.EXACT and mapping.location:
                        loc = mapping.location
                        line_str = (
                            f"{loc.start_line}-{loc.end_line}"
                            if loc.end_line > loc.start_line
                            else str(loc.start_line)
                        )
                        source_info = {
                            "source_file": loc.file_path,
                            "function_name": loc.function_name or loc.route_handler,
                            "line_numbers": line_str,
                            "vulnerable_code": loc.code_snippet,
                            "black_box_only": False,
                            "mapping_status": mapping.status.value,
                        }
                        finding.technical_details.update(
                            {
                                "source_file": loc.file_path,
                                "function_name": loc.function_name or loc.route_handler,
                                "line_numbers": line_str,
                                "vulnerable_code": loc.code_snippet,
                            }
                        )
                except Exception as exc:
                    logger.warning(f"Source code mapping skipped for {finding.id}: {exc}")

        # 2. Generate structured simple + technical explanation via ExplanationEngine
        explanation_summary = finding.impact_explanation or finding.description
        remediation_code = finding.remediation_guidance or finding.remediation_recommendation
        try:
            report = self.explanation_engine.generate_explanation(finding)
            explanation_summary = (
                f"{report.simple_explanation.what_happened} "
                f"{report.simple_explanation.why_is_this_a_problem}"
            ).strip()
            if report.code_example and report.code_example.corrected_code:
                remediation_code = report.code_example.corrected_code
                finding.technical_details["suggested_code"] = remediation_code
            finding.technical_details["root_cause"] = report.technical_explanation.root_cause
            finding.technical_details["what_could_attacker_do"] = (
                report.simple_explanation.what_could_an_attacker_do
            )
        except Exception as exc:
            logger.warning(f"ExplanationEngine fallback for {finding.id}: {exc}")

        return {
            "source_info": source_info,
            "explanation": sanitize_event_text(explanation_summary),
            "remediation_code": sanitize_event_text(remediation_code or ""),
        }

    async def astream_assessment(
        self,
        request: Union[AssessmentPipelineRequest, AssessmentRequest, Dict[str, Any]],
        cancel_token: Optional[CancellationToken] = None,
    ) -> AsyncGenerator[AssessmentEvent, None]:
        """Streams real-time AssessmentEvent items for the unified assessment pipeline.

        Executes a single non-duplicating pipeline:
        ScopeGuard check -> Gemini assessment plan -> ToolRegistry & AssessmentEngine execution
        -> Evidence validation -> Memory/RAG recording -> CodeMapper & ExplanationEngine enrichment.
        """
        if isinstance(request, dict):
            scan_id = str(request.get("assessment_id") or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
            target_url = str(request.get("target_url") or "http://localhost:3000").strip().rstrip("/")
            objective = str(
                request.get("objective")
                or f"Execute authorization differential assessment on {target_url}"
            )
            source_root = request.get("source_archive_path") or request.get("github_repo")
        else:
            scan_id = getattr(request, "assessment_id", f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}")
            target_url = str(getattr(request, "target_url", "http://localhost:3000")).strip().rstrip("/")
            objective = str(getattr(request, "objective", f"Execute authorization assessment on {target_url}"))
            source_root = getattr(request, "source_archive_path", None) or getattr(request, "github_repo", None)

        # 1. Enforce ScopeGuard before starting
        scope_check = self.scope_guard.validate_request(url=target_url, method="GET")
        if not scope_check.is_allowed:
            raise ScopeViolationError(f"Scope violation: {scope_check.reason}")

        # 2. Initialize context & retrieve security knowledge in MemoryManager
        self.memory_manager.update_assessment_context(
            scan_id,
            {"target_url": target_url, "objective": objective, "started_at": datetime.now(timezone.utc).isoformat()},
        )
        knowledge_items = self.memory_manager.search_knowledge(query=objective, limit=3)

        # 3. Create bounded Gemini assessment plan
        try:
            plan = await asyncio.to_thread(self.create_plan, target_url, scan_id, objective)
            plan_steps = [f"{s.step_number}. {s.description}" for s in plan.steps]
            plan_summary = plan.objective_summary
        except Exception as exc:
            logger.warning(f"Planner fallback used for {scan_id}: {exc}")
            plan_steps = [
                "1. Validate target scope against strict ScopeGuard allowlist.",
                "2. Establish target connectivity and verify HTTP response.",
                "3. Discover attack surface endpoints and parameterized resources.",
                "4. Validate multi-role testing personas (User A, User B, Admin).",
                "5. Execute cross-account differential tests on identified endpoints.",
                "6. Cryptographically sign and validate evidence artifacts (SHA-256).",
                "7. Compile findings and synthesize remediation code patches.",
            ]
            plan_summary = "7-stage authorization evaluation plan initialized."

        # Record plan observation in MemoryManager
        self.memory_manager.save_observation(
            scan_id,
            {
                "type": "agent_plan",
                "summary": plan_summary,
                "steps": plan_steps,
                "knowledge_count": len(knowledge_items),
            },
        )

        # 4. Execute the single real AssessmentEngine pipeline bound to scan_id
        bound_repo = SessionBoundRepositoryProxy(repository=self.repository, bound_scan_id=scan_id)
        engine = AssessmentEngine(
            repository=bound_repo,  # type: ignore[arg-type]
            scope_guard=self.scope_guard,
        )
        gen = engine.stream_assessment(target_url=target_url, cancel_token=cancel_token)

        while True:
            event: Optional[AssessmentEvent] = await asyncio.to_thread(lambda: next(gen, None))
            if event is None:
                break

            event.assessment_id = scan_id

            # Attach Gemini plan metadata to ASSESSMENT_STARTED event so SSE stream emits agent_thinking & agent_plan
            if event.event_type == EventType.ASSESSMENT_STARTED.value:
                event.metadata["plan_summary"] = plan_summary
                event.metadata["plan_steps"] = plan_steps
                event.metadata["thinking_message"] = (
                    f"Formulating authorization testing strategy for {target_url} "
                    f"using {len(knowledge_items)} OWASP security knowledge blueprints."
                )

            # Record observation in MemoryManager
            self.memory_manager.save_observation(
                scan_id,
                {
                    "event_type": event.event_type,
                    "stage": event.stage,
                    "message": event.message,
                    "metadata": event.metadata,
                },
            )

            # Enrich findings with CodeMapper and ExplanationEngine when detected/confirmed
            if event.event_type in (
                EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value,
                EventType.FINDING_CONFIRMED.value,
            ):
                finding_id = event.metadata.get("finding_id")
                finding = self.repository.get_finding(str(finding_id)) if finding_id else None
                if finding is not None:
                    review_is_eligible = (
                        event.event_type == EventType.FINDING_CONFIRMED.value
                        and finding.evidence is not None
                    )
                    if review_is_eligible:
                        yield AssessmentEvent(
                            assessment_id=scan_id,
                            event_type="ai_review_started",
                            stage="AI_REVIEW",
                            message="Reviewing validated finding evidence.",
                            metadata={"finding_id": finding.id},
                        )
                        yield AssessmentEvent(
                            assessment_id=scan_id,
                            event_type="ai_review_progress",
                            stage="AI_REVIEW",
                            message="Preparing redacted evidence context for review.",
                            metadata={"finding_id": finding.id},
                        )
                        review = await asyncio.to_thread(
                            self.finding_review_service.review,
                            finding,
                            finding.technical_details.get("source_mapping"),
                        )
                        review_data = review.model_dump(mode="json")
                        event.metadata["ai_review"] = review_data
                        finding.technical_details["ai_review"] = review_data
                        yield AssessmentEvent(
                            assessment_id=scan_id,
                            event_type="ai_review_completed",
                            stage="AI_REVIEW",
                            message="Advisory AI review completed.",
                            metadata={"finding_id": finding.id, "ai_review": review_data},
                        )
                        if review.fix_recommendation:
                            yield AssessmentEvent(
                                assessment_id=scan_id,
                                event_type="fix_recommendation_generated",
                                stage="AI_REVIEW",
                                message="Advisory fix recommendation generated.",
                                metadata={"finding_id": finding.id, "fix_recommendation": review.fix_recommendation},
                            )
                    enrichment = await asyncio.to_thread(
                        self.enrich_finding_with_source_and_explanation,
                        finding,
                        str(source_root) if source_root else None,
                    )
                    self.repository.update_finding(finding)
                    self.memory_manager.save_finding(scan_id, finding)
                    event.metadata["source_info"] = enrichment["source_info"]
                    event.metadata["explanation"] = enrichment["explanation"]
                    event.metadata["remediation_code"] = enrichment["remediation_code"]
                else:
                    event.metadata["source_info"] = {
                        "source_file": None,
                        "function_name": None,
                        "line_numbers": None,
                        "vulnerable_code": None,
                        "black_box_only": True,
                        "mapping_status": MappingStatus.UNAVAILABLE.value,
                    }

            yield event
            await asyncio.sleep(0.02)

