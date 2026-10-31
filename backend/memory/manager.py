"""MemoryManager — public interface for AuthScope Memory Subsystem.

This is the ONLY entry point Members 1 and 4 should import.

Public API (exact signatures as specified):
    manager.get_context(assessment_id: str) -> dict
    manager.save_observation(assessment_id: str, observation: str) -> None
    manager.search_knowledge(query: str, category: Optional[str] = None, limit: int = 5) -> list
    manager.save_finding(assessment_id: str, finding: FindingRecord) -> None

Additional helpers:
    manager.create_assessment(assessment_id: str, target_url: str) -> dict
    manager.get_previous_assessments(target_url: str, limit: int = 10) -> list
    manager.analyze_finding_with_source(finding: FindingRecord, repo_root: Optional[str]) -> dict

Security constraints enforced here:
- Credentials are never stored (sanitized in ShortTermMemory).
- Duplicate finding records are avoided (checked in LongTermMemory).
- Retrieval mode is always honestly labelled.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.memory.long_term import LongTermMemory
from backend.memory.rag import SecurityKnowledgeRAG
from backend.memory.short_term import ShortTermMemory
from backend.memory.source_integration import SourceCodeIntegration
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord
from backend.utils.helpers import DuplicateRecordError
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Default knowledge-base directory relative to repository root
_DEFAULT_KB_DIR = Path(__file__).parent.parent.parent / "knowledge_base"
# Default ChromaDB persistence directory
_DEFAULT_CHROMA_DIR = Path(__file__).parent.parent.parent / "data" / "chroma_kb"


class MemoryManager:
    """Unified memory interface for the AuthScope AI security assessment engine.

    Instantiate once and share across the assessment lifecycle::

        manager = MemoryManager()
        manager.create_assessment("scan-001", "http://localhost:3000")

        manager.save_observation("scan-001", "Discovered endpoint GET /api/baskets/{id}")
        ctx = manager.get_context("scan-001")

        knowledge = manager.search_knowledge("BOLA basket ownership check", limit=3)

        manager.save_finding("scan-001", finding_record)

    Args:
        repository:         Existing FindingRepository instance.  A new one is
                            created automatically when None (uses default DB path).
        chroma_path:        Path for ChromaDB persistence.  Falls back to
                            in-process NumPy vector store when ChromaDB is
                            unavailable.
        gemini_api_key:     Gemini API key for embedding generation.  When None,
                            the GEMINI_API_KEY / GOOGLE_API_KEY env variable is used.
        use_vector_rag:     Enable semantic vector retrieval.  Defaults to True.
        knowledge_base_dir: Directory containing ``*.md`` knowledge documents.
                            Defaults to ``knowledge_base/`` in the repository root.
        embed_fn:           Inject a custom embedding function (primarily for
                            unit tests to avoid real API calls).
    """

    def __init__(
        self,
        repository: Optional[FindingRepository] = None,
        chroma_path: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        use_vector_rag: bool = True,
        knowledge_base_dir: Optional[str] = None,
        embed_fn: Optional[Any] = None,
    ) -> None:
        # --- Resolve dependencies ---
        self._repo: FindingRepository = repository or FindingRepository()
        api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        chroma_dir = chroma_path or str(_DEFAULT_CHROMA_DIR)
        kb_dir = Path(knowledge_base_dir) if knowledge_base_dir else _DEFAULT_KB_DIR

        # --- Sub-systems ---
        self._short_term = ShortTermMemory()
        self._long_term = LongTermMemory(repository=self._repo)
        self._rag = SecurityKnowledgeRAG(
            chroma_path=chroma_dir,
            gemini_api_key=api_key,
            use_vector=use_vector_rag,
            embed_fn=embed_fn,
        )
        self._source_integration = SourceCodeIntegration()

        # --- Ingest knowledge base documents ---
        if kb_dir.exists():
            try:
                count = self._rag.ingest_documents(kb_dir)
                logger.info(
                    "MemoryManager: knowledge base ingested",
                    extra={"chunks": count, "mode": self._rag.retrieval_mode},
                )
            except Exception as exc:
                logger.warning(
                    "MemoryManager: knowledge base ingestion failed",
                    extra={"error": str(exc)},
                )
        else:
            logger.warning(
                "MemoryManager: knowledge base directory not found",
                extra={"path": str(kb_dir)},
            )

        logger.info(
            "MemoryManager initialised",
            extra={"retrieval_mode": self._rag.retrieval_mode},
        )

    # ==================================================================
    # Required public interface (exact signatures from spec)
    # ==================================================================

    def get_context(self, assessment_id: str) -> dict:
        """Return the current assessment context as a plain dict.

        Returns an empty dict when no context exists for *assessment_id*.

        Args:
            assessment_id: Unique assessment identifier.

        Returns:
            dict with keys: assessment_id, target_url, stage,
            discovered_endpoints, tested_endpoints, observations,
            confirmed_finding_ids, conversation_context, created_at, updated_at.
        """
        return self._short_term.get_context_dict(assessment_id)

    def save_observation(self, assessment_id: str, observation: str) -> None:
        """Sanitize and persist *observation* in the short-term context.

        Credentials (JWTs, Bearer tokens, cookies, API keys, passwords) are
        automatically redacted before storage.

        Args:
            assessment_id: Unique assessment identifier.
            observation:   Free-text security observation (may be raw output
                           from tools or agent thoughts).
        """
        self._short_term.add_observation(assessment_id, observation)

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> list:
        """Retrieve relevant security knowledge chunks for *query*.

        Uses semantic vector retrieval when available, otherwise keyword
        matching (clearly labelled via ``retrieval_mode`` on each result).

        Args:
            query:    Natural-language or keyword query.
            category: Optional vulnerability category filter
                      (e.g., "BOLA_IDOR", "BFLA", "MISSING_AUTH").
            limit:    Maximum number of results to return.

        Returns:
            List of dicts with keys: chunk_id, source, category, content,
            retrieval_mode, similarity_score, metadata.
        """
        try:
            chunks = self._rag.search(query=query, category=category, limit=limit)
            return [c.model_dump() for c in chunks]
        except Exception as exc:
            logger.error(
                "MemoryManager: knowledge search failed",
                extra={"error": str(exc), "query": query},
            )
            return []

    def save_finding(self, assessment_id: str, finding: FindingRecord) -> None:
        """Persist *finding* to long-term SQLite storage and register its ID in
        the short-term context.

        Duplicate finding IDs are silently skipped (idempotent).

        Args:
            assessment_id: Unique assessment identifier.
            finding:       A validated FindingRecord to persist.
        """
        try:
            self._long_term.save_finding(assessment_id, finding, allow_overwrite=False)
        except DuplicateRecordError:
            logger.debug(
                "MemoryManager: finding already persisted — skipping",
                extra={"finding_id": finding.id, "assessment_id": assessment_id},
            )
        except Exception as exc:
            logger.error(
                "MemoryManager: failed to persist finding",
                extra={"finding_id": finding.id, "error": str(exc)},
            )
            return

        # Register finding ID in short-term context
        try:
            self._short_term.add_finding_id(assessment_id, finding.id)
        except Exception as exc:
            logger.warning(
                "MemoryManager: could not register finding_id in short-term context",
                extra={"finding_id": finding.id, "error": str(exc)},
            )

    # ==================================================================
    # Additional helpers (not in spec but useful)
    # ==================================================================

    def create_assessment(self, assessment_id: str, target_url: str) -> dict:
        """Initialise a fresh context for *assessment_id*.

        Safe to call multiple times; subsequent calls reset the context.

        Args:
            assessment_id: Unique assessment identifier.
            target_url:    Authorized target URL for this assessment.

        Returns:
            The fresh context dict.
        """
        ctx = self._short_term.create(assessment_id, target_url)
        return ctx.model_dump(mode="json")

    def update_stage(self, assessment_id: str, stage: str) -> None:
        """Update the current stage label in short-term context."""
        self._short_term.update_stage(assessment_id, stage)

    def add_tool_result(self, assessment_id: str, result: Dict[str, Any]) -> None:
        """Store a sanitized tool result in short-term context."""
        self._short_term.add_tool_result(assessment_id, result)

    def add_conversation_turn(
        self, assessment_id: str, role: str, content: str
    ) -> None:
        """Append a conversation turn to the short-term context."""
        self._short_term.add_conversation_turn(assessment_id, role, content)

    def get_previous_assessments(
        self, target_url: str, limit: int = 10
    ) -> list:
        """Return metadata for previous assessments against *target_url*.

        Args:
            target_url: The target to filter by.
            limit:      Maximum number of sessions to return.

        Returns:
            List of dicts with keys: assessment_id, target_url, status,
            started_at, completed_at, confirmed_findings_count, etc.
        """
        try:
            return self._long_term.get_previous_assessments(target_url, limit=limit)
        except Exception as exc:
            logger.error(
                "MemoryManager: get_previous_assessments failed",
                extra={"error": str(exc)},
            )
            return []

    def get_finding_history(self, target_url: str, limit: int = 50) -> list:
        """Return metadata for historical findings on *target_url*."""
        try:
            return self._long_term.get_finding_history(target_url, limit=limit)
        except Exception as exc:
            logger.error(
                "MemoryManager: get_finding_history failed",
                extra={"error": str(exc)},
            )
            return []

    def analyze_finding_with_source(
        self,
        finding: FindingRecord,
        repo_root: Optional[str] = None,
    ) -> dict:
        """Produce a structured explanation of *finding* with optional source mapping.

        When *repo_root* is provided and exists, attempts to locate the
        vulnerable handler in the repository.  Without it, returns a
        black-box HTTP-evidence-based analysis.

        Args:
            finding:   Validated FindingRecord.
            repo_root: Path to the target application's source tree (optional).

        Returns:
            dict with keys: finding_id, what_happened, why_security_problem,
            evidence_summary, potential_impact, likely_root_cause,
            source_location (or None), suggested_fix (or None),
            how_to_retest, analysis_type, disclaimer.
        """
        try:
            result = self._source_integration.analyze_finding(finding, repo_root=repo_root)
            return result.model_dump()
        except Exception as exc:
            logger.error(
                "MemoryManager: analyze_finding_with_source failed",
                extra={"finding_id": finding.id, "error": str(exc)},
            )
            return {
                "finding_id": finding.id,
                "what_happened": "Analysis failed due to an internal error.",
                "why_security_problem": "Unknown",
                "evidence_summary": "",
                "potential_impact": "Unknown",
                "likely_root_cause": "Unknown",
                "source_location": None,
                "suggested_fix": None,
                "how_to_retest": "Manual investigation required.",
                "analysis_type": "error",
                "disclaimer": f"Analysis failed: {exc}",
            }

    def save_assessment_summary(
        self, assessment_id: str, summary: Dict[str, Any]
    ) -> None:
        """Persist a structured summary dict for *assessment_id*."""
        self._long_term.save_assessment_summary(assessment_id, summary)

    def get_assessment_summary(
        self, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a previously persisted summary for *assessment_id*."""
        return self._long_term.get_assessment_summary(assessment_id)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def retrieval_mode(self) -> str:
        """The active RAG retrieval mode label."""
        return self._rag.retrieval_mode

    @property
    def knowledge_chunk_count(self) -> int:
        """Number of indexed knowledge chunks."""
        return self._rag.chunk_count

