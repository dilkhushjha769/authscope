"""Long-term assessment memory.

Wraps the existing FindingRepository and DatabaseManager to provide persistent
retrieval of assessment history, finding metadata, and summary records.

Rules:
- NEVER duplicate finding records — check existence first.
- NEVER store passwords, JWTs, bearer tokens, API keys, or session cookies.
- NEVER create a competing SQLite database — reuse the existing DatabaseManager.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import FindingRecord, ScanSessionRecord
from backend.utils.helpers import DuplicateRecordError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class LongTermMemory:
    """Persistent memory layer backed by the existing SQLite storage.

    Uses FindingRepository for all read/write operations.
    Adds a lightweight *assessment_summaries* concept stored as JSON blobs
    inside the existing ``scan_sessions.summary_text`` column (no new tables).
    """

    def __init__(self, repository: Optional[FindingRepository] = None) -> None:
        self._repo: FindingRepository = repository or FindingRepository()

    # ------------------------------------------------------------------
    # Finding persistence
    # ------------------------------------------------------------------

    def save_finding(
        self,
        assessment_id: str,
        finding: FindingRecord,
        *,
        allow_overwrite: bool = False,
    ) -> str:
        """Persist *finding* to SQLite.

        Checks for duplicate IDs before writing to avoid double-counting.

        Args:
            assessment_id: The parent assessment ID (used for logging only).
            finding:        The FindingRecord to persist.
            allow_overwrite: When ``True``, replaces an existing record with
                             the same ID.  Defaults to ``False`` (safe mode).

        Returns:
            The stored finding ID.

        Raises:
            DuplicateRecordError: If the finding already exists and
                                  *allow_overwrite* is ``False``.
        """
        existing = self._repo.get_finding(finding.id)
        if existing is not None and not allow_overwrite:
            logger.debug(
                "LongTermMemory: finding already exists, skipping",
                extra={"finding_id": finding.id, "assessment_id": assessment_id},
            )
            raise DuplicateRecordError(
                f"Finding '{finding.id}' already persisted for assessment '{assessment_id}'."
            )

        stored_id = self._repo.save_finding(finding, overwrite=allow_overwrite)
        logger.info(
            "LongTermMemory: finding persisted",
            extra={"finding_id": stored_id, "assessment_id": assessment_id},
        )
        return stored_id

    def get_finding_history(
        self,
        target_url: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return sanitized metadata dicts for historical findings on *target_url*."""
        findings = self._repo.get_all_findings(target_identifier=target_url)
        results: List[Dict[str, Any]] = []
        for f in findings[:limit]:
            results.append(
                {
                    "id": f.id,
                    "title": f.title,
                    "endpoint": f.endpoint,
                    "vulnerability_type": f.vulnerability_type,
                    "severity": (
                        f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    ),
                    "status": f.status,
                    "created_at": (
                        f.created_at.isoformat() if f.created_at else None
                    ),
                }
            )
        return results

    # ------------------------------------------------------------------
    # Assessment session retrieval
    # ------------------------------------------------------------------

    def get_previous_assessments(
        self,
        target_url: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Return summary metadata for previous assessments against *target_url*.

        Queries existing scan_sessions table via FindingRepository.
        """
        sessions: List[ScanSessionRecord] = self._repo.list_scan_sessions(limit=200)
        # Filter to the requested target (exact or prefix match)
        matching = [s for s in sessions if target_url in s.target_url or s.target_url in target_url]
        results: List[Dict[str, Any]] = []
        for s in matching[:limit]:
            results.append(
                {
                    "assessment_id": s.id,
                    "target_url": s.target_url,
                    "status": s.status,
                    "started_at": (
                        s.started_at.isoformat() if s.started_at else None
                    ),
                    "completed_at": (
                        s.completed_at.isoformat() if s.completed_at else None
                    ),
                    "confirmed_findings_count": s.confirmed_findings_count,
                    "endpoints_tested_count": s.endpoints_tested_count,
                    "summary_text": s.summary_text or "",
                }
            )
        return results

    def get_all_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return metadata for the most recent *limit* scan sessions."""
        sessions = self._repo.list_scan_sessions(limit=limit)
        return [
            {
                "assessment_id": s.id,
                "target_url": s.target_url,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "confirmed_findings_count": s.confirmed_findings_count,
                "endpoints_tested_count": s.endpoints_tested_count,
            }
            for s in sessions
        ]

    # ------------------------------------------------------------------
    # Assessment summary persistence
    # ------------------------------------------------------------------

    def save_assessment_summary(
        self, assessment_id: str, summary: Dict[str, Any]
    ) -> None:
        """Persist a structured summary dict as JSON inside an existing scan session.

        If the session does not exist, this is a no-op (we do not create sessions).
        """
        session = self._repo.get_scan_session(assessment_id)
        if session is None:
            logger.warning(
                "LongTermMemory: scan session not found — cannot save summary",
                extra={"assessment_id": assessment_id},
            )
            return

        try:
            session.summary_text = json.dumps(summary, default=str)
            self._repo.save_scan_session(session)
            logger.debug(
                "LongTermMemory: summary saved",
                extra={"assessment_id": assessment_id},
            )
        except Exception as exc:
            logger.error(
                "LongTermMemory: failed to save summary",
                extra={"assessment_id": assessment_id, "error": str(exc)},
            )

    def get_assessment_summary(
        self, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the persisted summary for *assessment_id*.

        Returns ``None`` if the session does not exist or has no JSON summary.
        """
        session = self._repo.get_scan_session(assessment_id)
        if session is None:
            return None
        if not session.summary_text:
            return None
        try:
            return json.loads(session.summary_text)
        except Exception:
            # Plain text summary (legacy)
            return {"summary_text": session.summary_text}

