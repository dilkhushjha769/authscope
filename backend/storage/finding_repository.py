"""Finding & Assessment Repository: CRUD operations for scans, events, endpoints, and findings."""

from typing import List, Optional, Dict
import json
from datetime import datetime, timezone

from backend.storage.database import DatabaseManager
from backend.storage.models import (
    AssessmentEvent,
    DiscoveredEndpointRecord,
    FindingRecord,
    ScanSessionRecord,
    StageStateRecord,
)
from backend.analysis.evidence_validator import EvidenceArtifact
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class FindingRepository:
    """Manages persistence of security assessments, real-time events, endpoints, and findings."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.db.init_schema()

    def save_scan_session(self, session: ScanSessionRecord) -> str:
        """Inserts or updates a ScanSessionRecord in SQLite."""
        stages_serialized = {
            k: v.model_dump(mode="json") for k, v in (session.stages or {}).items()
        }
        started_str = (
            session.started_at.isoformat()
            if isinstance(session.started_at, datetime)
            else str(session.started_at)
        )
        completed_str = (
            session.completed_at.isoformat()
            if isinstance(session.completed_at, datetime)
            else (str(session.completed_at) if session.completed_at else None)
        )

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_sessions (
                    id, target_url, status, started_at, completed_at,
                    endpoints_discovered_count, endpoints_tested_count,
                    confirmed_findings_count, suspicious_results_count,
                    stages_json, summary_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.target_url,
                    session.status,
                    started_str,
                    completed_str,
                    session.endpoints_discovered_count,
                    session.endpoints_tested_count,
                    session.confirmed_findings_count,
                    session.suspicious_results_count,
                    json.dumps(stages_serialized),
                    session.summary_text,
                ),
            )
            conn.commit()
        return session.id

    def get_scan_session(self, scan_id: str) -> Optional[ScanSessionRecord]:
        """Retrieves a single ScanSessionRecord by ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id = ?", (scan_id,)
            ).fetchone()

        if not row:
            return None
        return self._row_to_scan_session(row)

    def list_scan_sessions(self, limit: int = 50) -> List[ScanSessionRecord]:
        """Lists persisted assessments ordered by most recent first."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [self._row_to_scan_session(r) for r in rows]

    @staticmethod
    def _row_to_scan_session(row) -> ScanSessionRecord:
        row_keys = row.keys()
        stages_dict: Dict[str, StageStateRecord] = {}
        raw_stages = row["stages_json"] if "stages_json" in row_keys else "{}"
        if raw_stages:
            try:
                parsed = json.loads(raw_stages)
                for k, v in parsed.items():
                    stages_dict[k] = StageStateRecord.model_validate(v)
            except Exception:
                pass

        return ScanSessionRecord(
            id=row["id"],
            target_url=row["target_url"],
            status=row["status"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            endpoints_discovered_count=(
                row["endpoints_discovered_count"] if "endpoints_discovered_count" in row_keys else 0
            ),
            endpoints_tested_count=(
                row["endpoints_tested_count"] if "endpoints_tested_count" in row_keys else 0
            ),
            confirmed_findings_count=(
                row["confirmed_findings_count"] if "confirmed_findings_count" in row_keys else 0
            ),
            suspicious_results_count=(
                row["suspicious_results_count"] if "suspicious_results_count" in row_keys else 0
            ),
            stages=stages_dict,
            summary_text=row["summary_text"] if "summary_text" in row_keys else "",
        )

    def save_event(self, event: AssessmentEvent) -> None:
        """Persists a sanitized real-time AssessmentEvent to SQLite."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assessment_events (
                    scan_id, event_type, stage, message, timestamp, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.assessment_id,
                    event.event_type,
                    event.stage,
                    event.message,
                    event.timestamp,
                    json.dumps(event.metadata or {}),
                ),
            )
            conn.commit()

    def list_events(self, scan_id: str) -> List[AssessmentEvent]:
        """Lists all persisted events for a given assessment in chronological order."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM assessment_events WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()

        events: List[AssessmentEvent] = []
        for r in rows:
            meta = {}
            if r["metadata_json"]:
                try:
                    meta = json.loads(r["metadata_json"])
                except Exception:
                    pass
            events.append(
                AssessmentEvent(
                    assessment_id=r["scan_id"],
                    event_type=r["event_type"],
                    stage=r["stage"],
                    message=r["message"],
                    timestamp=r["timestamp"],
                    metadata=meta,
                )
            )
        return events

    def save_discovered_endpoint(self, endpoint: DiscoveredEndpointRecord) -> str:
        """Inserts or updates a DiscoveredEndpointRecord for an assessment."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO discovered_endpoints (
                    id, scan_id, path, method, category, parameters_json,
                    requires_auth, discovery_status, test_status, verdict,
                    associated_finding_ids_json, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    endpoint.id,
                    endpoint.scan_id,
                    endpoint.path,
                    endpoint.method,
                    endpoint.category,
                    json.dumps(endpoint.parameters),
                    1 if endpoint.requires_auth else 0,
                    endpoint.discovery_status,
                    endpoint.test_status,
                    endpoint.verdict,
                    json.dumps(endpoint.associated_finding_ids),
                    endpoint.summary,
                ),
            )
            conn.commit()
        return endpoint.id

    def list_discovered_endpoints(self, scan_id: str) -> List[DiscoveredEndpointRecord]:
        """Lists all discovered endpoints for a given assessment."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM discovered_endpoints WHERE scan_id = ? ORDER BY path ASC",
                (scan_id,),
            ).fetchall()

        results: List[DiscoveredEndpointRecord] = []
        for r in rows:
            params_list = []
            finding_ids = []
            try:
                params_list = json.loads(r["parameters_json"] or "[]")
            except Exception:
                pass
            try:
                finding_ids = json.loads(r["associated_finding_ids_json"] or "[]")
            except Exception:
                pass
            results.append(
                DiscoveredEndpointRecord(
                    id=r["id"],
                    scan_id=r["scan_id"],
                    path=r["path"],
                    method=r["method"],
                    category=r["category"] or "UNKNOWN",
                    parameters=params_list,
                    requires_auth=bool(r["requires_auth"]),
                    discovery_status=r["discovery_status"] or "DISCOVERED",
                    test_status=r["test_status"] or "UNTESTED",
                    verdict=r["verdict"],
                    associated_finding_ids=finding_ids,
                    summary=r["summary"] or "",
                )
            )
        return results

    def save_finding(self, finding: FindingRecord) -> str:
        """Persists a finding record and its associated EvidenceArtifact."""
        logger.info("Saving finding to database", extra={"finding_id": finding.id, "title": finding.title})
        evidence_str = (
            json.dumps(finding.evidence.model_dump(mode="json"))
            if finding.evidence is not None
            else None
        )
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, scan_id, title, vulnerability_type, severity, status,
                    validation_status, access_verdict, target_endpoint, http_method,
                    resource_id, expected_behavior, actual_behavior,
                    description, remediation_guidance, retest_status, evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.scan_id,
                    finding.title,
                    finding.vulnerability_type,
                    finding.severity.value,
                    finding.status,
                    finding.validation_status,
                    finding.access_verdict,
                    finding.target_endpoint,
                    finding.http_method,
                    finding.resource_id,
                    finding.expected_behavior,
                    finding.actual_behavior,
                    finding.description,
                    finding.remediation_guidance,
                    finding.retest_status,
                    evidence_str,
                ),
            )
            if finding.evidence is not None:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_artifacts (
                        id, finding_id, test_role, authorized_role,
                        request_method, request_url, response_status,
                        response_body, evidence_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.evidence.id,
                        finding.id,
                        finding.evidence.test_role.value,
                        finding.evidence.authorized_role.value,
                        finding.evidence.request_method,
                        finding.evidence.request_url,
                        finding.evidence.response_status,
                        finding.evidence.response_body,
                        finding.evidence.evidence_sha256,
                    ),
                )
            conn.commit()
        return finding.id

    def list_findings(self, scan_id: Optional[str] = None) -> List[FindingRecord]:
        """Lists findings, optionally filtered by scan_id."""
        with self.db.get_connection() as conn:
            query = "SELECT * FROM findings"
            params = ()
            if scan_id:
                query += " WHERE scan_id = ?"
                params = (scan_id,)
            query += " ORDER BY created_at DESC"
            rows = conn.execute(query, params).fetchall()

        results: List[FindingRecord] = []
        for row in rows:
            row_keys = row.keys()
            evi_obj: Optional[EvidenceArtifact] = None
            if "evidence_json" in row_keys and row["evidence_json"]:
                try:
                    evi_obj = EvidenceArtifact.model_validate(json.loads(row["evidence_json"]))
                except Exception:
                    pass

            results.append(
                FindingRecord(
                    id=row["id"],
                    scan_id=row["scan_id"],
                    title=row["title"],
                    vulnerability_type=row["vulnerability_type"],
                    severity=row["severity"],
                    status=row["status"],
                    validation_status=(
                        row["validation_status"] if "validation_status" in row_keys and row["validation_status"] else "CONFIRMED"
                    ),
                    access_verdict=(
                        row["access_verdict"]
                        if "access_verdict" in row_keys and row["access_verdict"]
                        else "CONFIRMED_UNAUTHORIZED_ACCESS"
                    ),
                    target_endpoint=row["target_endpoint"],
                    http_method=row["http_method"],
                    resource_id=row["resource_id"] if "resource_id" in row_keys else None,
                    expected_behavior=(
                        row["expected_behavior"] if "expected_behavior" in row_keys and row["expected_behavior"] else ""
                    ),
                    actual_behavior=(
                        row["actual_behavior"] if "actual_behavior" in row_keys and row["actual_behavior"] else ""
                    ),
                    description=row["description"],
                    remediation_guidance=row["remediation_guidance"],
                    retest_status=(
                        row["retest_status"] if "retest_status" in row_keys and row["retest_status"] else "NOT_RETESTED"
                    ),
                    created_at=row["created_at"],
                    evidence=evi_obj,
                )
            )
        return results
