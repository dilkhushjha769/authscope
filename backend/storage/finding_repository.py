"""Finding & Assessment Repository: CRUD operations for scans, events, endpoints, and findings.

Implements safe parameterized SQL queries, complete type enforcement, and
atomic transaction lifecycle. Redacts sensitive credentials before disk write.
"""

from typing import List, Optional, Dict, Any, Union
import json
from datetime import datetime, timezone
import sqlite3
import uuid

from backend.storage.database import DatabaseManager, initialize_database
from backend.storage.models import (
    AssessmentEvent,
    DiscoveredEndpointRecord,
    EvidenceArtifact,
    FindingRecord,
    RetestLogRecord,
    ScanSessionRecord,
    StageStateRecord,
)
from backend.utils.helpers import (
    RecordNotFoundError,
    DuplicateRecordError,
    InvalidDataError,
    redact_sensitive_text,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Helper to convert datetime to ISO-8601 string."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.isoformat()


def _iso_to_dt(iso_str: Optional[str]) -> Optional[datetime]:
    """Helper to parse ISO-8601 string to datetime."""
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(iso_str)
    except Exception:
        return None


class FindingRepository:
    """Manages persistence of security scans, confirmed findings, endpoints, and events."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.db.init_schema()

    def initialize_database(self) -> None:
        """Explicitly re-initializes DDL schema if needed."""
        self.db.init_schema()

    def save_scan_session(self, session: ScanSessionRecord) -> str:
        """Inserts or updates a ScanSessionRecord in SQLite."""
        stages_serialized = {
            k: v.model_dump(mode="json") for k, v in (session.stages or {}).items()
        }
        started_str = _dt_to_iso(session.started_at)
        completed_str = _dt_to_iso(session.completed_at)
        updated_str = _dt_to_iso(session.updated_at or datetime.now(timezone.utc))

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_sessions (
                    id, target_url, status, started_at, completed_at,
                    endpoints_discovered_count, endpoints_tested_count,
                    confirmed_findings_count, suspicious_results_count,
                    stages_json, summary_text, config_json, updated_at, failure_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(session.config or {}),
                    updated_str,
                    session.failure_reason or "",
                ),
            )
            conn.commit()
        return session.id

    def recover_orphaned_running_sessions(self, active_session_ids: Optional[Set[str]] = None) -> int:
        """Identifies assessments left in RUNNING/PENDING state from previous server executions and marks them FAILED.

        Args:
            active_session_ids: Optional set of actively running in-memory task IDs to preserve.

        Returns:
            Count of orphaned sessions marked as FAILED with SERVER_RESTART.
        """
        active_set = active_session_ids or set()
        with self.db.get_connection() as conn:
            query = "SELECT id FROM scan_sessions WHERE status IN ('RUNNING', 'PENDING')"
            rows = conn.execute(query).fetchall()
            orphaned = [r["id"] for r in rows if r["id"] not in active_set]
            if not orphaned:
                return 0

            placeholders = ",".join("?" for _ in orphaned)
            now_iso = _dt_to_iso(datetime.now(timezone.utc))
            conn.execute(
                f"""
                UPDATE scan_sessions
                SET status = 'FAILED',
                    completed_at = ?,
                    updated_at = ?,
                    failure_reason = 'SERVER_RESTART',
                    summary_text = 'Assessment interrupted by server restart.'
                WHERE id IN ({placeholders})
                """,
                (now_iso, now_iso, *orphaned),
            )
            for scan_id in orphaned:
                conn.execute(
                    """
                    INSERT INTO assessment_events (
                        scan_id, event_type, stage, message, timestamp, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        "assessment_failed",
                        "report_preparation",
                        "Assessment was interrupted by server restart (SERVER_RESTART). Operator can retry.",
                        now_iso,
                        json.dumps({"reason": "SERVER_RESTART", "failure_reason": "SERVER_RESTART"}),
                    ),
                )
            conn.commit()
            return len(orphaned)

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

        cfg = {}
        if "config_json" in row_keys and row["config_json"]:
            try:
                cfg = json.loads(row["config_json"])
            except Exception:
                cfg = {}

        return ScanSessionRecord(
            id=row["id"],
            target_url=row["target_url"],
            status=row["status"],
            started_at=_iso_to_dt(row["started_at"]) or datetime.now(timezone.utc),
            completed_at=_iso_to_dt(row["completed_at"]),
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
            config=cfg,
            updated_at=_iso_to_dt(row["updated_at"]) if "updated_at" in row_keys and row["updated_at"] else (_iso_to_dt(row["started_at"]) or datetime.now(timezone.utc)),
            failure_reason=row["failure_reason"] if "failure_reason" in row_keys and row["failure_reason"] else "",
        )

    def save_event(self, event: AssessmentEvent) -> int:
        """Persists a sanitized real-time AssessmentEvent to SQLite and sets event.id."""
        with self.db.get_connection() as conn:
            cursor = conn.execute(
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
            if cursor.lastrowid is not None:
                event.id = cursor.lastrowid
                return cursor.lastrowid
        return 0

    def list_events(self, scan_id: str, after_id: Optional[int] = None) -> List[AssessmentEvent]:
        """Lists all persisted events for a given assessment in chronological order.

        Args:
            scan_id: Assessment scan ID.
            after_id: Optional event ID cursor for incremental replay and SSE reconnection.
        """
        query = "SELECT * FROM assessment_events WHERE scan_id = ?"
        params: List[Any] = [scan_id]
        if after_id is not None:
            query += " AND id > ?"
            params.append(after_id)
        query += " ORDER BY id ASC"

        with self.db.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

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
                    id=r["id"] if "id" in r.keys() else None,
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

    def save_finding(self, finding: Union[FindingRecord, Dict[str, Any]], overwrite: bool = True) -> str:
        """Persists a finding and its evidence artifact using parameterized SQL.

        Args:
            finding: FindingRecord model instance or dictionary.
            overwrite: If False, raises DuplicateRecordError if ID already exists.

        Returns:
            The stored finding unique ID.
        """
        if not isinstance(finding, FindingRecord):
            try:
                finding = FindingRecord(**finding)
            except Exception as e:
                raise InvalidDataError(f"Invalid finding data: {e}") from e

        logger.info("Saving finding to database", extra={"finding_id": finding.id, "title": finding.title})

        evidence_str = (
            json.dumps(finding.evidence.model_dump(mode="json"))
            if finding.evidence is not None
            else None
        )

        with self.db.session_scope() as conn:
            cursor = conn.execute("SELECT id FROM findings WHERE id = ?", (finding.id,))
            exists = cursor.fetchone() is not None

            if exists and not overwrite:
                raise DuplicateRecordError(f"Finding with ID '{finding.id}' already exists.")

            sql_action = "INSERT OR REPLACE INTO" if overwrite else "INSERT INTO"

            conn.execute(
                f"""
                {sql_action} findings (
                    id, target_identifier, scan_id, title, endpoint, target_endpoint,
                    http_method, vulnerability_category, vulnerability_type, affected_role,
                    affected_roles_json, expected_behavior, actual_behavior, evidence_reference,
                    confirmation_status, status, validation_status, access_verdict, resource_id,
                    severity, impact_explanation, description, remediation_recommendation,
                    remediation_guidance, created_timestamp, created_at, last_retested_timestamp,
                    retest_status, evidence_json, technical_details_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.target_identifier,
                    finding.scan_id,
                    finding.title,
                    finding.endpoint,
                    finding.target_endpoint,
                    finding.http_method,
                    finding.vulnerability_category,
                    finding.vulnerability_type,
                    finding.affected_role,
                    json.dumps(finding.affected_roles),
                    finding.expected_behavior,
                    finding.actual_behavior,
                    finding.evidence_reference,
                    finding.confirmation_status,
                    finding.status,
                    finding.validation_status,
                    finding.access_verdict,
                    finding.resource_id,
                    finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    finding.impact_explanation,
                    finding.description,
                    finding.remediation_recommendation,
                    finding.remediation_guidance,
                    _dt_to_iso(finding.created_timestamp),
                    _dt_to_iso(finding.created_at),
                    _dt_to_iso(finding.last_retested_timestamp),
                    finding.retest_status,
                    evidence_str,
                    json.dumps(finding.technical_details),
                    _dt_to_iso(finding.updated_at),
                ),
            )

            # Insert or replace evidence artifact if present
            if finding.evidence:
                evi = finding.evidence
                now_iso = _dt_to_iso(evi.timestamp or datetime.now(timezone.utc))
                role_val = str(evi.testing_role.value if hasattr(evi.testing_role, "value") else (getattr(evi, "test_role", None) or evi.testing_role or "user_b"))
                auth_val = str(evi.authorized_role.value if hasattr(evi.authorized_role, "value") else (evi.authorized_role or "")) if evi.authorized_role else None
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_artifacts (
                        id, finding_id, timestamp, captured_at, testing_role, test_role, authorized_role,
                        request_metadata_json, request_method, request_url, request_headers_json,
                        response_status, relevant_response_headers_json, sanitized_response_body,
                        response_body, evidence_validation_status, evidence_sha256, redacted_fields_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evi.id or f"evi_{uuid.uuid4().hex[:8]}",
                        finding.id,
                        now_iso,
                        now_iso,
                        role_val,
                        role_val,
                        auth_val,
                        json.dumps(evi.request_metadata),
                        evi.request_method,
                        evi.request_url,
                        json.dumps(evi.request_headers),
                        evi.response_status,
                        json.dumps(evi.relevant_response_headers),
                        evi.sanitized_response_body,
                        evi.response_body,
                        evi.evidence_validation_status,
                        evi.evidence_sha256,
                        json.dumps(evi.redacted_fields),
                    ),
                )

        return finding.id

    def get_finding(self, finding_id: str) -> Optional[FindingRecord]:
        """Retrieves a finding by its unique ID, including associated evidence artifact."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if not row:
                return None

            evidence_row = conn.execute(
                "SELECT * FROM evidence_artifacts WHERE finding_id = ?",
                (finding_id,)
            ).fetchone()

        evidence = None
        if "evidence_json" in row.keys() and row["evidence_json"]:
            try:
                evidence = EvidenceArtifact.model_validate(json.loads(row["evidence_json"]))
            except Exception:
                pass
        if evidence is None and evidence_row:
            evidence = self._row_to_evidence(evidence_row)

        return self._row_to_finding(row, evidence=evidence)

    def get_all_findings(
        self,
        target_identifier: Optional[str] = None,
        scan_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        vulnerability_category: Optional[str] = None,
    ) -> List[FindingRecord]:
        """Retrieves all findings matching optional search filters."""
        query = "SELECT * FROM findings"
        conditions = []
        params: List[Any] = []

        if target_identifier:
            conditions.append("(target_identifier = ? OR scan_id = ?)")
            params.extend([target_identifier, target_identifier])
        if scan_id:
            conditions.append("(scan_id = ? OR target_identifier = ?)")
            params.extend([scan_id, scan_id])
        if status:
            conditions.append("(status = ? OR confirmation_status = ?)")
            params.extend([status, status])
        if severity:
            sev_val = severity.value if hasattr(severity, "value") else str(severity)
            conditions.append("severity = ?")
            params.append(sev_val)
        if vulnerability_category:
            conditions.append("(vulnerability_category = ? OR vulnerability_type = ?)")
            params.extend([vulnerability_category, vulnerability_category])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC"

        with self.db.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            evidence_rows = conn.execute("SELECT * FROM evidence_artifacts").fetchall()

        evidence_map = {r["finding_id"]: self._row_to_evidence(r) for r in evidence_rows}

        results = []
        for row in rows:
            evi = None
            if "evidence_json" in row.keys() and row["evidence_json"]:
                try:
                    evi = EvidenceArtifact.model_validate(json.loads(row["evidence_json"]))
                except Exception:
                    pass
            if evi is None:
                evi = evidence_map.get(row["id"])
            results.append(self._row_to_finding(row, evidence=evi))

        return results


    def save_evidence(self, evidence: EvidenceArtifact, finding_id: Optional[str] = None) -> str:
        """Saves or updates an EvidenceArtifact in SQLite with explicit timestamp."""
        f_id = finding_id or evidence.finding_id
        if not f_id:
            raise InvalidDataError("EvidenceArtifact must be associated with a valid finding_id.")

        now_iso = _dt_to_iso(evidence.timestamp or datetime.now(timezone.utc))
        role_val = str(evidence.testing_role.value if hasattr(evidence.testing_role, "value") else (getattr(evidence, "test_role", None) or evidence.testing_role or "user_b"))
        auth_val = str(evidence.authorized_role.value if hasattr(evidence.authorized_role, "value") else (evidence.authorized_role or "")) if evidence.authorized_role else None
        evi_id = evidence.id or evidence.evidence_id or f"evi_{uuid.uuid4().hex[:8]}"

        with self.db.session_scope() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence_artifacts (
                    id, finding_id, timestamp, captured_at, testing_role, test_role, authorized_role,
                    request_metadata_json, request_method, request_url, request_headers_json,
                    response_status, relevant_response_headers_json, sanitized_response_body,
                    response_body, evidence_validation_status, evidence_sha256, redacted_fields_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evi_id,
                    f_id,
                    now_iso,
                    now_iso,
                    role_val,
                    role_val,
                    auth_val,
                    json.dumps(evidence.request_metadata),
                    evidence.request_method,
                    evidence.request_url,
                    json.dumps(evidence.request_headers),
                    evidence.response_status,
                    json.dumps(evidence.relevant_response_headers),
                    evidence.sanitized_response_body,
                    evidence.response_body,
                    evidence.evidence_validation_status,
                    evidence.evidence_sha256,
                    json.dumps(evidence.redacted_fields),
                ),
            )
        return evi_id

    def get_evidence(self, identifier: str) -> Optional[EvidenceArtifact]:
        """Retrieves an EvidenceArtifact by its unique evidence ID or finding ID."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM evidence_artifacts WHERE id = ?", (identifier,)).fetchone()
            if not row:
                row = conn.execute("SELECT * FROM evidence_artifacts WHERE finding_id = ?", (identifier,)).fetchone()
            if not row:
                return None
            return self._row_to_evidence(row)

    def get_evidence_by_finding_id(self, finding_id: str) -> Optional[EvidenceArtifact]:
        """Retrieves an EvidenceArtifact associated with a given finding ID."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM evidence_artifacts WHERE finding_id = ?", (finding_id,)).fetchone()
            if not row:
                return None
            return self._row_to_evidence(row)

    def get_discovered_endpoints(self, scan_id: Optional[str] = None) -> List[DiscoveredEndpointRecord]:
        """Retrieves discovered endpoints, optionally filtered by scan_id."""
        if scan_id:
            return self.list_discovered_endpoints(scan_id)
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM discovered_endpoints ORDER BY path ASC").fetchall()
            return [self._row_to_endpoint(r) for r in rows]

    def list_findings(self, scan_id: Optional[str] = None) -> List[FindingRecord]:
        """Lists findings, optionally filtered by scan_id."""
        return self.get_all_findings(scan_id=scan_id)

    def update_finding(
        self,
        finding_id: str,
        update_data: Union[FindingRecord, Dict[str, Any]]
    ) -> FindingRecord:
        """Updates an existing finding's fields using parameterized SQL."""
        if isinstance(update_data, FindingRecord):
            data_dict = update_data.model_dump(exclude_unset=True)
        elif isinstance(update_data, dict):
            data_dict = dict(update_data)
        else:
            raise InvalidDataError("update_data must be a FindingRecord or dict.")

        current = self.get_finding(finding_id)
        if not current:
            raise RecordNotFoundError(f"Finding with ID '{finding_id}' not found.")

        # Sanitize sensitive fields if present in update
        if "description" in data_dict:
            data_dict["description"] = redact_sensitive_text(str(data_dict["description"]))
            data_dict["impact_explanation"] = data_dict["description"]
        if "impact_explanation" in data_dict:
            data_dict["impact_explanation"] = redact_sensitive_text(str(data_dict["impact_explanation"]))
            data_dict["description"] = data_dict["impact_explanation"]
        if "actual_behavior" in data_dict:
            data_dict["actual_behavior"] = redact_sensitive_text(str(data_dict["actual_behavior"]))
        if "status" in data_dict:
            data_dict["confirmation_status"] = str(data_dict["status"])
        if "confirmation_status" in data_dict:
            data_dict["status"] = str(data_dict["confirmation_status"])
        if "severity" in data_dict:
            sev = data_dict["severity"]
            data_dict["severity"] = sev.value if hasattr(sev, "value") else str(sev)

        data_dict["updated_at"] = datetime.now(timezone.utc)

        # Validate merged update with FindingRecord before applying to SQLite
        merged_dict = current.model_dump()
        merged_dict.update(data_dict)
        try:
            FindingRecord(**merged_dict)
        except Exception as e:
            raise InvalidDataError(f"Invalid update data: {e}") from e

        # Build parameterized UPDATE statement
        fields_to_update = []
        values = []
        allowed_columns = {
            "title", "endpoint", "target_endpoint", "http_method",
            "vulnerability_category", "vulnerability_type", "affected_role",
            "expected_behavior", "actual_behavior", "evidence_reference",
            "confirmation_status", "status", "validation_status", "access_verdict",
            "resource_id", "severity", "impact_explanation",
            "description", "remediation_recommendation", "remediation_guidance",
            "last_retested_timestamp", "retest_status", "updated_at"
        }

        for col, val in data_dict.items():
            if col in allowed_columns:
                fields_to_update.append(f"{col} = ?")
                if isinstance(val, datetime):
                    values.append(_dt_to_iso(val))
                else:
                    values.append(val)

        if fields_to_update:
            values.append(finding_id)
            query = f"UPDATE findings SET {', '.join(fields_to_update)} WHERE id = ?"
            with self.db.session_scope() as conn:
                conn.execute(query, tuple(values))

        # Check if evidence was included in update
        new_evidence = data_dict.get("evidence")
        if new_evidence:
            if not isinstance(new_evidence, EvidenceArtifact):
                new_evidence = EvidenceArtifact(**new_evidence)
            with self.db.session_scope() as conn:
                now_iso = _dt_to_iso(new_evidence.timestamp or datetime.now(timezone.utc))
                role_val = str(new_evidence.testing_role.value if hasattr(new_evidence.testing_role, "value") else (getattr(new_evidence, "test_role", None) or new_evidence.testing_role or "user_b"))
                auth_val = str(new_evidence.authorized_role.value if hasattr(new_evidence.authorized_role, "value") else (new_evidence.authorized_role or "")) if new_evidence.authorized_role else None
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_artifacts (
                        id, finding_id, timestamp, captured_at, testing_role, test_role, authorized_role,
                        request_metadata_json, request_method, request_url, request_headers_json,
                        response_status, relevant_response_headers_json, sanitized_response_body,
                        response_body, evidence_validation_status, evidence_sha256, redacted_fields_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_evidence.id or f"evi_{uuid.uuid4().hex[:8]}",
                        finding_id,
                        now_iso,
                        now_iso,
                        role_val,
                        role_val,
                        auth_val,
                        json.dumps(new_evidence.request_metadata),
                        new_evidence.request_method,
                        new_evidence.request_url,
                        json.dumps(new_evidence.request_headers),
                        new_evidence.response_status,
                        json.dumps(new_evidence.relevant_response_headers),
                        new_evidence.sanitized_response_body,
                        new_evidence.response_body,
                        new_evidence.evidence_validation_status,
                        new_evidence.evidence_sha256,
                        json.dumps(new_evidence.redacted_fields),
                    ),
                )

        updated_record = self.get_finding(finding_id)
        if not updated_record:
            raise RecordNotFoundError(f"Failed to fetch updated finding '{finding_id}'")
        return updated_record

    def save_retest_result(self, retest: Union[RetestLogRecord, Dict[str, Any]]) -> str:
        """Saves a retest execution result and updates the target finding's retest status."""
        if not isinstance(retest, RetestLogRecord):
            try:
                retest = RetestLogRecord(**retest)
            except Exception as e:
                raise InvalidDataError(f"Invalid retest log data: {e}") from e

        with self.db.session_scope() as conn:
            # Check parent finding existence
            cursor = conn.execute("SELECT id FROM findings WHERE id = ?", (retest.finding_id,))
            if not cursor.fetchone():
                raise RecordNotFoundError(f"Cannot save retest result: Finding '{retest.finding_id}' does not exist.")

            conn.execute(
                """
                INSERT INTO retest_logs (
                    id, finding_id, previous_status, new_status, is_vulnerable,
                    summary, notes, differential_result_json, retested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    retest.id,
                    retest.finding_id,
                    retest.previous_status,
                    retest.new_status,
                    1 if retest.is_vulnerable else 0,
                    retest.summary,
                    retest.notes,
                    json.dumps(retest.differential_result) if retest.differential_result else None,
                    _dt_to_iso(retest.retested_at),
                ),
            )

            # Keep verification history separate from the original finding classification.
            conn.execute(
                """
                UPDATE findings SET
                    last_retested_timestamp = ?,
                    retest_status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    _dt_to_iso(retest.retested_at),
                    retest.new_status,
                    _dt_to_iso(datetime.now(timezone.utc)),
                    retest.finding_id,
                )
            )

        logger.info(
            "Retest log recorded",
            extra={"retest_id": retest.id, "finding_id": retest.finding_id, "new_status": retest.new_status}
        )
        return retest.id

    def get_retest_history(self, finding_id: Optional[str] = None) -> List[RetestLogRecord]:
        """Retrieves retest history, optionally filtered by finding_id."""
        query = "SELECT * FROM retest_logs"
        params: List[Any] = []
        if finding_id:
            query += " WHERE finding_id = ?"
            params.append(finding_id)

        query += " ORDER BY retested_at DESC"

        with self.db.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        return [
            RetestLogRecord(
                id=row["id"],
                finding_id=row["finding_id"],
                retest_id=row["id"],
                previous_status=row["previous_status"],
                new_status=row["new_status"],
                is_vulnerable=bool(row["is_vulnerable"]),
                summary=row["summary"],
                notes=row["notes"] or "",
                differential_result=json.loads(row["differential_result_json"]) if row["differential_result_json"] else None,
                retested_at=_iso_to_dt(row["retested_at"]) or datetime.now(timezone.utc),
            )
            for row in rows
        ]

    def delete_finding(self, finding_id: str) -> bool:
        """Deletes a finding and all cascaded evidence and retest logs."""
        with self.db.session_scope() as conn:
            cursor = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            return cursor.rowcount > 0

    def _row_to_finding(self, row: sqlite3.Row, evidence: Optional[EvidenceArtifact] = None) -> FindingRecord:
        """Helper to convert a sqlite3.Row into a typed FindingRecord."""
        row_keys = row.keys()
        affected_roles = []
        if "affected_roles_json" in row_keys and row["affected_roles_json"]:
            try:
                affected_roles = json.loads(row["affected_roles_json"])
            except Exception:
                affected_roles = [row["affected_role"]]
        elif "affected_role" in row_keys and row["affected_role"]:
            affected_roles = [row["affected_role"]]

        tech_details = {}
        if "technical_details_json" in row_keys and row["technical_details_json"]:
            try:
                tech_details = json.loads(row["technical_details_json"])
            except Exception:
                tech_details = {}

        endpoint_val = (
            row["endpoint"]
            if "endpoint" in row_keys and row["endpoint"]
            else (row["target_endpoint"] if "target_endpoint" in row_keys and row["target_endpoint"] else "")
        )
        target_endpoint_val = (
            row["target_endpoint"]
            if "target_endpoint" in row_keys and row["target_endpoint"]
            else (row["endpoint"] if "endpoint" in row_keys and row["endpoint"] else "")
        )
        vuln_cat = (
            row["vulnerability_category"]
            if "vulnerability_category" in row_keys and row["vulnerability_category"]
            else (row["vulnerability_type"] if "vulnerability_type" in row_keys and row["vulnerability_type"] else "BOLA_IDOR")
        )
        vuln_type = (
            row["vulnerability_type"]
            if "vulnerability_type" in row_keys and row["vulnerability_type"]
            else (row["vulnerability_category"] if "vulnerability_category" in row_keys and row["vulnerability_category"] else "BOLA_IDOR")
        )
        conf_status = (
            row["confirmation_status"]
            if "confirmation_status" in row_keys and row["confirmation_status"]
            else (row["status"] if "status" in row_keys and row["status"] else "confirmed")
        )
        status_val = (
            row["status"]
            if "status" in row_keys and row["status"]
            else (row["confirmation_status"] if "confirmation_status" in row_keys and row["confirmation_status"] else "confirmed")
        )
        desc_val = (
            row["description"]
            if "description" in row_keys and row["description"]
            else (row["impact_explanation"] if "impact_explanation" in row_keys and row["impact_explanation"] else "")
        )
        impact_val = (
            row["impact_explanation"]
            if "impact_explanation" in row_keys and row["impact_explanation"]
            else (row["description"] if "description" in row_keys and row["description"] else "")
        )
        remed_guidance = (
            row["remediation_guidance"]
            if "remediation_guidance" in row_keys and row["remediation_guidance"]
            else (row["remediation_recommendation"] if "remediation_recommendation" in row_keys and row["remediation_recommendation"] else "")
        )
        remed_rec = (
            row["remediation_recommendation"]
            if "remediation_recommendation" in row_keys and row["remediation_recommendation"]
            else (row["remediation_guidance"] if "remediation_guidance" in row_keys and row["remediation_guidance"] else "")
        )
        created_dt = (
            _iso_to_dt(row["created_at"])
            if "created_at" in row_keys and row["created_at"]
            else (_iso_to_dt(row["created_timestamp"]) if "created_timestamp" in row_keys and row["created_timestamp"] else datetime.now(timezone.utc))
        ) or datetime.now(timezone.utc)

        return FindingRecord(
            id=row["id"] if "id" in row_keys else "",
            target_identifier=row["target_identifier"] if "target_identifier" in row_keys and row["target_identifier"] else (row["scan_id"] if "scan_id" in row_keys else ""),
            scan_id=row["scan_id"] if "scan_id" in row_keys else "",
            title=row["title"] if "title" in row_keys else "",
            endpoint=endpoint_val,
            target_endpoint=target_endpoint_val,
            http_method=row["http_method"] if "http_method" in row_keys else "GET",
            vulnerability_category=vuln_cat,
            vulnerability_type=vuln_type,
            affected_role=row["affected_role"] if "affected_role" in row_keys and row["affected_role"] else "user_b",
            affected_roles=affected_roles,
            expected_behavior=row["expected_behavior"] if "expected_behavior" in row_keys and row["expected_behavior"] else "",
            actual_behavior=row["actual_behavior"] if "actual_behavior" in row_keys and row["actual_behavior"] else "",
            evidence_reference=row["evidence_reference"] if "evidence_reference" in row_keys else None,
            confirmation_status=conf_status,
            status=status_val,
            validation_status=row["validation_status"] if "validation_status" in row_keys and row["validation_status"] else "CONFIRMED",
            access_verdict=row["access_verdict"] if "access_verdict" in row_keys and row["access_verdict"] else "CONFIRMED_UNAUTHORIZED_ACCESS",
            resource_id=row["resource_id"] if "resource_id" in row_keys else None,
            severity=row["severity"] if "severity" in row_keys and row["severity"] else "HIGH",
            impact_explanation=impact_val,
            description=desc_val,
            remediation_recommendation=remed_rec,
            remediation_guidance=remed_guidance,
            created_timestamp=created_dt,
            created_at=created_dt,
            last_retested_timestamp=_iso_to_dt(row["last_retested_timestamp"]) if "last_retested_timestamp" in row_keys and row["last_retested_timestamp"] else None,
            retest_status=row["retest_status"] if "retest_status" in row_keys and row["retest_status"] else "NOT_RETESTED",
            technical_details=tech_details,
            updated_at=_iso_to_dt(row["updated_at"]) if "updated_at" in row_keys and row["updated_at"] else datetime.now(timezone.utc),
            evidence=evidence,
        )

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceArtifact:
        """Helper to convert a sqlite3.Row into a typed EvidenceArtifact."""
        row_keys = row.keys()

        req_meta = {}
        if "request_metadata_json" in row_keys and row["request_metadata_json"]:
            try:
                req_meta = json.loads(row["request_metadata_json"])
            except Exception:
                req_meta = {}

        req_headers = {}
        if "request_headers_json" in row_keys and row["request_headers_json"]:
            try:
                req_headers = json.loads(row["request_headers_json"])
            except Exception:
                req_headers = {}

        resp_headers = {}
        if "relevant_response_headers_json" in row_keys and row["relevant_response_headers_json"]:
            try:
                resp_headers = json.loads(row["relevant_response_headers_json"])
            except Exception:
                resp_headers = {}

        redacted_fields = []
        if "redacted_fields_json" in row_keys and row["redacted_fields_json"]:
            try:
                redacted_fields = json.loads(row["redacted_fields_json"])
            except Exception:
                redacted_fields = []

        raw_sanitized_body = (
            row["sanitized_response_body"]
            if "sanitized_response_body" in row_keys and row["sanitized_response_body"]
            else (row["response_body"] if "response_body" in row_keys and row["response_body"] else "")
        )

        val_status = (
            row["evidence_validation_status"]
            if "evidence_validation_status" in row_keys and row["evidence_validation_status"]
            else "valid"
        )

        ts = None
        if "timestamp" in row_keys and row["timestamp"]:
            ts = _iso_to_dt(row["timestamp"])
        elif "captured_at" in row_keys and row["captured_at"]:
            ts = _iso_to_dt(row["captured_at"])
        if not ts:
            ts = datetime.now(timezone.utc)

        role = "user_b"
        if "testing_role" in row_keys and row["testing_role"]:
            role = row["testing_role"]
        elif "test_role" in row_keys and row["test_role"]:
            role = row["test_role"]

        auth_role = None
        if "authorized_role" in row_keys and row["authorized_role"]:
            auth_role = row["authorized_role"]

        return EvidenceArtifact(
            id=row["id"] if "id" in row_keys else "",
            evidence_id=row["id"] if "id" in row_keys else "",
            finding_id=row["finding_id"] if "finding_id" in row_keys else "",
            timestamp=ts,
            testing_role=role,
            test_role=role,
            authorized_role=auth_role,
            request_metadata=req_meta,
            request_method=row["request_method"] if "request_method" in row_keys else "GET",
            request_url=row["request_url"] if "request_url" in row_keys else "",
            request_headers=req_headers,
            response_status=row["response_status"] if "response_status" in row_keys else 200,
            relevant_response_headers=resp_headers,
            response_headers=resp_headers,
            sanitized_response_body=raw_sanitized_body,
            response_body=raw_sanitized_body,
            sanitized_response_evidence=raw_sanitized_body[:1500],
            evidence_validation_status=val_status,
            evidence_sha256=row["evidence_sha256"] if "evidence_sha256" in row_keys else "",
            redacted_fields=redacted_fields,
            redacted_tokens=redacted_fields,
        )
