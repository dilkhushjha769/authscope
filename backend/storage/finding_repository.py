"""Finding Repository: CRUD operations for scans, findings, and evidence artifacts.

Implements safe parameterized SQL queries, complete type enforcement, and
atomic transaction lifecycle. Redacts sensitive credentials before disk write.
"""

from typing import List, Optional, Dict, Any, Union
import json
from datetime import datetime, timezone
import sqlite3

from backend.storage.database import DatabaseManager, initialize_database
from backend.storage.models import FindingRecord, EvidenceArtifact, RetestLogRecord, ScanSessionRecord
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
    """Manages persistence of security scans, confirmed findings, and retests."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.db.init_schema()

    def initialize_database(self) -> None:
        """Explicitly re-initializes DDL schema if needed."""
        self.db.init_schema()

    def save_finding(self, finding: Union[FindingRecord, Dict[str, Any]], overwrite: bool = False) -> str:
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

        with self.db.session_scope() as conn:
            # Check for duplicate ID
            cursor = conn.execute("SELECT id FROM findings WHERE id = ?", (finding.id,))
            exists = cursor.fetchone() is not None

            if exists and not overwrite:
                raise DuplicateRecordError(f"Finding with ID '{finding.id}' already exists.")

            sql_action = "INSERT OR REPLACE INTO" if overwrite else "INSERT INTO"
            
            # 1. Insert Finding Record
            conn.execute(
                f"""
                {sql_action} findings (
                    id, target_identifier, scan_id, title, endpoint, target_endpoint,
                    http_method, vulnerability_category, vulnerability_type, affected_role,
                    affected_roles_json, expected_behavior, actual_behavior, evidence_reference,
                    confirmation_status, status, severity, impact_explanation, description,
                    remediation_recommendation, remediation_guidance, created_timestamp,
                    created_at, last_retested_timestamp, retest_status, technical_details_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    finding.impact_explanation,
                    finding.description,
                    finding.remediation_recommendation,
                    finding.remediation_guidance,
                    _dt_to_iso(finding.created_timestamp),
                    _dt_to_iso(finding.created_at),
                    _dt_to_iso(finding.last_retested_timestamp),
                    finding.retest_status,
                    json.dumps(finding.technical_details),
                    _dt_to_iso(finding.updated_at),
                )
            )

            # 2. Insert Evidence Artifact if present
            if finding.evidence:
                evidence = finding.evidence
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_artifacts (
                        id, finding_id, timestamp, testing_role, authorized_role,
                        request_metadata_json, request_method, request_url, request_headers_json,
                        response_status, relevant_response_headers_json, sanitized_response_body,
                        response_body, evidence_validation_status, evidence_sha256, redacted_fields_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence.id,
                        finding.id,
                        _dt_to_iso(evidence.timestamp),
                        str(evidence.testing_role.value if hasattr(evidence.testing_role, "value") else evidence.testing_role),
                        str(evidence.authorized_role.value if hasattr(evidence.authorized_role, "value") else evidence.authorized_role),
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
                    )
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
        if evidence_row:
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

        query += " ORDER BY created_timestamp DESC"

        with self.db.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            evidence_rows = conn.execute("SELECT * FROM evidence_artifacts").fetchall()

        evidence_map = {r["finding_id"]: self._row_to_evidence(r) for r in evidence_rows}

        return [
            self._row_to_finding(row, evidence=evidence_map.get(row["id"]))
            for row in rows
        ]

    def list_findings(self, scan_id: Optional[str] = None) -> List[FindingRecord]:
        """Alias for get_all_findings to maintain backwards compatibility with dashboard."""
        return self.get_all_findings(scan_id=scan_id)

    def update_finding(
        self,
        finding_id: str,
        update_data: Union[FindingRecord, Dict[str, Any]]
    ) -> FindingRecord:
        """Updates an existing finding's fields using parameterized SQL.

        Raises RecordNotFoundError if finding_id does not exist.
        """
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
            "confirmation_status", "status", "severity", "impact_explanation",
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
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evidence_artifacts (
                        id, finding_id, timestamp, testing_role, authorized_role,
                        request_metadata_json, request_method, request_url, request_headers_json,
                        response_status, relevant_response_headers_json, sanitized_response_body,
                        response_body, evidence_validation_status, evidence_sha256, redacted_fields_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_evidence.id,
                        finding_id,
                        _dt_to_iso(new_evidence.timestamp),
                        str(new_evidence.testing_role.value if hasattr(new_evidence.testing_role, "value") else new_evidence.testing_role),
                        str(new_evidence.authorized_role.value if hasattr(new_evidence.authorized_role, "value") else new_evidence.authorized_role),
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
                    )
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
                )
            )

            # Update finding's last_retested_timestamp and retest status
            conn.execute(
                """
                UPDATE findings SET
                    last_retested_timestamp = ?,
                    retest_status = ?,
                    status = ?,
                    confirmation_status = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    _dt_to_iso(retest.retested_at),
                    "vulnerable" if retest.is_vulnerable else "remediated",
                    retest.new_status,
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
        affected_roles = []
        if row["affected_roles_json"]:
            try:
                affected_roles = json.loads(row["affected_roles_json"])
            except Exception:
                affected_roles = [row["affected_role"]]

        tech_details = {}
        if row["technical_details_json"]:
            try:
                tech_details = json.loads(row["technical_details_json"])
            except Exception:
                tech_details = {}

        return FindingRecord(
            id=row["id"],
            target_identifier=row["target_identifier"],
            scan_id=row["scan_id"],
            title=row["title"],
            endpoint=row["endpoint"],
            target_endpoint=row["target_endpoint"],
            http_method=row["http_method"],
            vulnerability_category=row["vulnerability_category"],
            vulnerability_type=row["vulnerability_type"],
            affected_role=row["affected_role"],
            affected_roles=affected_roles,
            expected_behavior=row["expected_behavior"],
            actual_behavior=row["actual_behavior"],
            evidence_reference=row["evidence_reference"],
            confirmation_status=row["confirmation_status"],
            status=row["status"],
            severity=row["severity"],
            impact_explanation=row["impact_explanation"],
            description=row["description"],
            remediation_recommendation=row["remediation_recommendation"],
            remediation_guidance=row["remediation_guidance"],
            created_timestamp=_iso_to_dt(row["created_timestamp"]) or datetime.now(timezone.utc),
            created_at=_iso_to_dt(row["created_at"]) or datetime.now(timezone.utc),
            last_retested_timestamp=_iso_to_dt(row["last_retested_timestamp"]),
            retest_status=row["retest_status"],
            technical_details=tech_details,
            updated_at=_iso_to_dt(row["updated_at"]) or datetime.now(timezone.utc),
            evidence=evidence,
        )

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceArtifact:
        """Helper to convert a sqlite3.Row into a typed EvidenceArtifact."""
        req_meta = {}
        if row["request_metadata_json"]:
            try:
                req_meta = json.loads(row["request_metadata_json"])
            except Exception:
                req_meta = {}

        req_headers = {}
        if row["request_headers_json"]:
            try:
                req_headers = json.loads(row["request_headers_json"])
            except Exception:
                req_headers = {}

        resp_headers = {}
        if row["relevant_response_headers_json"]:
            try:
                resp_headers = json.loads(row["relevant_response_headers_json"])
            except Exception:
                resp_headers = {}

        redacted_fields = []
        if row["redacted_fields_json"]:
            try:
                redacted_fields = json.loads(row["redacted_fields_json"])
            except Exception:
                redacted_fields = []

        return EvidenceArtifact(
            id=row["id"],
            evidence_id=row["id"],
            finding_id=row["finding_id"],
            timestamp=_iso_to_dt(row["timestamp"]) or datetime.now(timezone.utc),
            testing_role=row["testing_role"],
            test_role=row["testing_role"],
            authorized_role=row["authorized_role"],
            request_metadata=req_meta,
            request_method=row["request_method"],
            request_url=row["request_url"],
            request_headers=req_headers,
            response_status=row["response_status"],
            relevant_response_headers=resp_headers,
            response_headers=resp_headers,
            sanitized_response_body=row["sanitized_response_body"],
            response_body=row["response_body"],
            evidence_validation_status=row["evidence_validation_status"],
            evidence_sha256=row["evidence_sha256"],
            redacted_fields=redacted_fields,
            redacted_tokens=redacted_fields,
        )
