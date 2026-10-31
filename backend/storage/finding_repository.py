"""Finding Repository: CRUD operations for scans, findings, and evidence artifacts."""

from typing import List, Optional
from backend.storage.database import DatabaseManager
from backend.storage.models import FindingRecord, ScanSessionRecord
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class FindingRepository:
    """Manages persistence of security scans and confirmed findings."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()
        self.db.init_schema()

    def save_finding(self, finding: FindingRecord) -> str:
        """Persists a confirmed finding record.

        TODO (Phase 6): Implement parameterized INSERT including evidence artifact.
        """
        logger.info("Saving finding to database", extra={"finding_id": finding.id, "title": finding.title})
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, scan_id, title, vulnerability_type, severity, status,
                    target_endpoint, http_method, description, remediation_guidance
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.scan_id,
                    finding.title,
                    finding.vulnerability_type,
                    finding.severity.value,
                    finding.status,
                    finding.target_endpoint,
                    finding.http_method,
                    finding.description,
                    finding.remediation_guidance,
                )
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
            rows = conn.execute(query, params).fetchall()

        return [
            FindingRecord(
                id=row["id"],
                scan_id=row["scan_id"],
                title=row["title"],
                vulnerability_type=row["vulnerability_type"],
                severity=row["severity"],
                status=row["status"],
                target_endpoint=row["target_endpoint"],
                http_method=row["http_method"],
                description=row["description"],
                remediation_guidance=row["remediation_guidance"],
                created_at=row["created_at"]
            )
            for row in rows
        ]

