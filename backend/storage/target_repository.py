"""Target Repository: Persistence for Dynamic Authorized Target Profiles.

Manages server-side target authorization records in SQLite.
Enforces type safety, parameterized queries, and safe schema migrations.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from backend.storage.database import DatabaseManager
from backend.storage.models import (
    AuthorizationBasis,
    TargetApprovalStatus,
    TargetProfileRecord,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def _dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, str):
        return dt
    return dt.isoformat()


def _iso_to_dt(iso_str: Optional[str]) -> Optional[datetime]:
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(iso_str)
    except Exception:
        return None


class TargetRepository:
    """CRUD repository for server-side Authorized Target Profiles."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db = db_manager or DatabaseManager()
        self.db.init_schema()
        self.seed_default_targets()

    def seed_default_targets(self) -> None:
        """Seeds built-in authorized localhost target profiles if missing."""
        dev_ports = [3000, 80, 443, 8000, 8080, 8888, 5000, 5173, 4200, 8443]
        default_profiles = [
            TargetProfileRecord(
                id="target_localhost_3000",
                hostname="localhost",
                base_url="http://localhost:3000",
                allowed_schemes=["http"],
                allowed_ports=dev_ports,
                allowed_paths=[],
                allowed_methods=["GET", "HEAD"],
                authorization_basis=AuthorizationBasis.LOCAL_DEVELOPMENT.value,
                permission_reference="Default Local OWASP Juice Shop Target",
                approval_status=TargetApprovalStatus.APPROVED.value,
                approved_by="system",
                approved_at=datetime.now(timezone.utc),
                is_local_test=True,
                notes="Built-in authorized local development target.",
            ),
            TargetProfileRecord(
                id="target_127_0_0_1_3000",
                hostname="127.0.0.1",
                base_url="http://127.0.0.1:3000",
                allowed_schemes=["http"],
                allowed_ports=dev_ports,
                allowed_paths=[],
                allowed_methods=["GET", "HEAD"],
                authorization_basis=AuthorizationBasis.LOCAL_DEVELOPMENT.value,
                permission_reference="Default Local OWASP Juice Shop Loopback",
                approval_status=TargetApprovalStatus.APPROVED.value,
                approved_by="system",
                approved_at=datetime.now(timezone.utc),
                is_local_test=True,
                notes="Built-in authorized local loopback target.",
            ),
        ]
        for prof in default_profiles:
            existing = self.get_target_profile(prof.id)
            if existing is None:
                self.save_target_profile(prof)

    def save_target_profile(self, profile: TargetProfileRecord) -> str:
        """Inserts or updates a target profile in SQLite."""
        with self.db.session_scope() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO target_profiles (
                    id, hostname, base_url, allowed_schemes_json, allowed_ports_json,
                    allowed_paths_json, allowed_methods_json, authorization_basis,
                    permission_reference, approval_status, approved_by, approved_at,
                    created_at, expires_at, revoked_at, revocation_reason,
                    verification_token, verified_at, is_local_test, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.id,
                    profile.hostname.lower().strip(),
                    profile.base_url.strip(),
                    json.dumps([s.lower() for s in profile.allowed_schemes]),
                    json.dumps(profile.allowed_ports),
                    json.dumps(profile.allowed_paths),
                    json.dumps([m.upper() for m in profile.allowed_methods]),
                    profile.authorization_basis,
                    profile.permission_reference or "",
                    profile.approval_status,
                    profile.approved_by or "",
                    _dt_to_iso(profile.approved_at),
                    _dt_to_iso(profile.created_at),
                    _dt_to_iso(profile.expires_at),
                    _dt_to_iso(profile.revoked_at),
                    profile.revocation_reason or "",
                    profile.verification_token or "",
                    _dt_to_iso(profile.verified_at),
                    1 if profile.is_local_test else 0,
                    profile.notes or "",
                ),
            )
        return profile.id

    def get_target_profile(self, profile_id: str) -> Optional[TargetProfileRecord]:
        """Retrieves a single target profile by ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM target_profiles WHERE id = ?", (profile_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def get_profile_by_hostname(self, hostname: str) -> Optional[TargetProfileRecord]:
        """Retrieves the most recent target profile matching an exact hostname."""
        norm_host = hostname.lower().strip()
        with self.db.get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM target_profiles
                WHERE hostname = ?
                ORDER BY
                    CASE approval_status
                        WHEN 'APPROVED' THEN 1
                        WHEN 'PENDING' THEN 2
                        ELSE 3
                    END ASC,
                    created_at DESC
                LIMIT 1
                """,
                (norm_host,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def list_target_profiles(
        self,
        status_filter: Optional[str] = None,
        limit: int = 50,
    ) -> List[TargetProfileRecord]:
        """Lists target profiles ordered by newest first with optional status filtering."""
        query = "SELECT * FROM target_profiles"
        params: List[Any] = []
        if status_filter:
            query += " WHERE approval_status = ?"
            params.append(status_filter.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.db.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()

        return [self._row_to_record(r) for r in rows]

    def delete_target_profile(self, profile_id: str) -> bool:
        """Deletes a target profile by ID."""
        with self.db.session_scope() as conn:
            cursor = conn.execute(
                "DELETE FROM target_profiles WHERE id = ?", (profile_id,)
            )
            return cursor.rowcount > 0

    @staticmethod
    def _row_to_record(row: Any) -> TargetProfileRecord:
        schemes = []
        ports = []
        paths = []
        methods = []

        try:
            schemes = json.loads(row["allowed_schemes_json"] or '["https"]')
        except Exception:
            schemes = ["https"]
        try:
            ports = json.loads(row["allowed_ports_json"] or "[443]")
        except Exception:
            ports = [443]
        try:
            paths = json.loads(row["allowed_paths_json"] or "[]")
        except Exception:
            paths = []
        try:
            methods = json.loads(row["allowed_methods_json"] or '["GET", "HEAD"]')
        except Exception:
            methods = ["GET", "HEAD"]

        return TargetProfileRecord(
            id=row["id"],
            hostname=row["hostname"],
            base_url=row["base_url"],
            allowed_schemes=schemes,
            allowed_ports=ports,
            allowed_paths=paths,
            allowed_methods=methods,
            authorization_basis=row["authorization_basis"],
            permission_reference=row["permission_reference"] or "",
            approval_status=row["approval_status"],
            approved_by=row["approved_by"] or None,
            approved_at=_iso_to_dt(row["approved_at"]),
            created_at=_iso_to_dt(row["created_at"]) or datetime.now(timezone.utc),
            expires_at=_iso_to_dt(row["expires_at"]),
            revoked_at=_iso_to_dt(row["revoked_at"]),
            revocation_reason=row["revocation_reason"] or "",
            verification_token=row["verification_token"] or "",
            verified_at=_iso_to_dt(row["verified_at"]),
            is_local_test=bool(row["is_local_test"]),
            notes=row["notes"] or "",
        )
