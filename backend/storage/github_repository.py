"""SQLite persistence for GitHub OAuth sessions, installations, and source scans."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.storage.database import DatabaseManager


class GitHubRepository:
    """Stores per-GitHub-user records in the existing AuthScope SQLite database."""

    def __init__(self, database: Optional[DatabaseManager] = None) -> None:
        self.database = database or DatabaseManager()

    def save_oauth_state(
        self, state_hash: str, flow: str, expires_at: str, github_user_id: Optional[str] = None
    ) -> None:
        with self.database.session_scope() as conn:
            conn.execute(
                "INSERT INTO github_oauth_states(state_hash, flow, github_user_id, expires_at) VALUES (?, ?, ?, ?)",
                (state_hash, flow, github_user_id, expires_at),
            )

    def consume_oauth_state(self, state_hash: str, flow: str) -> Optional[str]:
        now = datetime.now(timezone.utc).isoformat()
        with self.database.session_scope() as conn:
            row = conn.execute(
                "SELECT github_user_id FROM github_oauth_states WHERE state_hash = ? AND flow = ? AND expires_at > ?",
                (state_hash, flow, now),
            ).fetchone()
            conn.execute("DELETE FROM github_oauth_states WHERE state_hash = ?", (state_hash,))
        if not row:
            return None
        return str(row[0]) if row[0] is not None else "oauth"

    def save_connection(
        self,
        github_user_id: str,
        login: str,
        avatar_url: str,
        encrypted_credentials: str,
        expires_at: Optional[str],
    ) -> None:
        with self.database.session_scope() as conn:
            conn.execute(
                """INSERT INTO github_connections
                   (github_user_id, login, avatar_url, encrypted_credentials, expires_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(github_user_id) DO UPDATE SET login=excluded.login,
                     avatar_url=excluded.avatar_url, encrypted_credentials=excluded.encrypted_credentials,
                     expires_at=excluded.expires_at, updated_at=excluded.updated_at""",
                (github_user_id, login, avatar_url, encrypted_credentials, expires_at, datetime.now(timezone.utc).isoformat()),
            )

    def get_connection(self, github_user_id: str) -> Optional[Dict[str, Any]]:
        with self.database.session_scope() as conn:
            row = conn.execute(
                "SELECT * FROM github_connections WHERE github_user_id = ?", (github_user_id,)
            ).fetchone()
        return dict(row) if row else None

    def create_session(self, session_hash: str, github_user_id: str, expires_at: str) -> None:
        with self.database.session_scope() as conn:
            conn.execute(
                "INSERT INTO github_sessions(session_hash, github_user_id, expires_at) VALUES (?, ?, ?)",
                (session_hash, github_user_id, expires_at),
            )

    def get_session_user(self, session_hash: str) -> Optional[str]:
        now = datetime.now(timezone.utc).isoformat()
        with self.database.session_scope() as conn:
            row = conn.execute(
                "SELECT github_user_id FROM github_sessions WHERE session_hash = ? AND expires_at > ?",
                (session_hash, now),
            ).fetchone()
        return str(row[0]) if row else None

    def delete_session(self, session_hash: str) -> None:
        with self.database.session_scope() as conn:
            conn.execute("DELETE FROM github_sessions WHERE session_hash = ?", (session_hash,))

    def delete_connection(self, github_user_id: str) -> None:
        with self.database.session_scope() as conn:
            conn.execute("DELETE FROM github_connections WHERE github_user_id = ?", (github_user_id,))

    def save_installation(
        self, github_user_id: str, installation_id: int, account_login: str, account_type: str
    ) -> None:
        with self.database.session_scope() as conn:
            conn.execute(
                """INSERT INTO github_installations(github_user_id, installation_id, account_login, account_type)
                   VALUES (?, ?, ?, ?) ON CONFLICT(github_user_id, installation_id) DO UPDATE SET
                   account_login=excluded.account_login, account_type=excluded.account_type""",
                (github_user_id, installation_id, account_login, account_type),
            )

    def list_installations(self, github_user_id: str) -> List[Dict[str, Any]]:
        with self.database.session_scope() as conn:
            rows = conn.execute(
                "SELECT installation_id, account_login, account_type FROM github_installations WHERE github_user_id = ? ORDER BY account_login",
                (github_user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_installations(self, github_user_id: str) -> None:
        with self.database.session_scope() as conn:
            conn.execute("DELETE FROM github_installations WHERE github_user_id = ?", (github_user_id,))

    def create_scan(self, record: Dict[str, Any]) -> None:
        with self.database.session_scope() as conn:
            conn.execute(
                """INSERT INTO github_scans
                   (id, github_user_id, installation_id, repository_id, owner, repository, branch, commit_sha,
                    status, created_at, completed_at, error_code, languages_json, findings_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"], record["github_user_id"], record["installation_id"], record["repository_id"],
                    record["owner"], record["repository"], record["branch"], record["commit_sha"], record["status"],
                    record["created_at"], record.get("completed_at"), record.get("error_code", ""),
                    json.dumps(record.get("languages", {})), json.dumps(record.get("findings", [])),
                ),
            )

    @staticmethod
    def _scan_dict(row: sqlite3.Row) -> Dict[str, Any]:
        scan = dict(row)
        scan["languages"] = json.loads(scan.pop("languages_json") or "{}")
        scan["findings"] = json.loads(scan.pop("findings_json") or "[]")
        return scan

    def get_scan(self, scan_id: str, github_user_id: str) -> Optional[Dict[str, Any]]:
        with self.database.session_scope() as conn:
            row = conn.execute(
                "SELECT * FROM github_scans WHERE id = ? AND github_user_id = ?", (scan_id, github_user_id)
            ).fetchone()
        return self._scan_dict(row) if row else None

    def list_scans(self, github_user_id: str) -> List[Dict[str, Any]]:
        with self.database.session_scope() as conn:
            rows = conn.execute(
                "SELECT * FROM github_scans WHERE github_user_id = ? ORDER BY created_at DESC", (github_user_id,)
            ).fetchall()
        return [self._scan_dict(row) for row in rows]

    def has_running_scan(self, github_user_id: str) -> bool:
        with self.database.session_scope() as conn:
            row = conn.execute(
                "SELECT 1 FROM github_scans WHERE github_user_id = ? AND status = 'RUNNING' LIMIT 1",
                (github_user_id,),
            ).fetchone()
        return row is not None

    def recover_orphaned_running_scans(self, active_scan_ids: Optional[set[str]] = None) -> int:
        """Marks orphaned RUNNING GitHub source scans as FAILED on server startup or before new scans."""
        active = active_scan_ids or set()
        now = datetime.now(timezone.utc).isoformat()
        with self.database.session_scope() as conn:
            rows = conn.execute(
                "SELECT id FROM github_scans WHERE status = 'RUNNING'"
            ).fetchall()
            orphaned_ids = [str(r[0]) for r in rows if str(r[0]) not in active]
            for sid in orphaned_ids:
                conn.execute(
                    "UPDATE github_scans SET status = 'FAILED', error_code = 'SCAN_INTERRUPTED', completed_at = ? WHERE id = ?",
                    (now, sid),
                )
        return len(orphaned_ids)

    def update_scan(
        self,
        scan_id: str,
        github_user_id: str,
        status: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        languages: Optional[Dict[str, int]] = None,
        error_code: str = "",
        completed_at: Optional[str] = None,
    ) -> bool:
        updates = ["status = ?", "error_code = ?", "completed_at = ?"]
        values: List[Any] = [status, error_code, completed_at]
        if findings is not None:
            updates.append("findings_json = ?")
            values.append(json.dumps(findings))
        if languages is not None:
            updates.append("languages_json = ?")
            values.append(json.dumps(languages))
        values.extend([scan_id, github_user_id])
        with self.database.session_scope() as conn:
            cursor = conn.execute(
                f"UPDATE github_scans SET {', '.join(updates)} WHERE id = ? AND github_user_id = ?", tuple(values)
            )
        return cursor.rowcount == 1

    def save_scan_event(self, scan_id: str, event_type: str, stage: str, message: str, metadata: Dict[str, Any]) -> int:
        with self.database.session_scope() as conn:
            cursor = conn.execute(
                "INSERT INTO github_scan_events(scan_id, event_type, stage, message, timestamp, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, event_type, stage, message, datetime.now(timezone.utc).isoformat(), json.dumps(metadata)),
            )
        return int(cursor.lastrowid or 0)

    def list_scan_events(self, scan_id: str, after_id: int = 0) -> List[Dict[str, Any]]:
        with self.database.session_scope() as conn:
            rows = conn.execute(
                "SELECT * FROM github_scan_events WHERE scan_id = ? AND id > ? ORDER BY id", (scan_id, after_id)
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            record["metadata"] = json.loads(record.pop("metadata_json") or "{}")
            result.append(record)
        return result
