"""Database Manager: SQLite Connection Lifecycle and DDL Initialization."""

import sqlite3
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_identifier TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    target_endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    vulnerability_category TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    affected_role TEXT NOT NULL,
    affected_roles_json TEXT,
    expected_behavior TEXT NOT NULL,
    actual_behavior TEXT NOT NULL,
    evidence_reference TEXT,
    confirmation_status TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    impact_explanation TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation_recommendation TEXT NOT NULL,
    remediation_guidance TEXT NOT NULL,
    created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_retested_timestamp TIMESTAMP,
    retest_status TEXT,
    technical_details_json TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    testing_role TEXT NOT NULL,
    authorized_role TEXT,
    request_metadata_json TEXT,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_headers_json TEXT,
    response_status INTEGER NOT NULL,
    relevant_response_headers_json TEXT,
    sanitized_response_body TEXT NOT NULL,
    response_body TEXT NOT NULL,
    evidence_validation_status TEXT DEFAULT 'valid',
    evidence_sha256 TEXT NOT NULL,
    redacted_fields_json TEXT
);

CREATE TABLE IF NOT EXISTS retest_logs (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    is_vulnerable BOOLEAN NOT NULL,
    summary TEXT,
    notes TEXT,
    differential_result_json TEXT,
    retested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_identifier);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_artifacts(finding_id);
CREATE INDEX IF NOT EXISTS idx_retest_finding_id ON retest_logs(finding_id);
"""


class DatabaseManager:
    """Initializes and provides connections to SQLite storage."""

    def __init__(self, db_path: str = settings.database_path):
        self.db_path = db_path
        self._memory_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:")
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Creates parent directory if it does not exist."""
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection with foreign keys enabled."""
        if self.db_path == ":memory:":
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def session_scope(self):
        """Context manager providing an atomic transaction with safe cleanup."""
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def init_schema(self) -> None:
        """Executes DDL schema initialization."""
        logger.info("Initializing database schema", extra={"db_path": self.db_path})
        if self.db_path == ":memory:":
            self._memory_conn.executescript(SCHEMA_SQL)
            self._memory_conn.commit()
        else:
            with self.session_scope() as conn:
                conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        """Closes any active held connections."""
        if self._memory_conn:
            try:
                self._memory_conn.close()
            except Exception:
                pass
            self._memory_conn = None


def initialize_database(db_path: Optional[str] = None) -> DatabaseManager:
    """Helper to initialize and return a configured DatabaseManager instance."""
    path = db_path or settings.database_path
    db_manager = DatabaseManager(db_path=path)
    db_manager.init_schema()
    return db_manager
