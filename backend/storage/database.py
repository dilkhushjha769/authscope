"""Database Manager: SQLite Connection Lifecycle, Migrations, and DDL Initialization."""

import sqlite3
from pathlib import Path
from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    endpoints_discovered_count INTEGER DEFAULT 0,
    endpoints_tested_count INTEGER DEFAULT 0,
    confirmed_findings_count INTEGER DEFAULT 0,
    suspicious_results_count INTEGER DEFAULT 0,
    stages_json TEXT DEFAULT '{}',
    summary_text TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS discovered_endpoints (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    category TEXT DEFAULT 'UNKNOWN',
    parameters_json TEXT DEFAULT '[]',
    requires_auth BOOLEAN DEFAULT 1,
    discovery_status TEXT DEFAULT 'DISCOVERED',
    test_status TEXT DEFAULT 'UNTESTED',
    verdict TEXT,
    associated_finding_ids_json TEXT DEFAULT '[]',
    summary TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS assessment_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    stage TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    validation_status TEXT DEFAULT 'CONFIRMED',
    access_verdict TEXT DEFAULT 'CONFIRMED_UNAUTHORIZED_ACCESS',
    target_endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    resource_id TEXT,
    expected_behavior TEXT DEFAULT '',
    actual_behavior TEXT DEFAULT '',
    description TEXT NOT NULL,
    remediation_guidance TEXT NOT NULL,
    retest_status TEXT DEFAULT 'NOT_RETESTED',
    evidence_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE,
    test_role TEXT NOT NULL,
    authorized_role TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS retest_logs (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    is_vulnerable BOOLEAN NOT NULL,
    notes TEXT,
    retested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class DatabaseManager:
    """Initializes and provides connections to SQLite storage."""

    def __init__(self, db_path: str = settings.database_path):
        self.db_path = db_path
        self._mem_conn: sqlite3.Connection | None = None
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Creates parent directory if it does not exist."""
        if self.db_path != ":memory:":
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection."""
        if self.db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
                self._mem_conn.execute("PRAGMA foreign_keys = ON;")
            return self._mem_conn

        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        """Safely migrates older SQLite tables if columns were added in Phase 3.5."""
        migrations = [
            ("scan_sessions", "endpoints_discovered_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "endpoints_tested_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "confirmed_findings_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "suspicious_results_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "stages_json", "TEXT DEFAULT '{}'"),
            ("scan_sessions", "summary_text", "TEXT DEFAULT ''"),
            ("findings", "validation_status", "TEXT DEFAULT 'CONFIRMED'"),
            ("findings", "access_verdict", "TEXT DEFAULT 'CONFIRMED_UNAUTHORIZED_ACCESS'"),
            ("findings", "resource_id", "TEXT"),
            ("findings", "expected_behavior", "TEXT DEFAULT ''"),
            ("findings", "actual_behavior", "TEXT DEFAULT ''"),
            ("findings", "retest_status", "TEXT DEFAULT 'NOT_RETESTED'"),
            ("findings", "evidence_json", "TEXT"),
        ]
        for table, col, col_def in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                pass

    def init_schema(self) -> None:
        """Executes DDL schema initialization and column migrations."""
        logger.info("Initializing database schema", extra={"db_path": self.db_path})
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            self._ensure_columns(conn)
            conn.commit()
