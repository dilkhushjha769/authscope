"""Database Manager: SQLite Connection Lifecycle and DDL Initialization."""

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
    completed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    target_endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation_guidance TEXT NOT NULL,
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
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Creates parent directory if it does not exist."""
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_schema(self) -> None:
        """Executes DDL schema initialization."""
        logger.info("Initializing database schema", extra={"db_path": self.db_path})
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

