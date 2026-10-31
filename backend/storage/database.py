"""Database Manager: SQLite Connection Lifecycle, Migrations, and DDL Initialization."""

import sqlite3
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


TABLES_SQL = """
PRAGMA foreign_keys = ON;

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
    summary_text TEXT DEFAULT '',
    config_json TEXT DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failure_reason TEXT DEFAULT ''
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
    target_identifier TEXT DEFAULT '',
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    endpoint TEXT DEFAULT '',
    target_endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    vulnerability_category TEXT DEFAULT 'BOLA_IDOR',
    vulnerability_type TEXT NOT NULL,
    affected_role TEXT DEFAULT 'user_b',
    affected_roles_json TEXT DEFAULT '[]',
    expected_behavior TEXT NOT NULL,
    actual_behavior TEXT NOT NULL,
    evidence_reference TEXT,
    confirmation_status TEXT DEFAULT 'confirmed',
    status TEXT NOT NULL,
    validation_status TEXT DEFAULT 'CONFIRMED',
    access_verdict TEXT DEFAULT 'CONFIRMED_UNAUTHORIZED_ACCESS',
    resource_id TEXT,
    severity TEXT NOT NULL,
    impact_explanation TEXT DEFAULT '',
    description TEXT NOT NULL,
    remediation_recommendation TEXT DEFAULT '',
    remediation_guidance TEXT NOT NULL,
    created_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_retested_timestamp TIMESTAMP,
    retest_status TEXT DEFAULT 'untested',
    evidence_json TEXT,
    technical_details_json TEXT DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    testing_role TEXT NOT NULL DEFAULT 'user_b',
    test_role TEXT DEFAULT 'user_b',
    authorized_role TEXT,
    request_metadata_json TEXT DEFAULT '{}',
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_headers_json TEXT DEFAULT '{}',
    response_status INTEGER NOT NULL,
    relevant_response_headers_json TEXT DEFAULT '{}',
    sanitized_response_body TEXT NOT NULL,
    response_body TEXT NOT NULL,
    evidence_validation_status TEXT DEFAULT 'valid',
    evidence_sha256 TEXT NOT NULL,
    redacted_fields_json TEXT DEFAULT '[]'
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

CREATE TABLE IF NOT EXISTS target_profiles (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    base_url TEXT NOT NULL,
    allowed_schemes_json TEXT DEFAULT '["https"]',
    allowed_ports_json TEXT DEFAULT '[443]',
    allowed_paths_json TEXT DEFAULT '[]',
    allowed_methods_json TEXT DEFAULT '["GET", "HEAD"]',
    authorization_basis TEXT NOT NULL,
    permission_reference TEXT DEFAULT '',
    approval_status TEXT NOT NULL DEFAULT 'PENDING',
    approved_by TEXT DEFAULT '',
    approved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason TEXT DEFAULT '',
    verification_token TEXT DEFAULT '',
    verified_at TIMESTAMP,
    is_local_test BOOLEAN DEFAULT 0,
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS github_connections (
    github_user_id TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    avatar_url TEXT DEFAULT '',
    encrypted_credentials TEXT NOT NULL,
    expires_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS github_sessions (
    session_hash TEXT PRIMARY KEY,
    github_user_id TEXT NOT NULL REFERENCES github_connections(github_user_id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_oauth_states (
    state_hash TEXT PRIMARY KEY,
    flow TEXT NOT NULL CHECK(flow IN ('oauth', 'install')),
    github_user_id TEXT,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_installations (
    github_user_id TEXT NOT NULL REFERENCES github_connections(github_user_id) ON DELETE CASCADE,
    installation_id INTEGER NOT NULL,
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL DEFAULT 'User',
    PRIMARY KEY (github_user_id, installation_id)
);

CREATE TABLE IF NOT EXISTS github_scans (
    id TEXT PRIMARY KEY,
    github_user_id TEXT NOT NULL REFERENCES github_connections(github_user_id) ON DELETE CASCADE,
    installation_id INTEGER NOT NULL,
    repository_id INTEGER NOT NULL,
    owner TEXT NOT NULL,
    repository TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error_code TEXT DEFAULT '',
    languages_json TEXT NOT NULL DEFAULT '{}',
    findings_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS github_scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES github_scans(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    stage TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
"""

INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_identifier);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_artifacts(finding_id);
CREATE INDEX IF NOT EXISTS idx_retest_finding_id ON retest_logs(finding_id);
CREATE INDEX IF NOT EXISTS idx_target_profiles_hostname ON target_profiles(hostname);
CREATE INDEX IF NOT EXISTS idx_target_profiles_status ON target_profiles(approval_status);
CREATE INDEX IF NOT EXISTS idx_github_sessions_user ON github_sessions(github_user_id);
CREATE INDEX IF NOT EXISTS idx_github_scans_user ON github_scans(github_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_github_scan_events_scan ON github_scan_events(scan_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_one_active_scan_per_user ON github_scans(github_user_id) WHERE status = 'RUNNING';
"""

SCHEMA_SQL = TABLES_SQL + "\n" + INDEXES_SQL


class DatabaseManager:
    """Initializes and provides connections to SQLite storage."""

    def __init__(self, db_path: str = settings.database_path):
        self.db_path = db_path
        self._memory_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            self._ensure_directory()

    def _ensure_directory(self) -> None:
        """Creates parent directory if it does not exist."""
        if self.db_path != ":memory:":
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection with foreign keys enabled."""
        if self.db_path == ":memory:":
            return self._memory_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
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

    def _ensure_columns(self, conn: sqlite3.Connection) -> None:
        """Safely and idempotently migrates older SQLite tables if columns were added.

        Uses PRAGMA table_info to inspect existing columns. For SQLite compatibility,
        ALTER TABLE ADD COLUMN is executed without non-constant expressions such as
        CURRENT_TIMESTAMP, followed by safe row backfills.
        """
        migrations = [
            ("scan_sessions", "endpoints_discovered_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "endpoints_tested_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "confirmed_findings_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "suspicious_results_count", "INTEGER DEFAULT 0"),
            ("scan_sessions", "stages_json", "TEXT DEFAULT '{}'"),
            ("scan_sessions", "summary_text", "TEXT DEFAULT ''"),
            ("scan_sessions", "config_json", "TEXT DEFAULT '{}'"),
            ("scan_sessions", "updated_at", "TIMESTAMP"),
            ("scan_sessions", "failure_reason", "TEXT DEFAULT ''"),
            ("findings", "target_identifier", "TEXT DEFAULT ''"),
            ("findings", "validation_status", "TEXT DEFAULT 'CONFIRMED'"),
            ("findings", "classification", "TEXT DEFAULT ''"),
            ("findings", "access_verdict", "TEXT DEFAULT 'CONFIRMED_UNAUTHORIZED_ACCESS'"),
            ("findings", "resource_id", "TEXT"),
            ("findings", "expected_behavior", "TEXT DEFAULT ''"),
            ("findings", "actual_behavior", "TEXT DEFAULT ''"),
            ("findings", "retest_status", "TEXT DEFAULT 'untested'"),
            ("findings", "evidence_json", "TEXT"),
            ("findings", "endpoint", "TEXT DEFAULT ''"),
            ("findings", "target_endpoint", "TEXT DEFAULT ''"),
            ("findings", "vulnerability_category", "TEXT DEFAULT 'BOLA_IDOR'"),
            ("findings", "affected_role", "TEXT DEFAULT 'user_b'"),
            ("findings", "affected_roles_json", "TEXT DEFAULT '[]'"),
            ("findings", "evidence_reference", "TEXT"),
            ("findings", "confirmation_status", "TEXT DEFAULT 'confirmed'"),
            ("findings", "impact_explanation", "TEXT DEFAULT ''"),
            ("findings", "remediation_recommendation", "TEXT DEFAULT ''"),
            ("findings", "created_timestamp", "TIMESTAMP"),
            ("findings", "last_retested_timestamp", "TIMESTAMP"),
            ("findings", "technical_details_json", "TEXT DEFAULT '{}'"),
            ("findings", "updated_at", "TIMESTAMP"),
            ("evidence_artifacts", "timestamp", "TIMESTAMP"),
            ("evidence_artifacts", "captured_at", "TIMESTAMP"),
            ("evidence_artifacts", "testing_role", "TEXT DEFAULT 'user_b'"),
            ("evidence_artifacts", "test_role", "TEXT DEFAULT 'user_b'"),
            ("evidence_artifacts", "request_metadata_json", "TEXT DEFAULT '{}'"),
            ("evidence_artifacts", "request_headers_json", "TEXT DEFAULT '{}'"),
            ("evidence_artifacts", "relevant_response_headers_json", "TEXT DEFAULT '{}'"),
            ("evidence_artifacts", "sanitized_response_body", "TEXT DEFAULT ''"),
            ("evidence_artifacts", "response_body", "TEXT DEFAULT ''"),
            ("evidence_artifacts", "evidence_validation_status", "TEXT DEFAULT 'valid'"),
            ("evidence_artifacts", "redacted_fields_json", "TEXT DEFAULT '[]'"),
            ("retest_logs", "summary", "TEXT"),
            ("retest_logs", "notes", "TEXT"),
            ("retest_logs", "differential_result_json", "TEXT"),
            ("scan_sessions", "updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("scan_sessions", "failure_reason", "TEXT DEFAULT ''"),
        ]

        # Cache existing table columns using PRAGMA table_info
        table_columns_cache: Dict[str, Set[str]] = {}
        for table, col, col_def in migrations:
            if table not in table_columns_cache:
                try:
                    cursor = conn.execute(f"PRAGMA table_info({table})")
                    table_columns_cache[table] = {row[1] for row in cursor.fetchall()}
                except sqlite3.OperationalError as e:
                    logger.warning(f"Could not read PRAGMA table_info for {table}: {e}")
                    table_columns_cache[table] = set()

            if col not in table_columns_cache[table]:
                try:
                    logger.info(f"Applying migration: ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                    table_columns_cache[table].add(col)
                except sqlite3.OperationalError as exc:
                    # Ignore only if column already exists (race condition)
                    if "duplicate column name" in str(exc).lower():
                        table_columns_cache[table].add(col)
                    else:
                        logger.error(f"Migration failed for {table}.{col}: {exc}")
                        raise

        # Safe backfills for newly added columns across existing rows
        try:
            if "evidence_artifacts" in table_columns_cache:
                ev_cols = table_columns_cache["evidence_artifacts"]
                if "timestamp" in ev_cols and "captured_at" in ev_cols:
                    conn.execute("UPDATE evidence_artifacts SET timestamp = COALESCE(captured_at, datetime('now')) WHERE timestamp IS NULL")
                    conn.execute("UPDATE evidence_artifacts SET captured_at = COALESCE(timestamp, datetime('now')) WHERE captured_at IS NULL")
                elif "timestamp" in ev_cols:
                    conn.execute("UPDATE evidence_artifacts SET timestamp = datetime('now') WHERE timestamp IS NULL")

                if "testing_role" in ev_cols and "test_role" in ev_cols:
                    conn.execute("UPDATE evidence_artifacts SET testing_role = COALESCE(test_role, 'user_b') WHERE testing_role IS NULL OR testing_role = ''")
                    conn.execute("UPDATE evidence_artifacts SET test_role = COALESCE(testing_role, 'user_b') WHERE test_role IS NULL OR test_role = ''")

            if "scan_sessions" in table_columns_cache:
                ss_cols = table_columns_cache["scan_sessions"]
                if "updated_at" in ss_cols:
                    conn.execute("UPDATE scan_sessions SET updated_at = COALESCE(started_at, datetime('now')) WHERE updated_at IS NULL")

            if "findings" in table_columns_cache:
                f_cols = table_columns_cache["findings"]
                if "created_timestamp" in f_cols:
                    conn.execute("UPDATE findings SET created_timestamp = COALESCE(created_at, datetime('now')) WHERE created_timestamp IS NULL")
                if "updated_at" in f_cols:
                    conn.execute("UPDATE findings SET updated_at = COALESCE(created_timestamp, created_at, datetime('now')) WHERE updated_at IS NULL")
                if "target_identifier" in f_cols and "scan_id" in f_cols:
                    conn.execute("UPDATE findings SET target_identifier = scan_id WHERE target_identifier IS NULL OR target_identifier = ''")

        except sqlite3.OperationalError as exc:
            logger.error(f"Backfill execution failed: {exc}")
            raise

    def init_schema(self) -> None:
        """Executes DDL schema initialization, column migrations, and index creation."""
        logger.info("Initializing database schema", extra={"db_path": self.db_path})
        if self.db_path == ":memory:":
            self._memory_conn.executescript(TABLES_SQL)
            self._ensure_columns(self._memory_conn)
            self._memory_conn.executescript(INDEXES_SQL)
            self._memory_conn.commit()
        else:
            with self.session_scope() as conn:
                conn.executescript(TABLES_SQL)
                self._ensure_columns(conn)
                conn.executescript(INDEXES_SQL)

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
