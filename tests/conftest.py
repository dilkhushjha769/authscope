"""Pytest configuration and shared test fixtures for AuthScope."""

import pytest
from backend.core.scope_guard import ScopeGuard
from backend.scanner.request_executor import RequestExecutor
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository


@pytest.fixture
def scope_guard() -> ScopeGuard:
    """Provides a ScopeGuard instance locked to localhost:3000."""
    return ScopeGuard(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_schemes=["http", "https"]
    )


@pytest.fixture
def in_memory_db() -> DatabaseManager:
    """Provides an isolated in-memory SQLite database manager for unit tests."""
    db_mgr = DatabaseManager(db_path=":memory:")
    db_mgr.init_schema()
    return db_mgr


@pytest.fixture
def finding_repo(in_memory_db: DatabaseManager) -> FindingRepository:
    """Provides a FindingRepository backed by an in-memory database."""
    return FindingRepository(db_manager=in_memory_db)

