"""Test fixtures for the memory subsystem test suite."""

import uuid
import pytest
from datetime import datetime, timezone
from typing import List
from unittest.mock import MagicMock

from backend.analysis.severity_engine import SeverityLevel
from backend.memory.manager import MemoryManager
from backend.memory.rag import SecurityKnowledgeRAG
from backend.storage.database import DatabaseManager
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    EvidenceArtifact,
    EvidenceValidationStatus,
    FindingRecord,
    FindingStatus,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_db() -> DatabaseManager:
    """In-memory SQLite database for isolated test runs."""
    db = DatabaseManager(db_path=":memory:")
    db.init_schema()
    return db


@pytest.fixture
def finding_repo(in_memory_db: DatabaseManager) -> FindingRepository:
    """FindingRepository wired to in-memory SQLite."""
    return FindingRepository(db_manager=in_memory_db)


# ---------------------------------------------------------------------------
# Embedding mock
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_embedding_fn():
    """Deterministic fake embedding function (returns 16-dim constant vector)."""
    call_log: List[str] = []

    def _embed(text: str) -> List[float]:
        call_log.append(text)
        # Simple hash-derived pseudo-embedding for consistency in tests
        h = sum(ord(c) for c in text) % 100
        return [float(h) / 100.0] * 16

    _embed.call_log = call_log  # expose for assertions
    return _embed


# ---------------------------------------------------------------------------
# Sample finding
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_evidence() -> EvidenceArtifact:
    return EvidenceArtifact(
        finding_id="finding-test-001",
        endpoint="/api/test/resource/1",
        http_method="GET",
        testing_role="user_b",
        authorized_role="user_a",
        resource_id="1",
        expected_behavior="HTTP 403 Forbidden",
        actual_behavior="HTTP 200 with user_a private data",
        validation_status=EvidenceValidationStatus.CONFIRMED,
        request_method="GET",
        request_url="http://localhost:3000/api/test/resource/1",
        response_status=200,
        sanitized_response_body='{"id":1,"name":"User A secret"}',
        sanitized_response_evidence='{"id":1,"name":"User A secret"}',
    )


@pytest.fixture
def sample_finding(sample_evidence: EvidenceArtifact) -> FindingRecord:
    return FindingRecord(
        id="finding-test-001",
        target_identifier="http://localhost:3000",
        scan_id="scan-test-001",
        title="BOLA: Unauthorized basket access",
        endpoint="/api/test/resource/1",
        http_method="GET",
        vulnerability_category="BOLA_IDOR",
        vulnerability_type="BOLA_IDOR",
        affected_role="user_b",
        expected_behavior="HTTP 403 Forbidden",
        actual_behavior="HTTP 200 with user_a private data",
        severity=SeverityLevel.HIGH,
        status=FindingStatus.CONFIRMED,
        confirmation_status="confirmed",
        validation_status="CONFIRMED",
        description="User B accessed User A's private resource without authorization.",
        remediation_recommendation="Add user ownership check to the resource query.",
        evidence=sample_evidence,
    )


# ---------------------------------------------------------------------------
# MemoryManager fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def memory_manager(finding_repo: FindingRepository, mock_embedding_fn) -> MemoryManager:
    """MemoryManager wired to in-memory DB with mock embeddings and no ChromaDB."""
    return MemoryManager(
        repository=finding_repo,
        use_vector_rag=True,
        embed_fn=mock_embedding_fn,
        knowledge_base_dir=None,  # no KB ingestion in unit tests
    )

