"""Pydantic data models for database records and domain entities."""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from backend.core.session_manager import Role
from backend.analysis.evidence_validator import EvidenceArtifact
from backend.analysis.severity_engine import SeverityLevel


class ScanSessionRecord(BaseModel):
    """Represents a penetration testing scan session."""
    id: str
    target_url: str
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class FindingRecord(BaseModel):
    """Represents a verified security finding."""
    id: str
    scan_id: str
    title: str
    vulnerability_type: str
    severity: SeverityLevel
    status: str = "confirmed"  # suspected, confirmed, remediated, false_positive
    target_endpoint: str
    http_method: str
    description: str
    remediation_guidance: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    evidence: Optional[EvidenceArtifact] = None


class RetestLogRecord(BaseModel):
    """Represents a regression retest execution entry."""
    id: str
    finding_id: str
    previous_status: str
    new_status: str
    is_vulnerable: bool
    notes: str
    retested_at: datetime = Field(default_factory=datetime.utcnow)

