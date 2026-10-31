"""Pydantic data models for database records, real-time events, and domain entities."""

from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from backend.core.session_manager import Role
from backend.analysis.evidence_validator import EvidenceArtifact, EvidenceValidationStatus
from backend.analysis.severity_engine import SeverityLevel
from backend.scanner.response_analyzer import AccessVerdict


class AssessmentStage(str, Enum):
    """Seven canonical operational stages of an AuthScope security assessment."""
    SCOPE_VALIDATION = "scope_validation"
    TARGET_CONNECTION = "target_connection"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    SESSION_VERIFICATION = "session_verification"
    AUTHORIZATION_TESTING = "authorization_testing"
    EVIDENCE_VALIDATION = "evidence_validation"
    REPORT_PREPARATION = "report_preparation"


STAGE_LABELS: Dict[AssessmentStage, str] = {
    AssessmentStage.SCOPE_VALIDATION: "1. Validating target scope",
    AssessmentStage.TARGET_CONNECTION: "2. Connecting to the application",
    AssessmentStage.ENDPOINT_DISCOVERY: "3. Discovering endpoints",
    AssessmentStage.SESSION_VERIFICATION: "4. Verifying authentication sessions",
    AssessmentStage.AUTHORIZATION_TESTING: "5. Comparing authorization behavior",
    AssessmentStage.EVIDENCE_VALIDATION: "6. Validating evidence",
    AssessmentStage.REPORT_PREPARATION: "7. Preparing final findings",
}


class StageStatus(str, Enum):
    """Execution state of an individual assessment stage."""
    WAITING = "waiting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class EventType(str, Enum):
    """Structured real-time event types emitted by the assessment engine."""
    ASSESSMENT_STARTED = "assessment_started"
    SCOPE_VALIDATION_STARTED = "scope_validation_started"
    SCOPE_VALIDATION_COMPLETED = "scope_validation_completed"
    CONNECTION_COMPLETED = "connection_completed"
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    ENDPOINT_DISCOVERY_COMPLETED = "endpoint_discovery_completed"
    SESSION_VALIDATION_STARTED = "session_validation_started"
    SESSION_VALIDATION_COMPLETED = "session_validation_completed"
    AUTHORIZATION_TEST_STARTED = "authorization_test_started"
    AUTHORIZATION_TEST_COMPLETED = "authorization_test_completed"
    SUSPICIOUS_BEHAVIOR_DETECTED = "suspicious_behavior_detected"
    EVIDENCE_VALIDATION_COMPLETED = "evidence_validation_completed"
    FINDING_CONFIRMED = "finding_confirmed"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    STAGE_UPDATED = "stage_updated"


class AssessmentEvent(BaseModel):
    """Structured real-time event emitted during an assessment."""
    assessment_id: str
    event_type: str
    stage: str
    message: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StageStateRecord(BaseModel):
    """Tracks timing, status, and explanation for one of the 7 assessment stages."""
    stage: AssessmentStage
    label: str
    status: StageStatus = StageStatus.WAITING
    explanation: str = "Waiting to start"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: Optional[float] = None
    events: List[AssessmentEvent] = Field(default_factory=list)


class DiscoveredEndpointRecord(BaseModel):
    """Persisted record of a discovered route and its authorization test status."""
    id: str
    scan_id: str
    path: str
    method: str = "GET"
    category: str = "UNKNOWN"
    parameters: List[str] = Field(default_factory=list)
    requires_auth: bool = True
    discovery_status: str = "DISCOVERED"
    test_status: str = "UNTESTED"  # UNTESTED, TESTED, PARTIAL_UNAUTH_ONLY, SKIPPED
    verdict: Optional[str] = None  # AccessVerdict string if tested
    associated_finding_ids: List[str] = Field(default_factory=list)
    summary: str = ""


class ScanSessionRecord(BaseModel):
    """Represents a penetration testing assessment session stored in SQLite."""
    id: str
    target_url: str
    status: str = "RUNNING"  # RUNNING, COMPLETED, FAILED, CANCELLED
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    endpoints_discovered_count: int = 0
    endpoints_tested_count: int = 0
    confirmed_findings_count: int = 0
    suspicious_results_count: int = 0
    stages: Dict[str, StageStateRecord] = Field(default_factory=dict)
    summary_text: str = ""


class FindingRecord(BaseModel):
    """Represents a security finding (confirmed or suspicious) with full evidence metadata."""
    id: str
    scan_id: str
    title: str
    vulnerability_type: str
    severity: SeverityLevel
    status: str = "confirmed"  # suspected, confirmed, remediated, false_positive
    validation_status: str = EvidenceValidationStatus.CONFIRMED.value
    access_verdict: str = AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
    target_endpoint: str
    http_method: str
    resource_id: Optional[str] = None
    expected_behavior: str = "Unauthorized role should be denied access (HTTP 401/403)."
    actual_behavior: str = ""
    description: str
    remediation_guidance: str
    retest_status: str = "NOT_RETESTED"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Optional[EvidenceArtifact] = None


class RetestLogRecord(BaseModel):
    """Represents a regression retest execution entry."""
    id: str
    finding_id: str
    previous_status: str
    new_status: str
    is_vulnerable: bool
    notes: str
    retested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
