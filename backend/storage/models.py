"""Pydantic data models for database records, real-time events, and domain entities.

Strictly adheres to API contracts, validation rules, and schema boundaries.
Enforces Data Redaction so sensitive credentials never enter persistence models in raw form.
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
from enum import Enum
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator
from backend.core.session_manager import Role
from backend.analysis.severity_engine import SeverityLevel
from backend.utils.helpers import compute_sha256, redact_sensitive_text, sanitize_dict_or_list


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
    EVIDENCE_VALIDATION_STARTED = "evidence_validation_started"
    SUSPICIOUS_BEHAVIOR_DETECTED = "suspicious_behavior_detected"
    EVIDENCE_VALIDATION_COMPLETED = "evidence_validation_completed"
    FINDING_CONFIRMED = "finding_confirmed"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    STAGE_UPDATED = "stage_updated"


class VulnerabilityType(str, Enum):
    """Categorization of supported authorization vulnerability types."""
    BOLA_IDOR = "BOLA_IDOR"
    BFLA = "BFLA"
    MISSING_AUTH = "MISSING_AUTH"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    MULTI_STEP_CHAIN = "MULTI_STEP_CHAIN"


class FindingStatus(str, Enum):
    """Lifecycle statuses for security findings."""
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class EvidenceValidationStatus(str, Enum):
    """Validation status of an authorization finding evidence artifact."""
    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    REJECTED_FALSE_POSITIVE = "REJECTED_FALSE_POSITIVE"
    UNVALIDATED = "UNVALIDATED"


class TargetApprovalStatus(str, Enum):
    """Approval lifecycle statuses for dynamic target profiles."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class AuthorizationBasis(str, Enum):
    """Legal and operational authorization grounds for target assessment."""
    ADMIN_APPROVED = "admin_approved"
    WRITTEN_PERMISSION = "written_permission"
    BUG_BOUNTY_SCOPE = "bug_bounty_scope"
    DOMAIN_OWNERSHIP_CHALLENGE = "domain_ownership_challenge"
    LOCAL_DEVELOPMENT = "local_development"


class TargetProfileRecord(BaseModel):
    """Persisted dynamic authorized target profile."""
    id: str = Field(..., description="Unique target profile identifier")
    hostname: str = Field(..., description="Exact target hostname (e.g. staging.example.com)")
    base_url: str = Field(..., description="Canonical base URL (e.g. https://staging.example.com)")
    allowed_schemes: List[str] = Field(default_factory=lambda: ["https"])
    allowed_ports: List[int] = Field(default_factory=lambda: [443])
    allowed_paths: List[str] = Field(default_factory=list, description="Optional path prefix restrictions")
    allowed_methods: List[str] = Field(default_factory=lambda: ["GET", "HEAD"])
    authorization_basis: str = Field(default="admin_approved")
    permission_reference: str = Field(default="", description="Ticket ID, contract, or bug bounty link")
    approval_status: str = Field(default="PENDING")
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: str = ""
    verification_token: str = ""
    verified_at: Optional[datetime] = None
    is_local_test: bool = False
    notes: str = ""

    def is_active(self, now: Optional[datetime] = None) -> bool:
        """Determines if the target profile is actively approved and unexpired."""
        current_time = now or datetime.now(timezone.utc)
        if self.approval_status != TargetApprovalStatus.APPROVED.value:
            return False
        if self.expires_at is not None and self.expires_at <= current_time:
            return False
        if self.revoked_at is not None:
            return False
        return True


class AssessmentEvent(BaseModel):
    """Structured real-time event emitted during an assessment."""
    id: Optional[int] = None
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
    id: str = Field(..., description="Unique scan session ID")
    target_url: str = Field(..., description="Base target URL scanned")
    status: str = Field("RUNNING", description="Session state: RUNNING, COMPLETED, FAILED, CANCELLED")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    endpoints_discovered_count: int = 0
    endpoints_tested_count: int = 0
    confirmed_findings_count: int = 0
    suspicious_results_count: int = 0
    stages: Dict[str, StageStateRecord] = Field(default_factory=dict)
    summary_text: str = ""
    config: Dict[str, Any] = Field(default_factory=dict, description="Scan parameters")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    failure_reason: str = Field(default="", description="Failure reason code: SERVER_RESTART, TIMEOUT, etc.")


class EvidenceArtifact(BaseModel):
    """Structured, immutable evidence package supporting a verified finding."""
    id: str = Field(default="", description="Unique evidence ID")
    evidence_id: Optional[str] = Field(None, description="Alias for evidence ID")
    finding_id: str = Field(..., description="Associated finding ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint: str = Field(default="", description="Target endpoint path or URL")
    http_method: str = Field(default="GET", description="HTTP method executed")
    testing_role: Union[Role, str] = Field(Role.USER_B, description="Active role context during probing")
    test_role: Optional[Union[Role, str]] = Field(None, description="Alias for testing_role")
    authorized_role: Optional[Union[Role, str]] = Field(Role.USER_A, description="Role authorized for resource")
    resource_id: Optional[str] = Field(default=None, description="Resource identifier tested")
    expected_behavior: str = Field(
        default="Access denied (HTTP 401/403) for unauthorized role",
        description="Expected authorization enforcement behavior",
    )
    actual_behavior: str = Field(
        default="",
        description="Observed response behavior from the target",
    )
    validation_status: Union[EvidenceValidationStatus, str] = Field(
        default=EvidenceValidationStatus.CONFIRMED,
        description="Evidence validation classification",
    )

    # Request data
    request_metadata: Dict[str, Any] = Field(default_factory=dict, description="Request execution metadata")
    request_method: str = Field("GET", description="HTTP method used in test")
    request_url: str = Field("", description="Full URL tested")
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Sanitized request headers")
    raw_request: Optional[Any] = Field(None, description="Structured request object if present")

    # Response data
    response_status: int = Field(200, description="HTTP response status code")
    relevant_response_headers: Dict[str, str] = Field(default_factory=dict, description="Sanitized response headers")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Alias for relevant_response_headers")
    sanitized_response_body: str = Field("", description="Redacted response body text")
    response_body: str = Field("", description="Alias for sanitized_response_body")
    sanitized_response_evidence: str = Field("", description="Sanitized excerpt demonstrating behavior")
    raw_response: Optional[Any] = Field(None, description="Structured response object if present")

    # Validation & integrity
    evidence_validation_status: str = Field("valid", description="Integrity status: valid, invalid, unverified")
    evidence_sha256: str = Field("", description="SHA-256 hash across canonical request/response")
    redacted_fields: List[str] = Field(default_factory=list, description="Fields and headers sanitized")
    redacted_tokens: List[str] = Field(default_factory=list, description="Alias for redacted_fields")

    @model_validator(mode="before")
    @classmethod
    def sanitize_and_normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # ID harmonization
        evi_id = data.get("id") or data.get("evidence_id")
        if not evi_id:
            evi_id = f"evi_{uuid.uuid4().hex[:8]}"
        data["id"] = evi_id
        data["evidence_id"] = evi_id

        # Role harmonization
        role = data.get("testing_role") or data.get("test_role") or Role.USER_B
        if isinstance(role, Role):
            role_val = role
        else:
            try:
                role_val = Role(role)
            except Exception:
                role_val = role
        data["testing_role"] = role_val
        data["test_role"] = role_val

        # Endpoint & Method harmonization
        if not data.get("endpoint") and data.get("request_url"):
            data["endpoint"] = str(data["request_url"])
        if not data.get("http_method") and data.get("request_method"):
            data["http_method"] = str(data["request_method"]).upper()

        # Handle nested raw_request / raw_response models or dicts
        req = data.get("raw_request")
        if req:
            if hasattr(req, "method"):
                data.setdefault("request_method", getattr(req, "method", "GET"))
                data.setdefault("request_url", str(getattr(req, "url", "")))
                req_headers = getattr(req, "headers", {})
                if isinstance(req_headers, dict):
                    data.setdefault("request_headers", dict(req_headers))
            elif isinstance(req, dict):
                data.setdefault("request_method", req.get("method", "GET"))
                data.setdefault("request_url", str(req.get("url", "")))
                if isinstance(req.get("headers"), dict):
                    data.setdefault("request_headers", dict(req["headers"]))

        resp = data.get("raw_response")
        if resp:
            if hasattr(resp, "status_code"):
                data.setdefault("response_status", int(getattr(resp, "status_code", 200)))
                data.setdefault("sanitized_response_body", str(getattr(resp, "body", "")))
            elif isinstance(resp, dict):
                data.setdefault("response_status", int(resp.get("status_code", 200)))
                data.setdefault("sanitized_response_body", str(resp.get("body", "")))

        # Sanitize request_url and request_metadata
        if "request_url" in data:
            data["request_url"] = redact_sensitive_text(str(data["request_url"]))
        if "request_metadata" in data:
            data["request_metadata"] = sanitize_dict_or_list(data["request_metadata"])

        # Harmonize response body
        body = data.get("sanitized_response_body") or data.get("response_body") or ""
        redacted_fields = list(data.get("redacted_fields") or data.get("redacted_tokens") or [])

        # Sanitize headers
        headers = dict(data.get("request_headers") or {})
        sanitized_headers = {}
        for k, v in headers.items():
            k_lower = k.lower()
            v_str = str(v)
            if k_lower in ("authorization", "proxy-authorization"):
                if v_str.lower().startswith("basic "):
                    sanitized_headers[k] = "Basic [REDACTED_BASIC_AUTH]"
                else:
                    sanitized_headers[k] = "Bearer [REDACTED_BEARER_TOKEN]"
                if k not in redacted_fields:
                    redacted_fields.append(k)
            elif k_lower in ("cookie", "set-cookie"):
                sanitized_headers[k] = "[REDACTED_COOKIE]"
                if k not in redacted_fields:
                    redacted_fields.append(k)
            elif k_lower in ("x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token"):
                sanitized_headers[k] = "[REDACTED_API_KEY]"
                if k not in redacted_fields:
                    redacted_fields.append(k)
            else:
                sanitized_headers[k] = redact_sensitive_text(v_str)
        data["request_headers"] = sanitized_headers

        # Sanitize response body
        sanitized_body = redact_sensitive_text(str(body))
        if sanitized_body != body and "response_body" not in redacted_fields:
            redacted_fields.append("response_body")
        data["sanitized_response_body"] = sanitized_body
        data["response_body"] = sanitized_body
        if not data.get("sanitized_response_evidence"):
            data["sanitized_response_evidence"] = sanitized_body[:1500]

        # Harmonize response headers
        resp_headers = dict(data.get("relevant_response_headers") or data.get("response_headers") or {})
        sanitized_resp_headers = {}
        for k, v in resp_headers.items():
            k_lower = k.lower()
            if k_lower in ("set-cookie", "cookie"):
                sanitized_resp_headers[k] = "[REDACTED_COOKIE]"
                if f"response_{k}" not in redacted_fields:
                    redacted_fields.append(f"response_{k}")
            elif k_lower in ("authorization", "proxy-authorization"):
                sanitized_resp_headers[k] = "[REDACTED]"
                if f"response_{k}" not in redacted_fields:
                    redacted_fields.append(f"response_{k}")
            elif k_lower in ("x-api-key", "api-key", "x-auth-token"):
                sanitized_resp_headers[k] = "[REDACTED_API_KEY]"
                if f"response_{k}" not in redacted_fields:
                    redacted_fields.append(f"response_{k}")
            else:
                sanitized_resp_headers[k] = redact_sensitive_text(str(v))
        data["relevant_response_headers"] = sanitized_resp_headers
        data["response_headers"] = sanitized_resp_headers

        data["redacted_fields"] = redacted_fields
        data["redacted_tokens"] = redacted_fields

        # Compute SHA-256 evidence integrity hash if not provided
        if not data.get("evidence_sha256"):
            method = data.get("request_method", "GET")
            url = data.get("request_url", "")
            status = data.get("response_status", 200)
            canonical = f"{method}|{url}|{status}|{sanitized_body}"
            data["evidence_sha256"] = compute_sha256(canonical)

        return data


class FindingRecord(BaseModel):
    """Represents a verified security finding with comprehensive metadata."""
    id: str = Field(..., description="Unique finding ID")
    target_identifier: str = Field(default="", description="Target application or scan identifier")
    scan_id: str = Field(default="default_scan", description="Associated scan identifier")
    endpoint: str = Field(default="", description="Vulnerable endpoint URL or path")
    target_endpoint: str = Field(default="", description="Alias for endpoint")
    http_method: str = Field("GET", description="HTTP method (GET, POST, etc.)")
    vulnerability_category: str = Field(default="BOLA_IDOR", description="Category of vulnerability")
    vulnerability_type: str = Field(default="BOLA_IDOR", description="Alias for vulnerability category")
    affected_role: str = Field(default="user_b", description="Role executing unauthorized access")
    affected_roles: List[Union[Role, str]] = Field(default_factory=list, description="Roles impacted")
    expected_behavior: str = Field(default="", description="Expected system behavior under authorization policy")
    actual_behavior: str = Field(default="", description="Observed differential discrepancy behavior")
    evidence_reference: Optional[str] = Field(None, description="Pointer or ID of supporting evidence artifact")
    confirmation_status: str = Field(default="confirmed", description="Confirmation status: suspected, confirmed, remediated, false_positive")
    status: str = Field(default="confirmed", description="Alias for confirmation_status")
    validation_status: str = Field(default="CONFIRMED", description="Validation status: CONFIRMED, SUSPICIOUS")
    access_verdict: str = Field(default="CONFIRMED_UNAUTHORIZED_ACCESS", description="Access verdict")
    resource_id: Optional[str] = None
    severity: SeverityLevel = Field(SeverityLevel.MEDIUM, description="Standardized severity rating")
    impact_explanation: str = Field(default="", description="Detailed business and security impact explanation")
    description: str = Field(default="", description="Alias for impact explanation")
    remediation_recommendation: str = Field(default="", description="Code-level remediation recommendation")
    remediation_guidance: str = Field(default="", description="Alias for remediation recommendation")
    created_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of finding creation")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Alias for created_timestamp")
    last_retested_timestamp: Optional[datetime] = None
    retest_status: Optional[str] = "untested"
    classification: Optional[str] = Field(default=None, description="Finding classification")
    title: str = Field(default="", description="Human-readable title for dashboards and reports")
    technical_details: Dict[str, Any] = Field(default_factory=dict, description="Differential metrics and context")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Optional[EvidenceArtifact] = Field(None, description="Embedded evidence artifact")

    @field_validator("id")
    @classmethod
    def validate_id_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Finding id must not be empty.")
        return v.strip()

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, v: str) -> str:
        method = v.strip().upper()
        allowed = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if method not in allowed:
            raise ValueError(f"Invalid HTTP method: '{v}'. Must be one of {allowed}")
        return method

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Harmonize endpoint
        ep = data.get("endpoint") or data.get("target_endpoint") or ""
        if not ep or not ep.strip():
            raise ValueError("Endpoint must not be empty.")
        data["endpoint"] = ep.strip()
        data["target_endpoint"] = ep.strip()

        # Harmonize target_identifier / scan_id
        target_id = data.get("target_identifier") or data.get("scan_id") or "scan_default"
        data["target_identifier"] = target_id
        data["scan_id"] = target_id

        # Harmonize vulnerability category / type
        v_type = data.get("vulnerability_category") or data.get("vulnerability_type") or "BOLA_IDOR"
        if isinstance(v_type, VulnerabilityType):
            v_type_val = v_type.value
        else:
            v_type_val = str(v_type)
        data["vulnerability_category"] = v_type_val
        data["vulnerability_type"] = v_type_val

        # Harmonize status
        st = data.get("confirmation_status") or data.get("status") or "confirmed"
        if isinstance(st, FindingStatus):
            st_val = st.value
        else:
            st_val = str(st)
        data["confirmation_status"] = st_val
        data["status"] = st_val

        # Harmonize validation status & access verdict
        val_st = data.get("validation_status")
        if not val_st:
            data["validation_status"] = "CONFIRMED" if st_val == "confirmed" else "SUSPICIOUS"
        if not data.get("access_verdict"):
            data["access_verdict"] = (
                "CONFIRMED_UNAUTHORIZED_ACCESS"
                if data["validation_status"] == "CONFIRMED"
                else "SUSPICIOUS_ACCESS"
            )

        # Harmonize classification
        if not data.get("classification") and "technical_details" in data and isinstance(data["technical_details"], dict):
            data["classification"] = data["technical_details"].get("classification")
        elif "classification" in data and data["classification"]:
            cl = data["classification"]
            data["classification"] = cl.value if hasattr(cl, "value") else str(cl)
        # Harmonize severity
        sev = data.get("severity")
        if sev is None:
            data["severity"] = SeverityLevel.MEDIUM

        # Harmonize roles
        aff_role = data.get("affected_role")
        aff_roles = list(data.get("affected_roles") or [])
        if not aff_role and aff_roles:
            first_role = aff_roles[0]
            aff_role = first_role.value if isinstance(first_role, Role) else str(first_role)
        elif aff_role and not aff_roles:
            aff_roles = [aff_role]
        elif not aff_role and not aff_roles:
            aff_role = "user_b"
            aff_roles = ["user_b"]
        data["affected_role"] = str(aff_role)
        data["affected_roles"] = aff_roles

        # Harmonize impact / description
        impact = data.get("impact_explanation") or data.get("description") or ""
        data["impact_explanation"] = redact_sensitive_text(str(impact))
        data["description"] = data["impact_explanation"]

        # Harmonize remediation
        remed = data.get("remediation_recommendation") or data.get("remediation_guidance") or ""
        data["remediation_recommendation"] = str(remed)
        data["remediation_guidance"] = str(remed)

        # Harmonize behavior fields
        exp = data.get("expected_behavior") or "Enforce authorization access control."
        act = data.get("actual_behavior") or data["impact_explanation"] or "Discrepancy detected across roles."
        data["expected_behavior"] = redact_sensitive_text(str(exp))
        data["actual_behavior"] = redact_sensitive_text(str(act))

        # Title fallback
        if not data.get("title"):
            data["title"] = f"{v_type_val} on {ep}"

        # Harmonize created timestamp
        c_time = data.get("created_timestamp") or data.get("created_at") or datetime.now(timezone.utc)
        data["created_timestamp"] = c_time
        data["created_at"] = c_time

        # Harmonize retest_status
        if not data.get("retest_status"):
            data["retest_status"] = "untested"

        # Evidence reference
        evi = data.get("evidence")
        if evi:
            if isinstance(evi, dict):
                data["evidence_reference"] = evi.get("id") or evi.get("evidence_id")
            elif hasattr(evi, "id"):
                data["evidence_reference"] = getattr(evi, "id")

        # Sanitize technical_details
        if "technical_details" in data:
            data["technical_details"] = sanitize_dict_or_list(data["technical_details"])

        return data


class RetestLogRecord(BaseModel):
    """Represents a regression retest execution entry."""
    id: str = Field(..., description="Unique retest execution ID")
    finding_id: str = Field(..., description="Target finding ID retested")
    retest_id: Optional[str] = Field(None, description="Alias for retest ID")
    previous_status: str = Field("confirmed", description="Status prior to retest")
    new_status: str = Field("confirmed", description="Status after retest")
    is_vulnerable: bool = Field(True, description="True if vulnerability is still confirmed")
    summary: Optional[str] = Field(None, description="Summary of retest analysis")
    notes: str = Field("", description="Detailed retest observations")
    differential_result: Optional[Dict[str, Any]] = Field(None, description="Differential probe details")
    retested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="before")
    @classmethod
    def normalize_retest(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        ret_id = data.get("id") or data.get("retest_id")
        if not ret_id:
            ret_id = f"retest_{uuid.uuid4().hex[:8]}"
        data["id"] = ret_id
        data["retest_id"] = ret_id
        if not data.get("notes") and data.get("summary"):
            data["notes"] = data["summary"]
        return data
