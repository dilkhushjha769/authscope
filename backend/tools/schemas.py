"""Data contracts, schemas, and event definitions for the AuthScope Tool System.

Defines Pydantic v2 validation models for tool execution, lifecycle events,
metadata registration, and domain-specific tool inputs and outputs.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import uuid
from pydantic import BaseModel, ConfigDict, Field


# ==============================================================================
# Enums
# ==============================================================================


class ToolCategory(str, Enum):
    """Categorization of security tools available to the AI agent."""
    WEBSITE_ASSESSMENT = "WEBSITE_ASSESSMENT"
    AUTHORIZATION_TESTING = "AUTHORIZATION_TESTING"
    SOURCE_ANALYSIS = "SOURCE_ANALYSIS"
    REPORTING = "REPORTING"


class ToolExecutionStatus(str, Enum):
    """Outcome status of an executed tool invocation."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"


# ==============================================================================
# Tool Execution Context & Results
# ==============================================================================


class ToolExecutionContext(BaseModel):
    """Runtime context passed to a tool during execution."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: Optional[str] = Field(default=None, description="Active scan session identifier")
    caller: str = Field(default="gemini_agent", description="Identifier of the invoking agent")
    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique execution correlation ID"
    )
    human_approved: bool = Field(
        default=False,
        description="Whether a human operator approved high-risk or write operations"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context headers or parameters")


class ToolExecutionResult(BaseModel):
    """Standardized result returned by any tool execution."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_name: str = Field(..., description="Name of the executed tool")
    execution_id: str = Field(..., description="Execution correlation ID")
    status: ToolExecutionStatus = Field(..., description="Execution status")
    duration_ms: float = Field(default=0.0, description="Execution duration in milliseconds")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of completion"
    )
    data: Optional[Dict[str, Any]] = Field(default=None, description="Structured tool output payload")
    error: Optional[str] = Field(default=None, description="Error message if execution failed")


# ==============================================================================
# Streaming Execution Events for Frontend (Member 4 Integration)
# ==============================================================================


class ToolEventBase(BaseModel):
    """Base model for streaming tool lifecycle events."""
    event_type: str
    tool_name: str
    execution_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ToolStartedEvent(ToolEventBase):
    """Emitted immediately before a tool begins execution."""
    event_type: str = "tool_started"
    arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolCompletedEvent(ToolEventBase):
    """Emitted immediately after a tool succeeds."""
    event_type: str = "tool_completed"
    duration_ms: float
    summary: str


class ToolFailedEvent(ToolEventBase):
    """Emitted when a tool encounters an error or scope violation."""
    event_type: str = "tool_failed"
    duration_ms: float
    error: str
    status: ToolExecutionStatus


class EvidenceValidatedEvent(ToolEventBase):
    """Emitted when evidence for a finding is verified."""
    event_type: str = "evidence_validated"
    finding_id: str
    validation_status: str
    is_confirmed: bool


# ==============================================================================
# Specific Tool Input / Output Schemas
# ==============================================================================

# --- 1. Website Assessment Schemas ---


class ValidateTargetInput(BaseModel):
    """Input for target scope validation."""
    url: str = Field(..., description="Target URL to validate against authorized scope")
    method: str = Field(default="GET", description="Intended HTTP method")


class ValidateTargetOutput(BaseModel):
    """Output for target scope validation."""
    url: str
    is_allowed: bool
    reason: str
    host: Optional[str] = None
    port: Optional[int] = None
    normalized_url: Optional[str] = None


class DiscoverEndpointsInput(BaseModel):
    """Input for attack surface endpoint discovery."""
    base_url: Optional[str] = Field(
        default=None,
        description="Base URL of authorized target (defaults to configured target)"
    )
    include_admin: bool = Field(default=True, description="Whether to include admin routes")


class DiscoveredEndpointSummary(BaseModel):
    """Summary of a discovered endpoint."""
    path: str
    method: str
    category: str
    resource_type: Optional[str] = None
    requires_auth: bool = True
    parameters: List[str] = Field(default_factory=list)


class DiscoverEndpointsOutput(BaseModel):
    """Output of attack surface endpoint discovery."""
    base_url: str
    endpoint_count: int
    endpoints: List[DiscoveredEndpointSummary]


class InspectEndpointInput(BaseModel):
    """Input for safely inspecting a permitted GET/HEAD endpoint."""
    url: str = Field(..., description="Full URL or relative path on authorized target")
    method: str = Field(default="GET", description="HTTP method (GET or HEAD only)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Optional custom headers")


class InspectEndpointOutput(BaseModel):
    """Output for inspecting an endpoint."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body_snippet: str
    is_json: bool
    content_length: int
    duration_ms: float


class AnalyzeResponseInput(BaseModel):
    """Input for analyzing an HTTP response for access-control indicators."""
    status_code: int = Field(..., description="HTTP status code")
    body: str = Field(default="", description="Response body text")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    expected_status: int = Field(default=200, description="Expected status code")


class AnalyzeResponseOutput(BaseModel):
    """Output for analyzing an HTTP response."""
    verdict: str
    is_access_granted: bool
    is_error: bool
    indicates_leak: bool
    reasons: List[str] = Field(default_factory=list)


class CheckHttpMethodsInput(BaseModel):
    """Input for checking permitted HTTP methods on an endpoint."""
    url: str = Field(..., description="Target URL")


class CheckHttpMethodsOutput(BaseModel):
    """Output of permitted HTTP methods check."""
    url: str
    allowed_methods: List[str]
    is_safe: bool


# --- 2. Authorization Testing Schemas ---


class CompareEndpointAccessInput(BaseModel):
    """Input for testing access-control differences across roles on an endpoint."""
    endpoint: str = Field(..., description="Relative endpoint path (e.g. /rest/basket/1)")
    resource_id: Optional[str] = Field(
        default=None,
        description="Concrete resource ID owned by primary role"
    )
    test_roles: List[str] = Field(
        default_factory=lambda: ["ANONYMOUS", "USER_B", "ADMIN"],
        description="Roles to test against primary owner"
    )
    owner_role: str = Field(default="USER_A", description="Legitimate resource owner role")


class RoleComparisonResult(BaseModel):
    """Result of access probe for a single role."""
    role: str
    status_code: int
    verdict: str
    is_access_granted: bool


class CompareEndpointAccessOutput(BaseModel):
    """Output of multi-role authorization-differential testing."""
    endpoint: str
    resolved_url: str
    resource_id: Optional[str] = None
    is_discrepancy_detected: bool
    is_confirmed: bool
    vulnerability_candidate: Optional[str] = None
    role_results: List[RoleComparisonResult]
    summary: str


class ProbeAccessControlInput(BaseModel):
    """Input for testing an endpoint under a specific test role."""
    __test__ = False
    endpoint: str = Field(..., description="Endpoint path")
    role: str = Field(..., description="Role to test: ANONYMOUS, USER_A, USER_B, ADMIN")
    resource_id: Optional[str] = Field(default=None, description="Resource ID")


class ProbeAccessControlOutput(BaseModel):
    """Output of single-role access control test."""
    __test__ = False
    endpoint: str
    role: str
    status_code: int
    verdict: str
    is_access_granted: bool
    evidence_id: Optional[str] = None


TestAccessControlInput = ProbeAccessControlInput
TestAccessControlOutput = ProbeAccessControlOutput


class DetectIdorInput(BaseModel):
    """Input for IDOR / BOLA specific detection."""
    endpoint_template: str = Field(..., description="Endpoint with ID (e.g. /rest/basket/{id})")
    victim_resource_id: str = Field(..., description="Resource ID owned by Victim (User A)")
    attacker_role: str = Field(default="USER_B", description="Role attempting unauthorized access")


class DetectIdorOutput(BaseModel):
    """Output for IDOR / BOLA specific detection."""
    is_idor_detected: bool
    victim_resource_id: str
    attacker_role: str
    evidence_summary: str
    vulnerability_title: Optional[str] = None


# --- 3. Source Analysis Schemas ---


class MapEndpointToCodeInput(BaseModel):
    """Input for mapping an endpoint to backend source code."""
    endpoint: str = Field(..., description="Endpoint path (e.g. /rest/basket/1)")
    http_method: str = Field(default="GET", description="HTTP method")


class SourceLocationSummary(BaseModel):
    """Summary of mapped source location."""
    repository_name: Optional[str] = None
    file_path: str
    function_name: Optional[str] = None
    start_line: int
    end_line: int
    code_snippet: str
    route_handler: Optional[str] = None
    database_operation: Optional[str] = None
    authorization_check: Optional[str] = None
    confidence: str


class MapEndpointToCodeOutput(BaseModel):
    """Output for mapping an endpoint to source code."""
    status: str
    verified: bool
    message: str
    location: Optional[SourceLocationSummary] = None
    candidate_count: int = 0


class AnalyzeSourceCodeInput(BaseModel):
    """Input for verifying a static source location hint."""
    file_path: str = Field(..., description="Relative file path in repository")
    start_line: int = Field(..., description="Starting line number")
    end_line: int = Field(..., description="Ending line number")
    function_name: Optional[str] = Field(default=None, description="Function name to verify")
    expected_snippet: Optional[str] = Field(default=None, description="Expected code snippet")


class AnalyzeSourceCodeOutput(BaseModel):
    """Output for verifying a static source location."""
    verified: bool
    status: str
    file_path: str
    actual_snippet: Optional[str] = None
    database_operation: Optional[str] = None
    authorization_check: Optional[str] = None
    error: Optional[str] = None


# --- 4. Reporting Schemas ---


class ValidateEvidenceInput(BaseModel):
    """Input for validating a finding's evidence artifact."""
    finding_id: str = Field(..., description="ID of finding to validate")
    status_code: int = Field(..., description="Observed HTTP status code")
    evidence_text: str = Field(..., description="Sanitized response body evidence")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    category: str = Field(default="BOLA_IDOR", description="Vulnerability category")


class ValidateEvidenceOutput(BaseModel):
    """Output of evidence validation."""
    finding_id: str
    is_valid: bool
    validation_status: str
    has_secret_leak: bool
    evidence_hash: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)


class ExplainFindingInput(BaseModel):
    """Input for generating a finding explanation."""
    finding_id: str = Field(..., description="Finding identifier")
    title: str = Field(..., description="Finding title")
    endpoint: str = Field(..., description="Endpoint")
    method: str = Field(default="GET", description="HTTP method")
    category: str = Field(default="BOLA_IDOR", description="Vulnerability category")
    affected_role: str = Field(default="USER_B", description="Affected role")
    actual_behavior: str = Field(..., description="Observed unauthorized behavior")


class ExplainFindingOutput(BaseModel):
    """Output of finding explanation."""
    finding_id: str
    title: str
    category: str
    explanation: str
    impact: str
    root_cause: str


class GenerateRemediationInput(BaseModel):
    """Input for generating remediation guidance."""
    finding_id: str = Field(..., description="Finding identifier")
    category: str = Field(default="BOLA_IDOR", description="Vulnerability category")
    endpoint: str = Field(..., description="Affected endpoint")
    method: str = Field(default="GET", description="HTTP method")
    code_snippet: Optional[str] = Field(default=None, description="Vulnerable code snippet if mapped")
    file_path: Optional[str] = Field(default=None, description="Source file path")


class GenerateRemediationOutput(BaseModel):
    """Output of remediation generation."""
    finding_id: str
    recommendation: str
    code_fix: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class GetAssessmentSummaryInput(BaseModel):
    """Input for retrieving assessment summary."""
    session_id: Optional[str] = Field(default=None, description="Session ID (optional)")


class GetAssessmentSummaryOutput(BaseModel):
    """Output for assessment summary."""
    total_findings: int
    confirmed_findings: int
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    endpoints_tested: int
