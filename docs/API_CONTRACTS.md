# AuthScope: API Contracts & Data Specifications

This document defines the formal Python interfaces, Pydantic schemas, and data structures used across AuthScope. All modules must adhere strictly to these contracts.

---

## 1. Core Enumerations & Types

```python
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime

class Role(str, Enum):
    ANONYMOUS = "anonymous"
    USER_A = "user_a"       # Low-privilege victim/baseline
    USER_B = "user_b"       # Low-privilege attacker/peer
    ADMIN = "admin"         # High-privilege administrator

class VulnerabilityType(str, Enum):
    BOLA_IDOR = "BOLA_IDOR"                     # Broken Object Level Authorization
    BFLA = "BFLA"                               # Broken Function Level Authorization
    MISSING_AUTH = "MISSING_AUTH"               # Unauthenticated access to private route
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION" # Vertical privilege escalation
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"         # Role tampering or unauthorized updates
    MULTI_STEP_CHAIN = "MULTI_STEP_CHAIN"       # Multi-endpoint chained vulnerability

class FindingStatus(str, Enum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"

class FindingClassification(str, Enum):
    """Strict lifecycle classification distinguishing static patterns from verified runtime findings."""
    DETECTED_CODE_PATTERN = "DETECTED_CODE_PATTERN"
    POTENTIAL_VULNERABILITY = "POTENTIAL_VULNERABILITY"
    CONFIRMED_RUNTIME_VULNERABILITY = "CONFIRMED_RUNTIME_VULNERABILITY"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    SUSPICIOUS_ACCESS = "SUSPICIOUS_ACCESS"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

---

## 2. Core Pydantic Schemas

### Scope Evaluation
```python
class ScopeCheckResult(BaseModel):
    is_allowed: bool = Field(..., description="Whether the request is strictly permitted")
    target_url: str = Field(..., description="Normalized URL checked")
    method: str = Field(default="GET", description="HTTP method evaluated")
    reason: str = Field(..., description="Approval or rejection explanation")
    normalized_host: str = Field(default="")
    normalized_port: int = Field(default=80)
    normalized_scheme: str = Field(default="http")
```

### HTTP Request & Response Models
```python
class RequestMetadata(BaseModel):
    method: str
    url: str
    role: str
    sanitized_headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    timestamp_utc: str

class HttpResponseModel(BaseModel):
    status_code: int = Field(..., description="HTTP response status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: str = Field(..., description="Response body content string (truncated if excessive)")
    json_data: Optional[Dict[str, Any]] = Field(None, description="Parsed JSON if applicable")
    response_time_ms: float = Field(..., description="Response latency in milliseconds")
    content_length: int = Field(0, description="Raw response byte length")
    is_truncated: bool = Field(False, description="True if response exceeded size boundaries")
    request_metadata: Optional[RequestMetadata] = None
```

### Authorization Comparison & Verdicts
```python
class AccessVerdict(str, Enum):
    ALLOWED_ACCESS = "ALLOWED_ACCESS"
    CORRECTLY_DENIED = "CORRECTLY_DENIED"
    SUSPICIOUS_ACCESS = "SUSPICIOUS_ACCESS"
    CONFIRMED_UNAUTHORIZED_ACCESS = "CONFIRMED_UNAUTHORIZED_ACCESS"

class RoleProbeOutcome(BaseModel):
    role: Role
    response: HttpResponseModel
    verdict: AccessVerdict
    comparison: Optional[ComparisonAnalysis] = None
    evidence: Optional[EvidenceArtifact] = None

class DifferentialResult(BaseModel):
    endpoint: str
    resolved_url: str = ""
    method: str = "GET"
    resource_id: Optional[str] = None
    owner_role: Role = Role.USER_A
    role_responses: Dict[Role, HttpResponseModel] = Field(default_factory=dict)
    probe_outcomes: Dict[Role, RoleProbeOutcome] = Field(default_factory=dict)
    overall_verdict: AccessVerdict = AccessVerdict.CORRECTLY_DENIED
    is_discrepancy_detected: bool = False
    is_confirmed: bool = False
    vulnerability_candidate: Optional[str] = None
    evidence_artifacts: List[EvidenceArtifact] = Field(default_factory=list)
    summary: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class VerifiedPromotionResult(BaseModel):
    """Result of runtime differential verification and potential promotion of a candidate finding."""
    finding_id: str
    target_endpoint: str
    http_method: str
    previous_classification: str
    new_classification: FindingClassification
    is_promoted: bool
    status: str
    validation_status: str
    summary: str
    owner_role: Role = Role.USER_A
    test_roles: List[Role] = Field(default_factory=list)
    reproduction_steps: List[str] = Field(default_factory=list)
    evidence: Optional[EvidenceArtifact] = None
    finding_record: Optional[FindingRecord] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    severity: SeverityLevel = SeverityLevel.HIGH
    recommended_fix: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
```

### Cross-File Static Analysis & Dependency Models
```python
class SymbolKind(str, Enum):
    FUNCTION = "FUNCTION"
    DECORATOR = "DECORATOR"
    DEPENDENCY = "DEPENDENCY"
    MIDDLEWARE = "MIDDLEWARE"
    ROUTER = "ROUTER"
    APP = "APP"
    CLASS = "CLASS"
    VARIABLE = "VARIABLE"

class ModuleSymbol(BaseModel):
    name: str
    kind: SymbolKind
    file_path: str
    module_name: str
    line_no: int = 1
    is_auth_related: bool = False
    auth_mechanisms: List[str] = Field(default_factory=list)
    docstring: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ModuleImport(BaseModel):
    source_module: str
    target_module: str
    imported_name: str
    alias: Optional[str] = None
    line_no: int = 1
    is_relative: bool = False
    relative_level: int = 0

class RouteSecurityContext(BaseModel):
    route_path: str
    http_method: str = "GET"
    file_path: str
    module_name: str
    function_name: str
    line_no: int = 1
    router_variable: Optional[str] = None
    router_prefix: str = ""
    decorators: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    in_body_calls: List[str] = Field(default_factory=list)
    resolved_auth_sources: List[str] = Field(default_factory=list)
    unresolved_symbols: List[str] = Field(default_factory=list)
    is_protected: bool = False
    has_uncertainty: bool = False
    uncertainty_reasons: List[str] = Field(default_factory=list)

class ProjectDependencyGraph(BaseModel):
    modules: Dict[str, str] = Field(default_factory=dict)
    reverse_modules: Dict[str, str] = Field(default_factory=dict)
    imports: List[ModuleImport] = Field(default_factory=list)
    symbols: Dict[str, List[ModuleSymbol]] = Field(default_factory=dict)
    routes: List[RouteSecurityContext] = Field(default_factory=list)
    router_prefixes: Dict[str, str] = Field(default_factory=dict)
    router_dependencies: Dict[str, List[str]] = Field(default_factory=dict)
    app_middlewares: List[str] = Field(default_factory=list)
    unresolved_imports: List[str] = Field(default_factory=list)
    analysis_uncertainties: List[str] = Field(default_factory=list)

class SourceFinding(BaseModel):
    finding_id: str
    rule_id: str
    vulnerability_category: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    source_type: str = "source_code"
    classification: FindingClassification = FindingClassification.POTENTIAL_VULNERABILITY
    validation_status: str = "POTENTIAL_VULNERABILITY"
    is_runtime_confirmed: bool = False
    file_path: str
    function_name: Optional[str] = None
    route_path: Optional[str] = None
    http_method: Optional[str] = None
    start_line: int
    end_line: int
    code_snippet: str
    detection_explanation: str
    detection_method: str
    remediation_hint: str = ""
```

### Evidence & Findings
```python
class EvidenceValidationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    REJECTED_FALSE_POSITIVE = "REJECTED_FALSE_POSITIVE"
    UNVALIDATED = "UNVALIDATED"

class EvidenceArtifact(BaseModel):
    id: str
    finding_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint: str
    http_method: str = "GET"
    test_role: Role
    authorized_role: Role
    resource_id: Optional[str] = None
    expected_behavior: str
    actual_behavior: str
    validation_status: EvidenceValidationStatus = EvidenceValidationStatus.CONFIRMED
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_status: int
    response_body: str
    sanitized_response_evidence: str
    evidence_sha256: str = Field(..., description="SHA-256 hash of normalized evidence bytes")
    redacted_tokens: List[str] = Field(default_factory=list)

class FindingRecord(BaseModel):
    id: str = Field(..., description="Unique finding UUID")
    scan_id: str = Field(..., description="Associated scan identifier")
    title: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    status: FindingStatus
    classification: Optional[str] = Field(default=None, description="Finding classification lifecycle state")
    target_endpoint: str
    http_method: str
    affected_roles: List[Role]
    description: str
    technical_details: Dict[str, Any]
    remediation_guidance: str
    evidence: EvidenceArtifact
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
```

### Retest Result
```python
class RetestResult(BaseModel):
    finding_id: str
    retest_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    previous_status: FindingStatus
    new_status: FindingStatus
    is_vulnerability_still_present: bool
    summary: str
    differential_result: DifferentialAnalysisResult
```

---

## 3. Core Function Interfaces

### 1. `check_scope` / `ScopeGuard.validate_request`
```python
def check_scope(url: str, method: str = "GET") -> ScopeCheckResult:
    """
    Validates whether a URL and HTTP method strictly conform to the authorized allowlist.
    Enforces host, port, protocol, method restrictions, and blocks loopback/metadata exploits.
    """
    ...

def assert_in_scope(url: str, method: str = "GET") -> None:
    """
    Asserts in-scope compliance. Raises ScopeViolationError, UnsupportedMethodError,
    or InvalidTargetURLError if rejected.
    """
    ...
```

### 2. `send_request`
```python
def send_request(
    role: Role | str = Role.ANONYMOUS,
    method: str = "GET",
    url: str = "",
    params: Optional[Dict[str, Any]] = None,
    custom_headers: Optional[Dict[str, str]] = None,
    json_body: Optional[Any] = None,
    timeout: Optional[float] = None,
    scope_guard: Optional[ScopeGuard] = None,
    session_manager: Optional[SessionManager] = None,
) -> HttpResponseModel:
    """
    Executes an in-scope HTTP request under the session context of the specified role.
    Strictly asserts scope via ScopeGuard prior to connection.
    Enforces timeout, max response boundaries, and follow_redirects=False.
    Sanitizes authentication tokens and cookies in request metadata.
    """
    ...
```

### 3. `compare_access`
```python
def compare_access(
    endpoint: str,
    method: str = "GET",
    resource_id: Optional[str] = None,
    owner_role: Role = Role.USER_A,
    roles_to_test: Optional[List[Role]] = None,
    executor: Optional[RequestExecutor] = None,
    session_manager: Optional[SessionManager] = None,
    scope_guard: Optional[ScopeGuard] = None,
) -> DifferentialResult:
    """
    Runs the same endpoint request across owner and test roles (e.g. User A vs User B / Anonymous)
    to detect authorization differentials indicating BOLA/IDOR, BFLA, or Missing Auth.
    Never treats HTTP 200 alone as proof of vulnerability.
    """
    ...
```

### 4. `create_and_sign_evidence` / `validate_artifact_completeness`
```python
def create_and_sign_evidence(
    finding_id: str,
    test_role: Role,
    authorized_role: Role,
    method: str,
    url: str,
    headers: Dict[str, str],
    response: HttpResponseModel,
    endpoint: Optional[str] = None,
    resource_id: Optional[str] = None,
    expected_behavior: Optional[str] = None,
    actual_behavior: Optional[str] = None,
    validation_status: EvidenceValidationStatus = EvidenceValidationStatus.CONFIRMED,
) -> EvidenceArtifact:
    """
    Sanitizes credentials in headers and response body, validates non-destructive proof,
    and generates an immutable SHA-256 checksum for the request/response pair.
    """
    ...
```

### 5. `analyze_finding`
```python
def analyze_finding(
    differential_result: DifferentialAnalysisResult
) -> Dict[str, Any]:
    """
    Invokes the AI agent's cognitive reasoning pipeline to analyze a differential
    discrepancy, synthesize the attack vector, assess severity, and produce a remediation patch.
    """
    ...
```

### 6. `save_finding`
```python
def save_finding(finding: FindingRecord) -> str:
    """
    Persists a verified FindingRecord and its corresponding EvidenceArtifact
    into the SQLite database. Returns the generated finding ID.
    """
    ...
```

### 7. `retest_finding`
```python
def retest_finding(finding_id: str) -> RetestResult:
    """
    Re-executes the exact non-destructive differential test sequence recorded in
    the finding's evidence artifact to determine if the vulnerability has been remediated.
    """
    ...
```

### 8. `AuthorizationTester.verify_potential_finding`
```python
def verify_potential_finding(
    candidate: Union[SourceFinding, FindingRecord, Dict[str, Any]],
    owner_role: Role = Role.USER_A,
    test_roles: Optional[List[Role]] = None,
    resource_id: Optional[str] = None,
) -> VerifiedPromotionResult:
    """
    Executes scoped runtime differential testing to verify potential authorization findings.
    Strictly promotes to CONFIRMED_RUNTIME_VULNERABILITY only when reproducible unauthorized
    access is proven with cryptographic evidence. Classifies denied access as NOT_REPRODUCIBLE,
    divergences as SUSPICIOUS_ACCESS, and unresolvable targets as INCONCLUSIVE.
    """
    ...
```

### 8. `AssessmentEngine.stream_assessment` & `AssessmentQueryAdapter` (Phase 3.5)
```python
class AssessmentEvent(BaseModel):
    assessment_id: str
    event_type: str
    stage: str
    message: str
    timestamp: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

def stream_assessment(
    target_url: str,
    cancel_token: Optional[CancellationToken] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Generator[AssessmentEvent, None, ScanSessionRecord]:
    """
    Executes a 7-stage security assessment against the target URL, yielding
    sanitized real-time AssessmentEvent objects and persisting session state,
    discovered endpoints, and signed findings in SQLite.
    """
    ...
```

### 9. FastAPI HTTP & Server-Sent Events (SSE) Endpoints
```python
# POST /api/assessments
# Request: {"target_url": "http://localhost:3000"}
# Response 201: {"assessment_id": "scan_...", "target_url": "...", "status": "PENDING"}

# GET /api/assessments/{assessment_id}/stream
# Content-Type: text/event-stream
# Event 1: event: activity\ndata: {"stage": "...", "message": "...", "status": "..."}\n\n
# Event 2: event: message\ndata: {"text": "Markdown text chunk...\n\n"}\n\n
# Event 3: event: done\ndata: {"status": "COMPLETED", "summary": "..."}\n\n

# GET /api/assessments/{assessment_id}
# Response 200: Full AssessmentSummaryResponse with stages, events, and markdown content

# POST /api/assessments/{assessment_id}/stop
# Response 200: {"status": "CANCELLING", "message": "Cancellation signal dispatched."}
```


