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
    is_allowed: bool = Field(..., description="Whether the target URL is strictly in-scope")
    target_url: str = Field(..., description="The normalized target URL being checked")
    reason: str = Field(..., description="Detailed explanation of allowance or rejection reason")
    normalized_host: str
    normalized_port: int
```

### HTTP Request & Response Models
```python
class HttpRequestModel(BaseModel):
    method: str = Field(..., description="HTTP Method (GET, POST, PUT, DELETE, etc.)")
    url: str = Field(..., description="Target full URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="Sanitized headers")
    params: Dict[str, Any] = Field(default_factory=dict, description="URL query parameters")
    body: Optional[Any] = Field(None, description="Request JSON or text body")
    role: Role = Field(default=Role.ANONYMOUS, description="Role context executing this request")

class HttpResponseModel(BaseModel):
    status_code: int = Field(..., description="HTTP response status code")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: str = Field(..., description="Response body content string (truncated if excessive)")
    json_data: Optional[Dict[str, Any]] = Field(None, description="Parsed JSON if applicable")
    response_time_ms: float = Field(..., description="Response latency in milliseconds")
```

### Authorization Comparison
```python
class RoleExecutionResult(BaseModel):
    role: Role
    request: HttpRequestModel
    response: HttpResponseModel
    is_success: bool = Field(..., description="Whether the request succeeded (2xx)")

class DifferentialAnalysisResult(BaseModel):
    endpoint: str
    method: str
    role_results: Dict[Role, RoleExecutionResult]
    is_discrepancy_detected: bool = Field(..., description="True if unauthorized access occurred")
    suspected_vulnerability: Optional[VulnerabilityType] = None
    summary: str
```

### Evidence & Findings
```python
class EvidenceArtifact(BaseModel):
    evidence_id: str
    finding_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    test_role: Role
    authorized_role: Role
    raw_request: HttpRequestModel
    raw_response: HttpResponseModel
    redacted_fields: List[str] = Field(default_factory=list)
    evidence_sha256: str = Field(..., description="SHA-256 hash of normalized evidence bytes")

class FindingRecord(BaseModel):
    id: str = Field(..., description="Unique finding UUID")
    scan_id: str = Field(..., description="Associated scan identifier")
    title: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    status: FindingStatus
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

### 1. `check_scope`
```python
def check_scope(url: str) -> ScopeCheckResult:
    """
    Validates whether a URL strictly conforms to the authorized target allowlist.
    Enforces host, port, protocol, and loopback/private IP restrictions.
    """
    ...
```

### 2. `send_request`
```python
def send_request(
    method: str,
    url: str,
    role: Role = Role.ANONYMOUS,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Any] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> HttpResponseModel:
    """
    Executes an in-scope HTTP request under the session context of the specified role.
    Strictly asserts scope via ScopeGuard prior to connection.
    Enforces timeout and follow_redirects=False.
    """
    ...
```

### 3. `compare_access`
```python
def compare_access(
    endpoint: str,
    method: str,
    param_matrix: Optional[Dict[str, Any]] = None,
    roles_to_test: Optional[List[Role]] = None
) -> DifferentialAnalysisResult:
    """
    Runs the same endpoint request across multiple roles (e.g. User A, User B, Anonymous)
    to detect authorization differentials indicating IDOR or privilege escalation.
    """
    ...
```

### 4. `validate_evidence`
```python
def validate_evidence(
    finding_id: str,
    test_role: Role,
    authorized_role: Role,
    request: HttpRequestModel,
    response: HttpResponseModel
) -> EvidenceArtifact:
    """
    Sanitizes credentials, validates non-destructive proof, and generates an
    immutable SHA-256 checksum for the request/response pair.
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

