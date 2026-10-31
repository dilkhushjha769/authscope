"""Pydantic schemas and typed data contracts for the AuthScope AI Analysis Module.

These schemas define the boundaries, evidence packages, analysis inputs,
cognitive findings, severity scores, and remediation recommendations.
Strict validation rules enforce that unvalidated evidence can never be
confirmed by AI opinion alone.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ==============================================================================
# Enumerations
# ==============================================================================


class ValidationStatus(str, Enum):
    """Validation states for security evidence."""
    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"


class ValidationMethod(str, Enum):
    """Techniques used to verify evidence reproducibility and authenticity."""
    DIFFERENTIAL_ANALYSIS = "differential_analysis"
    CRYPTOGRAPHIC_HASH = "cryptographic_hash"
    STATUS_CODE_ASSERTION = "status_code_assertion"
    RESPONSE_PAYLOAD_DIFF = "response_payload_diff"
    MANUAL_VERIFICATION = "manual_verification"
    RETEST_CONFIRMATION = "retest_confirmation"


class EvidenceType(str, Enum):
    """Categorization of collected security evidence."""
    HTTP_TRANSACTION = "http_transaction"
    DIFFERENTIAL_RESPONSE = "differential_response"
    STATUS_MISMATCH = "status_mismatch"
    PAYLOAD_LEAK = "payload_leak"
    TOKEN_LEAK = "token_leak"
    ACCESS_CONTROL_BYPASS = "access_control_bypass"


class ConfirmationStatus(str, Enum):
    """Lifecycle confirmation state of a security finding."""
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    UNCONFIRMED = "unconfirmed"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"

    @classmethod
    def _missing_(cls, value: object) -> Optional["ConfirmationStatus"]:
        if isinstance(value, str):
            normalized = value.strip().lower()
            for member in cls:
                if member.value == normalized:
                    return member
        return None


class ConfidenceLevel(str, Enum):
    """Level of confidence in vulnerability existence and impact."""
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def _missing_(cls, value: object) -> Optional["ConfidenceLevel"]:
        if isinstance(value, str):
            normalized = value.strip().upper()
            for member in cls:
                if member.value == normalized:
                    return member
        return None


class SeverityLevel(str, Enum):
    """Standardized severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def _missing_(cls, value: object) -> Optional["SeverityLevel"]:
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized in ("INFORMATIONAL", "INFO"):
                return cls.INFORMATIONAL
            for member in cls:
                if member.value == normalized:
                    return member
        return None


class ExploitabilityLevel(str, Enum):
    """Assessment of ease of vulnerability exploitation."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DataSensitivityLevel(str, Enum):
    """Classification of data exposed or affected."""
    CREDENTIALS = "CREDENTIALS"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    INTERNAL_CONFIDENTIAL = "INTERNAL_CONFIDENTIAL"
    LOW_SENSITIVITY = "LOW_SENSITIVITY"
    PUBLIC = "PUBLIC"


class PrivilegeGainedLevel(str, Enum):
    """Level of unauthorized privilege attained via the exploit."""
    NONE = "NONE"
    HORIZONTAL_USER = "HORIZONTAL_USER"
    VERTICAL_ADMIN = "VERTICAL_ADMIN"
    SYSTEM_ROOT = "SYSTEM_ROOT"


class VulnerabilityCategory(str, Enum):
    """Standard authorization vulnerability classes."""
    BOLA_IDOR = "BOLA_IDOR"
    BFLA = "BFLA"
    MISSING_AUTH = "MISSING_AUTH"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    MULTI_STEP_CHAIN = "MULTI_STEP_CHAIN"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"


class AnalysisStatus(str, Enum):
    """Status of the automated AI analysis run."""
    COMPLETED = "completed"
    REQUIRES_FURTHER_TESTING = "requires_further_testing"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    REJECTED = "rejected"


# ==============================================================================
# Core Schema Models
# ==============================================================================


class SecurityEvidence(BaseModel):
    """Represents an item of empirical security evidence collected during testing."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    evidence_id: str = Field(..., min_length=1, description="Unique identifier for the evidence artifact")
    evidence_type: EvidenceType = Field(..., description="Type of evidence collected")
    description: str = Field(..., min_length=1, description="Human-readable description of what this evidence captures")
    source_component: str = Field(..., min_length=1, description="Source component that captured this evidence (e.g., AuthorizationTester)")
    affected_endpoint: str = Field(..., min_length=1, description="Target endpoint or URI affected")
    http_method: Optional[str] = Field(None, description="HTTP method (GET, POST, etc.) if applicable")
    observed_behavior: str = Field(..., min_length=1, description="Empirical behavior observed (e.g., HTTP 200 returned User A cart)")
    expected_behavior: str = Field(..., min_length=1, description="Secure baseline behavior expected (e.g., HTTP 403 Forbidden)")
    validation_status: ValidationStatus = Field(..., description="Trust validation status of this evidence")
    supporting_evidence_refs: List[str] = Field(default_factory=list, description="IDs or references to supporting artifacts/hashes")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of evidence capture in UTC")

    @field_validator("http_method")
    @classmethod
    def normalize_http_method(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_clean = v.strip().upper()
            allowed = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
            if v_clean not in allowed:
                raise ValueError(f"Unsupported HTTP method: {v}. Must be one of {allowed}")
            return v_clean
        return None


class AffectedResource(BaseModel):
    """Identifies the resource, entity, or application boundary impacted by the vulnerability."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    resource_id: str = Field(..., min_length=1, description="Target resource identifier (e.g. basket_id_1, /api/Users)")
    resource_type: str = Field(..., min_length=1, description="Resource classification (e.g. API_ENDPOINT, DATA_RECORD, USER_OBJECT)")
    endpoint: str = Field(..., min_length=1, description="Endpoint path or URI exposing the resource")
    application_name: str = Field(default="OWASP Juice Shop", description="Name of the affected target application")
    parameters: List[str] = Field(default_factory=list, description="Path or query parameter keys involved (e.g. ['id'])")
    owner_identity: Optional[str] = Field(None, description="Legitimate owner identity (e.g., user_a)")
    unauthorized_accessors: List[str] = Field(default_factory=list, description="Roles/identities able to access this resource without authorization")


class EvidenceValidation(BaseModel):
    """Metadata asserting the independent technical validation of evidence."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    is_validated: bool = Field(..., description="Whether the evidence has been independently confirmed via technical validation")
    validation_method: ValidationMethod = Field(..., description="Technical method used to validate the evidence")
    validation_status: ValidationStatus = Field(..., description="Validation status outcome")
    validation_notes: Optional[str] = Field(None, description="Technical notes explaining the validation outcome")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="List of evidence IDs verified by this check")

    @model_validator(mode="after")
    def verify_consistency(self) -> "EvidenceValidation":
        if self.validation_status == ValidationStatus.VALIDATED and not self.is_validated:
            raise ValueError("Inconsistent validation: validation_status is 'validated' but is_validated is False.")
        if self.validation_status != ValidationStatus.VALIDATED and self.is_validated:
            raise ValueError(f"Inconsistent validation: is_validated cannot be True when validation_status is '{self.validation_status.value}'.")
        return self


class FindingAnalysisInput(BaseModel):
    """Strict input contract provided to the AI Finding Analyzer."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(..., min_length=1, description="Unique identifier for the candidate finding")
    vulnerability_category: VulnerabilityCategory = Field(..., description="Suspected category of authorization flaw")
    security_evidence: List[SecurityEvidence] = Field(..., min_length=1, description="Empirical evidence artifacts collected by security engine")
    affected_resource: AffectedResource = Field(..., description="Resource or endpoint target being analyzed")
    user_role_context: Optional[str] = Field(None, description="User role context under test (e.g., user_b, admin, anonymous)")
    testing_context: Dict[str, Any] = Field(default_factory=dict, description="Metadata regarding testing conditions and parameters")
    scope_info: Optional[Dict[str, Any]] = Field(None, description="Scope boundary details asserting in-scope target execution")
    evidence_validation: Optional[EvidenceValidation] = Field(None, description="Independent validation metadata from security engine")


class FindingAnalysis(BaseModel):
    """Detailed reasoning and narrative breakdown of an analyzed security finding."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    title: str = Field(..., min_length=5, description="Clear, concise finding title")
    vulnerability_explanation: str = Field(..., min_length=10, description="Detailed explanation of the authorization flaw")
    technical_root_cause: str = Field(..., min_length=10, description="Technical explanation of the flaw's root cause in application logic")
    affected_resources: List[AffectedResource] = Field(..., min_length=1, description="List of resources affected by this finding")
    potential_impact: str = Field(..., min_length=10, description="Exploration of business, data, and operational impacts")
    supporting_evidence: List[SecurityEvidence] = Field(..., min_length=1, description="Evidence items that substantiate this finding")
    confidence_level: ConfidenceLevel = Field(..., description="Confidence rating in the finding's accuracy")
    confirmation_status: ConfirmationStatus = Field(..., description="Confirmation lifecycle status")
    limitations_and_missing_info: List[str] = Field(default_factory=list, description="Any gaps, assumptions, or missing data points")

    @model_validator(mode="after")
    def enforce_grounded_confirmation(self) -> "FindingAnalysis":
        """Anti-hallucination guardrail:

        A finding can NEVER be marked as CONFIRMED unless all supporting evidence
        items are independently verified with validation_status == VALIDATED.
        """
        if self.confirmation_status == ConfirmationStatus.CONFIRMED:
            if not self.supporting_evidence:
                raise ValueError(
                    "Cannot mark finding as CONFIRMED without supporting evidence."
                )
            unvalidated = [
                e.evidence_id
                for e in self.supporting_evidence
                if e.validation_status != ValidationStatus.VALIDATED
            ]
            if unvalidated:
                raise ValueError(
                    f"AI Guardrail Violation: Cannot mark finding as CONFIRMED because "
                    f"supporting evidence {unvalidated} has not been independently validated. "
                    f"Confirmation must be determined using trusted validation metadata, not model opinion."
                )
        return self


class SeverityAssessment(BaseModel):
    """Objective risk and impact assessment based on CVSS 3.1 criteria and data sensitivity."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    severity: SeverityLevel = Field(..., description="Overall severity rating")
    exploitability: ExploitabilityLevel = Field(..., description="Ease of exploitation assessment")
    data_sensitivity: DataSensitivityLevel = Field(..., description="Sensitivity of impacted data")
    privilege_gained: PrivilegeGainedLevel = Field(..., description="Privilege escalation consequence")
    potential_impact: str = Field(..., min_length=10, description="Narrative analysis of real-world exploitation impact")
    severity_rationale: str = Field(..., min_length=10, description="Justification for the chosen severity rating")
    confidence: ConfidenceLevel = Field(..., description="Confidence in this severity calculation")
    contributing_factors: List[str] = Field(default_factory=list, description="Factors directly contributing to the severity rating")

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            clean = v.strip().upper()
            if clean in ("INFO", "INFORMATIONAL"):
                return SeverityLevel.INFORMATIONAL
            for member in SeverityLevel:
                if member.value == clean or member.name == clean:
                    return member
        return v


class RemediationRecommendation(BaseModel):
    """Actionable mitigation guidance and technical remediation patch instructions."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    recommended_fix: str = Field(..., min_length=10, description="High-level description of the recommended architectural fix")
    technical_implementation_guidance: str = Field(..., min_length=15, description="Concrete developer implementation steps and code guidance")
    server_side_controls: List[str] = Field(..., min_length=1, description="Server-side controls to enforce (e.g. ownership check middleware)")
    why_fix_works: str = Field(..., min_length=10, description="Explanation of how the proposed control mitigates the vulnerability")
    retesting_procedure: str = Field(..., min_length=10, description="Step-by-step procedure to re-verify whether the flaw is remediated")
    regression_testing_recommendations: List[str] = Field(default_factory=list, description="Recommended tests to prevent authorization regressions")


class FindingAnalysisOutput(BaseModel):
    """Unified output structure synthesized by the AI Analysis Module."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    analysis: FindingAnalysis = Field(..., description="Cognitive finding analysis and narrative breakdown")
    severity_assessment: SeverityAssessment = Field(..., description="CVSS and sensitivity-based severity assessment")
    remediation_recommendation: RemediationRecommendation = Field(..., description="Technical remediation guidance and patch")
    evidence_references: List[str] = Field(..., min_length=1, description="List of evidence IDs backing this complete analysis")
    overall_status: AnalysisStatus = Field(..., description="Overall state of the analysis operation")
    warnings_or_limitations: List[str] = Field(default_factory=list, description="Operational warnings or scope limitations")

    @model_validator(mode="after")
    def verify_consistency_and_references(self) -> "FindingAnalysisOutput":
        # Ensure all referenced evidence IDs exist in the nested analysis supporting evidence
        supporting_ids = {e.evidence_id for e in self.analysis.supporting_evidence}
        for ref in self.evidence_references:
            if ref not in supporting_ids:
                raise ValueError(
                    f"Evidence reference '{ref}' is not listed in the analysis supporting_evidence list."
                )
        return self

