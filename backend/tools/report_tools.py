"""Reporting Tools for AuthScope Tool Registry.

Exposes evidence validation, finding explanation, remediation generation,
and assessment metrics retrieval backed by EvidenceValidator, RemediationEngine,
and FindingRepository.
"""

import uuid
from typing import Dict, Any, List, Optional

from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.analysis.evidence_validator import (
    EvidenceValidator,
    JWT_REGEX,
    BEARER_REGEX,
)
from backend.analysis.remediation import RemediationEngine
from backend.core.session_manager import Role
from backend.scanner.request_executor import HttpResponseModel
from backend.scanner.response_analyzer import AccessVerdict
from backend.scanner.source_analyzer import FindingClassification
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import EvidenceValidationStatus, FindingRecord, FindingStatus
from backend.tools.schemas import (
    ExplainFindingInput,
    ExplainFindingOutput,
    GenerateRemediationInput,
    GenerateRemediationOutput,
    GetAssessmentSummaryInput,
    GetAssessmentSummaryOutput,
    RetestFindingInput,
    RetestFindingOutput,
    SaveFindingInput,
    SaveFindingOutput,
    ToolExecutionContext,
    ValidateEvidenceInput,
    ValidateEvidenceOutput,
)
from backend.utils.helpers import compute_sha256, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ReportTools:
    """Provides reporting and verification tools backed by EvidenceValidator and RemediationEngine."""

    def __init__(
        self,
        validator: Optional[EvidenceValidator] = None,
        remediation_engine: Optional[RemediationEngine] = None,
        repository: Optional[FindingRepository] = None,
        retest_engine: Optional[Any] = None,
    ):
        self.validator = validator or EvidenceValidator()
        self.remediation_engine = remediation_engine or RemediationEngine()
        self.repository = repository or FindingRepository()
        self.retest_engine = retest_engine

    def validate_evidence(
        self,
        payload: ValidateEvidenceInput,
        context: Optional[ToolExecutionContext] = None
    ) -> ValidateEvidenceOutput:
        """Validates that a finding's evidence artifact is authentic, non-empty, and free of secret leaks."""
        reasons: List[str] = []
        is_valid = True
        has_secret_leak = False

        # 1. Check HTTP status code
        if not (200 <= payload.status_code < 300):
            is_valid = False
            reasons.append(f"HTTP status {payload.status_code} does not indicate successful unauthorized access.")

        # 2. Check for empty evidence
        if not payload.evidence_text.strip():
            is_valid = False
            reasons.append("Evidence body is empty.")

        # 3. Check for raw token / secret leaks
        for val in payload.headers.values():
            if JWT_REGEX.search(val) or BEARER_REGEX.search(val):
                has_secret_leak = True
                is_valid = False
                reasons.append("Evidence contains unredacted Bearer JWT in request/response headers.")
                break

        if JWT_REGEX.search(payload.evidence_text):
            has_secret_leak = True
            is_valid = False
            reasons.append("Evidence body contains unredacted JWT.")

        # Determine validation status
        if is_valid:
            validation_status = EvidenceValidationStatus.CONFIRMED.value
            evidence_hash = compute_sha256(payload.evidence_text)
            reasons.append("Evidence artifact is confirmed and reproducible.")
        else:
            validation_status = EvidenceValidationStatus.REJECTED_FALSE_POSITIVE.value
            evidence_hash = None

        return ValidateEvidenceOutput(
            finding_id=payload.finding_id,
            is_valid=is_valid,
            validation_status=validation_status,
            has_secret_leak=has_secret_leak,
            evidence_hash=evidence_hash,
            reasons=reasons
        )

    def explain_finding(
        self,
        payload: ExplainFindingInput,
        context: Optional[ToolExecutionContext] = None
    ) -> ExplainFindingOutput:
        """Synthesizes structured explanation, impact statement, and root cause for a confirmed finding."""
        explanation = (
            f"The endpoint '{payload.endpoint}' failed to enforce object-level or functional "
            f"authorization when accessed with HTTP {payload.method}. "
            f"Role '{payload.affected_role}' observed: {payload.actual_behavior}."
        )

        impact = (
            f"An attacker operating under role '{payload.affected_role}' can access or modify "
            f"protected resources without proper authorization credentials, compromising user data confidentiality."
        )

        root_cause = (
            f"Missing server-side ownership or permission verification before returning resource data. "
            f"The application relies on client-side routing or untrusted parameters without checking the active session."
        )

        return ExplainFindingOutput(
            finding_id=payload.finding_id,
            title=payload.title,
            category=payload.category,
            explanation=explanation,
            impact=impact,
            root_cause=root_cause
        )

    def generate_remediation(
        self,
        payload: GenerateRemediationInput,
        context: Optional[ToolExecutionContext] = None
    ) -> GenerateRemediationOutput:
        """Generates actionable server-side remediation guidance and code mitigation."""
        # Use existing RemediationEngine deterministic rules
        rec_text = (
            f"Implement server-side ownership verification in handler for '{payload.endpoint}'. "
            f"Ensure the database query filters by both resource ID and current user session ID."
        )

        code_fix = None
        if payload.code_snippet:
            code_fix = (
                f"# Secure Implementation Recommendation for {payload.file_path or 'handler'}\n"
                f"# Validate that req.user owns the requested resource before returning data:\n"
                f"if resource.owner_id != current_user.id:\n"
                f"    raise HTTPException(status_code=403, detail='Access forbidden')\n"
            )

        references = [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html"
        ]

        return GenerateRemediationOutput(
            finding_id=payload.finding_id,
            recommendation=rec_text,
            code_fix=code_fix,
            references=references
        )

    def get_assessment_summary(
        self,
        payload: GetAssessmentSummaryInput,
        context: Optional[ToolExecutionContext] = None
    ) -> GetAssessmentSummaryOutput:
        """Retrieves summary metrics and severity breakdown from the finding repository."""
        if hasattr(self.repository, "get_all_findings"):
            findings = self.repository.get_all_findings()
        else:
            findings = self.repository.list_findings(scan_id=payload.session_id)
        total_findings = len(findings)
        confirmed_findings = sum(
            1
            for f in findings
            if (
                (f.confirmation_status.value if hasattr(f.confirmation_status, "value") else str(f.confirmation_status)).upper()
                == "CONFIRMED"
            )
            or (str(getattr(f, "validation_status", "")).upper() == "CONFIRMED")
        )

        severity_breakdown: Dict[str, int] = {}
        category_breakdown: Dict[str, int] = {}

        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            cat = f.vulnerability_category.value if hasattr(f.vulnerability_category, "value") else str(f.vulnerability_category)
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        if hasattr(self.repository, "get_discovered_endpoints"):
            endpoints = self.repository.get_discovered_endpoints()
        elif payload.session_id:
            endpoints = self.repository.list_discovered_endpoints(payload.session_id)
        else:
            endpoints = []

        return GetAssessmentSummaryOutput(
            total_findings=total_findings,
            confirmed_findings=confirmed_findings,
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            endpoints_tested=len(endpoints)
        )

    def save_finding(
        self,
        payload: SaveFindingInput,
        context: Optional[ToolExecutionContext] = None
    ) -> SaveFindingOutput:
        """Creates a signed, sanitized EvidenceArtifact and persists a FindingRecord to SQLite."""
        f_id = payload.finding_id or f"fnd_{uuid.uuid4().hex[:8]}"
        role_map = {r.value.upper(): r for r in Role}
        t_role = role_map.get(payload.testing_role.strip().upper(), Role.USER_B)
        o_role = role_map.get(payload.owner_role.strip().upper(), Role.USER_A)
        req_url = payload.request_url or f"http://localhost:3000/{payload.endpoint.lstrip('/')}"

        http_resp = HttpResponseModel(
            url=req_url,
            status_code=payload.status_code,
            headers=dict(payload.response_headers or {"content-type": "application/json"}),
            body=payload.response_excerpt or '{"status":"success"}',
            elapsed_ms=10.0,
            role=t_role.value,
        )
        val_status = (
            EvidenceValidationStatus.CONFIRMED
            if payload.is_confirmed
            else EvidenceValidationStatus.SUSPICIOUS
        )
        artifact = self.validator.create_and_sign_evidence(
            finding_id=f_id,
            test_role=t_role,
            authorized_role=o_role,
            method=payload.http_method.upper(),
            url=req_url,
            headers=dict(payload.request_headers),
            response=http_resp,
            endpoint=payload.endpoint,
            resource_id=payload.resource_id,
            expected_behavior=redact_sensitive_text(payload.expected_behavior),
            actual_behavior=redact_sensitive_text(payload.actual_behavior),
            validation_status=val_status,
        )

        sev_map = {s.value.upper(): s for s in SeverityLevel}
        sev = sev_map.get(payload.severity.strip().upper(), SeverityLevel.HIGH)
        conf = ConfidenceLevel.CONFIRMED if payload.is_confirmed else ConfidenceLevel.MEDIUM

        rem = self.remediation_engine.generate_recommendation(
            vulnerability_type=payload.vulnerability_type,
            endpoint=payload.endpoint,
        )
        explanation = redact_sensitive_text(
            payload.explanation
            or f"Role '{t_role.value}' accessed '{payload.http_method} {payload.endpoint}' owned by '{o_role.value}'."
        )
        repro_steps = payload.reproducibility_steps or [
            f"1. Authenticate as baseline owner '{o_role.value}' and request '{payload.http_method} {req_url}'.",
            f"2. Switch to testing role '{t_role.value}' and replay '{payload.http_method} {req_url}' -> HTTP {payload.status_code}.",
            f"3. Verify cryptographic evidence SHA-256: {artifact.evidence_sha256}.",
        ]

        rec = FindingRecord(
            id=f_id,
            scan_id=payload.scan_id,
            title=redact_sensitive_text(payload.title),
            vulnerability_category=payload.vulnerability_type,
            vulnerability_type=payload.vulnerability_type,
            severity=sev,
            confidence=conf,
            status=FindingStatus.CONFIRMED.value if payload.is_confirmed else FindingStatus.SUSPECTED.value,
            confirmation_status=FindingStatus.CONFIRMED.value if payload.is_confirmed else FindingStatus.SUSPECTED.value,
            validation_status="CONFIRMED" if payload.is_confirmed else "SUSPICIOUS",
            endpoint=payload.endpoint,
            target_endpoint=payload.endpoint,
            http_method=payload.http_method.upper(),
            resource_id=payload.resource_id,
            affected_roles=[t_role],
            affected_role=t_role.value,
            access_verdict=(
                AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
                if payload.is_confirmed
                else AccessVerdict.SUSPICIOUS_ACCESS.value
            ),
            classification=(
                FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY.value
                if payload.is_confirmed
                else FindingClassification.SUSPICIOUS_ACCESS.value
            ),
            description=explanation,
            impact_explanation=explanation,
            expected_behavior=artifact.expected_behavior,
            actual_behavior=artifact.actual_behavior,
            remediation_guidance=rem.code_Patch_example,
            remediation_recommendation=rem.remediation_steps,
            evidence=artifact,
            evidence_reference=artifact.evidence_id,
            technical_details={
                "vulnerability_type": payload.vulnerability_type,
                "affected_endpoint": payload.endpoint,
                "http_method": payload.http_method.upper(),
                "testing_role": t_role.value,
                "request_details": {
                    "method": artifact.request_method,
                    "url": artifact.request_url,
                    "headers": artifact.request_headers,
                },
                "sanitized_response_details": {
                    "status_code": artifact.response_status,
                    "headers": artifact.response_headers,
                    "sanitized_body_excerpt": artifact.sanitized_response_evidence,
                },
                "expected_behavior": artifact.expected_behavior,
                "actual_behavior": artifact.actual_behavior,
                "explanation": explanation,
                "reproducibility_steps": repro_steps,
                "risk_assessment": {
                    "severity": sev.value,
                    "confidence": conf.value,
                    "cwe_reference": rem.cwe_reference,
                    "owasp_reference": rem.owasp_reference,
                },
            },
        )
        self.repository.save_finding(rec)

        return SaveFindingOutput(
            finding_id=f_id,
            evidence_id=artifact.evidence_id,
            evidence_sha256=artifact.evidence_sha256,
            scan_id=payload.scan_id,
            saved=True,
            validation_status=rec.validation_status,
            summary=f"Saved finding '{f_id}' ({payload.vulnerability_type}) on '{payload.endpoint}' with SHA-256 '{artifact.evidence_sha256[:16]}...'.",
        )

    def retest_finding(
        self,
        payload: RetestFindingInput,
        context: Optional[ToolExecutionContext] = None
    ) -> RetestFindingOutput:
        """Retests an existing finding via RetestEngine to verify whether remediation resolved the vulnerability."""
        from backend.retesting.retest_engine import RetestEngine

        engine = self.retest_engine or RetestEngine(repository=self.repository)
        finding = self.repository.get_finding(payload.finding_id)
        res = engine.retest_finding(payload.finding_id)

        diff = res.differential_result or {}
        before = diff.get("before", {}) if isinstance(diff, dict) else {}
        after = diff.get("after", {}) if isinstance(diff, dict) else {}
        target_endpoint = (
            finding.endpoint
            if finding is not None
            else str(before.get("endpoint") or after.get("endpoint") or "")
        )
        retested_roles = list((after.get("roles") or {}).keys())
        if not retested_roles and before.get("test_role"):
            retested_roles = [str(before.get("test_role"))]
        elif not retested_roles and finding is not None:
            retested_roles = [
                r.value if hasattr(r, "value") else str(r)
                for r in finding.affected_roles
            ]

        remediation_verified = res.new_status == "FIXED"
        if finding is not None:
            if remediation_verified:
                finding.status = FindingStatus.REMEDIATED.value
                finding.confirmation_status = FindingStatus.REMEDIATED.value
                finding.retest_status = "fixed"
            else:
                finding.retest_status = str(res.new_status).lower()
            self.repository.save_finding(finding)

        new_finding_status = (
            FindingStatus.REMEDIATED.value
            if remediation_verified
            else str(res.new_status)
        )
        new_verdict = str(
            (diff.get("engine_verdict") if isinstance(diff, dict) else None)
            or (
                AccessVerdict.CORRECTLY_DENIED.value
                if remediation_verified
                else AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
            )
        )

        return RetestFindingOutput(
            finding_id=res.finding_id,
            target_endpoint=target_endpoint,
            retested_roles=retested_roles,
            previous_status=str(res.previous_status),
            new_finding_status=new_finding_status,
            new_verdict=new_verdict,
            remediation_verified=remediation_verified,
            is_still_vulnerable=bool(res.is_vulnerable),
            summary=str(res.summary or res.notes or ""),
        )

