"""Authorization-Differential Tester: Multi-Role Access Comparison Engine.

Executes identical non-destructive GET test vectors under legitimate owner accounts
(e.g. User A or Admin) and unauthorized test accounts (e.g. User B or Anonymous)
to detect Broken Access Control (BOLA/IDOR, BFLA, Missing Authentication).

Adheres strictly to evidence-driven verification:
- Never treats HTTP 200 alone as proof of vulnerability.
- Validates resource ownership, JSON structure, and sensitive field exposure.
- Never invents sessions or resource ownership.
- Enforces ScopeGuard, rate limits, and human approval boundaries.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
import time
import uuid
from pydantic import BaseModel, Field

from backend.config import settings
from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.endpoint_discovery import (
    DiscoveredEndpoint,
    EndpointCategory,
    EndpointDiscovery,
    TEMPLATE_PARAM_REGEX,
)
from backend.scanner.request_executor import RequestExecutor, HttpResponseModel
from backend.scanner.response_analyzer import (
    AccessVerdict,
    ComparisonAnalysis,
    ResponseAnalyzer,
)
from backend.analysis.evidence_validator import (
    EvidenceArtifact,
    EvidenceValidationStatus,
    EvidenceValidator,
)
from backend.scanner.source_analyzer import FindingClassification, SourceFinding
from backend.storage.models import FindingRecord, FindingStatus
from backend.utils.helpers import (
    HumanApprovalRequiredError,
    InvalidTargetURLError,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class RoleProbeOutcome(BaseModel):
    """Detailed outcome for a single role tested against an endpoint."""
    role: Role
    response: HttpResponseModel
    verdict: AccessVerdict
    comparison: Optional[ComparisonAnalysis] = None
    evidence: Optional[EvidenceArtifact] = None


class DifferentialResult(BaseModel):
    """Structured result of multi-role authorization-differential testing on an endpoint."""
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
    """Result of runtime verification and potential promotion of a candidate finding.

    Strictly satisfies:
    - Affected endpoint and HTTP method.
    - Relevant authentication roles.
    - Request and response evidence with sensitive data redacted.
    - Expected versus actual authorization behavior.
    - Reproduction steps.
    - Confidence and risk rating.
    - Recommended fix.
    """
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


class AuthorizationTester:
    """Coordinates differential execution and evidence validation across isolated roles."""

    def __init__(
        self,
        executor: Optional[RequestExecutor] = None,
        session_manager: Optional[SessionManager] = None,
        scope_guard: Optional[ScopeGuard] = None,
        base_url: str = settings.target_base_url,
        min_request_interval_ms: float = 0.0,
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager()
        self.executor = executor or RequestExecutor(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager
        )
        self.analyzer = ResponseAnalyzer()
        self.evidence_validator = EvidenceValidator()
        self.discovery = EndpointDiscovery(base_url=base_url, scope_guard=self.scope_guard)
        self.min_request_interval_ms = min_request_interval_ms
        self._last_request_ts: float = 0.0

    def _apply_rate_limit(self) -> None:
        """Applies configured request rate limiting between probes."""
        if self.min_request_interval_ms <= 0:
            return
        now = time.monotonic()
        elapsed_ms = (now - self._last_request_ts) * 1000.0
        if self._last_request_ts > 0 and elapsed_ms < self.min_request_interval_ms:
            sleep_sec = (self.min_request_interval_ms - elapsed_ms) / 1000.0
            time.sleep(sleep_sec)
        self._last_request_ts = time.monotonic()

    def _resolve_target_endpoint(
        self,
        endpoint: DiscoveredEndpoint | str,
        method: str = "GET",
        resource_id: Optional[str] = None,
        owner_role: Role = Role.USER_A,
        human_approved: bool = False,
    ) -> Tuple[DiscoveredEndpoint, str, Optional[str]]:
        """Normalizes endpoint metadata, resolves resource ID without inventing ownership, and validates scope."""
        if isinstance(endpoint, DiscoveredEndpoint):
            disc_ep = endpoint
        else:
            raw_str = str(endpoint).strip()
            if raw_str.startswith(("http://", "https://")):
                # Validate full URL against ScopeGuard first
                self.scope_guard.assert_in_scope(raw_str, method=method)
                rel_path = raw_str[len(self.discovery.base_url):] if raw_str.startswith(self.discovery.base_url) else raw_str
                disc_ep = self.discovery.register_endpoint(path=rel_path, method=method)
            else:
                disc_ep = self.discovery.register_endpoint(path=raw_str, method=method)

        if disc_ep.requires_human_approval and not human_approved:
            raise HumanApprovalRequiredError(
                f"Testing endpoint '{disc_ep.path}' with method '{disc_ep.method}' requires explicit human approval."
            )

        # Resolve resource_id: explicit -> extracted from concrete URL -> registered on owner session
        effective_res_id = resource_id or disc_ep.extracted_resource_id
        if not effective_res_id and TEMPLATE_PARAM_REGEX.search(disc_ep.path):
            owner_session = self.session_manager.get_session(owner_role)
            if disc_ep.resource_type:
                owned_set = owner_session.owned_resources.get(disc_ep.resource_type.lower(), set())
                if owned_set:
                    effective_res_id = sorted(owned_set)[0]

            if not effective_res_id:
                raise InvalidTargetURLError(
                    f"Endpoint '{disc_ep.path}' requires a concrete resource identifier owned by "
                    f"'{owner_role.value}', but none was provided or registered. AuthScope never invents resource ownership."
                )

        resolved_url = self.discovery.build_concrete_url(disc_ep, resource_id=effective_res_id)
        return disc_ep, resolved_url, effective_res_id

    @staticmethod
    def _classify_vulnerability_type(
        endpoint: DiscoveredEndpoint,
        test_role: Role
    ) -> str:
        """Determines the specific authorization vulnerability classification."""
        if test_role == Role.ANONYMOUS and endpoint.requires_auth:
            if endpoint.category == EndpointCategory.USER_OBJECT:
                return "BOLA_IDOR"
            return "MISSING_AUTH"
        if endpoint.category == EndpointCategory.ADMIN_FUNCTION:
            return "BFLA"
        if endpoint.category == EndpointCategory.USER_OBJECT or endpoint.requires_owner_match:
            return "BOLA_IDOR"
        return "BROKEN_ACCESS_CONTROL"

    def test_resource_access(
        self,
        endpoint: DiscoveredEndpoint | str,
        owner_role: Role = Role.USER_A,
        test_roles: Optional[List[Role]] = None,
        resource_id: Optional[str] = None,
        method: str = "GET",
        human_approved: bool = False,
    ) -> DifferentialResult:
        """Executes a full authorization-differential test on an endpoint.

        Workflow:
        1. Validates scope, method, and human approval boundaries.
        2. Verifies required sessions are authenticated in SessionManager.
        3. Requests the resource using the legitimate `owner_role` and records baseline.
        4. Requests the same resource using each `test_role` (e.g. User B, Anonymous).
        5. Compares responses via ResponseAnalyzer (status, JSON structure, ownership, sensitive fields).
        6. Validates and signs cryptographic EvidenceArtifact for suspicious or confirmed findings.
        """
        disc_ep, resolved_url, effective_res_id = self._resolve_target_endpoint(
            endpoint=endpoint,
            method=method,
            resource_id=resource_id,
            owner_role=owner_role,
            human_approved=human_approved,
        )

        # Default comparison roles depending on endpoint category
        if test_roles is None:
            if disc_ep.category == EndpointCategory.ADMIN_FUNCTION:
                test_roles = [Role.USER_A, Role.ANONYMOUS]
            else:
                test_roles = [r for r in (Role.USER_B, Role.ANONYMOUS) if r != owner_role]

        # Ensure owner and all test roles have valid sessions before making requests
        owner_session = self.session_manager.require_authenticated_session(owner_role)
        for trole in test_roles:
            self.session_manager.require_authenticated_session(trole)

        logger.info(
            "Starting authorization-differential test",
            extra={
                "endpoint": disc_ep.path,
                "resolved_url": resolved_url,
                "owner_role": owner_role.value,
                "test_roles": [r.value for r in test_roles],
                "resource_id": effective_res_id,
            }
        )

        role_responses: Dict[Role, HttpResponseModel] = {}
        probe_outcomes: Dict[Role, RoleProbeOutcome] = {}
        evidence_list: List[EvidenceArtifact] = []

        # Step 1: Request resource using legitimate owner
        self._apply_rate_limit()
        owner_resp = self.executor.send_request(
            role=owner_role,
            method=disc_ep.method,
            url=resolved_url,
        )
        role_responses[owner_role] = owner_resp
        owner_insp = self.analyzer.inspect_response(owner_resp)
        owner_verdict = (
            AccessVerdict.ALLOWED_ACCESS
            if (owner_insp.is_http_success and not owner_insp.is_empty_payload and not owner_insp.is_spa_html_fallback)
            else AccessVerdict.CORRECTLY_DENIED
        )
        probe_outcomes[owner_role] = RoleProbeOutcome(
            role=owner_role,
            response=owner_resp,
            verdict=owner_verdict,
        )

        # Step 2: Probe same resource across each unauthorized / peer test role
        overall_verdict = AccessVerdict.CORRECTLY_DENIED
        is_discrepancy = False
        is_confirmed = False
        vuln_candidate: Optional[str] = None
        summary_parts: List[str] = []

        for trole in test_roles:
            self._apply_rate_limit()
            test_session = self.session_manager.require_authenticated_session(trole)
            test_resp = self.executor.send_request(
                role=trole,
                method=disc_ep.method,
                url=resolved_url,
            )
            role_responses[trole] = test_resp

            # Check whether this role is legitimately expected to have access
            role_allowed_by_policy = (
                disc_ep.category == EndpointCategory.PUBLIC
                or (trole in disc_ep.expected_allowed_roles and not disc_ep.requires_owner_match)
                or (trole == owner_role)
                or (
                    disc_ep.requires_owner_match
                    and disc_ep.resource_type
                    and effective_res_id
                    and test_session.owns_resource(disc_ep.resource_type, effective_res_id)
                )
            )

            comparison = self.analyzer.compare_responses(
                owner_response=owner_resp,
                test_response=test_resp,
                expected_resource_id=effective_res_id,
                owner_user_id=owner_session.user_id,
                owner_email=owner_session.email,
                test_user_id=test_session.user_id,
                test_email=test_session.email,
                is_test_role_expected_allowed=role_allowed_by_policy,
            )

            artifact: Optional[EvidenceArtifact] = None
            final_role_verdict = comparison.verdict

            if comparison.verdict in (
                AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS,
                AccessVerdict.SUSPICIOUS_ACCESS,
            ):
                val_status = (
                    EvidenceValidationStatus.CONFIRMED
                    if comparison.verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
                    else EvidenceValidationStatus.SUSPICIOUS
                )
                expected_desc = (
                    f"Role '{trole.value}' must be denied access (HTTP 401/403) to "
                    f"{disc_ep.resource_type or 'resource'} '{effective_res_id or disc_ep.path}' "
                    f"owned by '{owner_role.value}'."
                )
                actual_desc = (
                    f"Role '{trole.value}' received HTTP {test_resp.status_code} "
                    f"(similarity={comparison.similarity_ratio:.2f}, "
                    f"sensitive_fields={comparison.sensitive_fields_exposed}). "
                    + " ".join(comparison.reasons)
                )

                artifact = self.evidence_validator.create_and_sign_evidence(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    test_role=trole,
                    authorized_role=owner_role,
                    method=disc_ep.method,
                    url=resolved_url,
                    headers=test_session.get_headers(),
                    response=test_resp,
                    endpoint=disc_ep.path,
                    resource_id=effective_res_id,
                    expected_behavior=expected_desc,
                    actual_behavior=actual_desc,
                    validation_status=val_status,
                )

                # Never mark a finding confirmed unless evidence passes completeness validation
                if not self.evidence_validator.validate_artifact_completeness(artifact):
                    artifact.validation_status = EvidenceValidationStatus.SUSPICIOUS
                    final_role_verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    comparison.verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    comparison.is_confirmed = False

                evidence_list.append(artifact)
                is_discrepancy = True

                if final_role_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS:
                    is_confirmed = True
                    overall_verdict = AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
                    vuln_candidate = self._classify_vulnerability_type(disc_ep, trole)
                elif overall_verdict != AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS:
                    overall_verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    if not vuln_candidate:
                        vuln_candidate = self._classify_vulnerability_type(disc_ep, trole)

            elif final_role_verdict == AccessVerdict.ALLOWED_ACCESS and overall_verdict == AccessVerdict.CORRECTLY_DENIED:
                overall_verdict = AccessVerdict.ALLOWED_ACCESS

            probe_outcomes[trole] = RoleProbeOutcome(
                role=trole,
                response=test_resp,
                verdict=final_role_verdict,
                comparison=comparison,
                evidence=artifact,
            )
            summary_parts.append(f"[{trole.value}: {final_role_verdict.value}]")

        summary_str = (
            f"Endpoint {disc_ep.method} {disc_ep.path} (resource_id={effective_res_id}): "
            f"owner={owner_role.value} (HTTP {owner_resp.status_code}) -> "
            + ", ".join(summary_parts)
        )

        return DifferentialResult(
            endpoint=disc_ep.path,
            resolved_url=resolved_url,
            method=disc_ep.method,
            resource_id=effective_res_id,
            owner_role=owner_role,
            role_responses=role_responses,
            probe_outcomes=probe_outcomes,
            overall_verdict=overall_verdict,
            is_discrepancy_detected=is_discrepancy,
            is_confirmed=is_confirmed,
            vulnerability_candidate=vuln_candidate,
            evidence_artifacts=evidence_list,
            summary=summary_str,
        )

    def test_endpoint(
        self,
        endpoint_url: str,
        method: str = "GET",
        roles: Optional[List[Role]] = None,
        owner_role: Role = Role.USER_A,
        resource_id: Optional[str] = None,
    ) -> DifferentialResult:
        """Executes the test vector across roles and analyzes access differentials."""
        test_roles = [r for r in (roles or [Role.USER_B, Role.ANONYMOUS]) if r != owner_role]
        return self.test_resource_access(
            endpoint=endpoint_url,
            owner_role=owner_role,
            test_roles=test_roles,
            resource_id=resource_id,
            method=method,
        )

    def verify_potential_finding(
        self,
        candidate: Union[SourceFinding, FindingRecord, Dict[str, Any]],
        owner_role: Role = Role.USER_A,
        test_roles: Optional[List[Role]] = None,
        resource_id: Optional[str] = None,
    ) -> VerifiedPromotionResult:
        """Verifies a potential vulnerability candidate through scoped runtime differential testing.

        STRICT PROMOTION RULE:
        Only AuthorizationTester can promote a POTENTIAL_VULNERABILITY to
        CONFIRMED_RUNTIME_VULNERABILITY, and only when non-destructive differential HTTP testing
        demonstrates reproducible unauthorized access with cryptographic evidence.

        - If reproducible unauthorized access is confirmed -> CONFIRMED_RUNTIME_VULNERABILITY
        - If server properly denies unauthorized access (401/403) -> NOT_REPRODUCIBLE
        - If behavioral divergence without confirmed sensitive data access -> SUSPICIOUS_ACCESS
        - If target cannot be safely tested or is out of scope -> INCONCLUSIVE
        """
        # 1. Extract endpoint, method, and candidate metadata
        if hasattr(candidate, "target_endpoint") and candidate.target_endpoint:
            endpoint = candidate.target_endpoint
        elif hasattr(candidate, "endpoint") and candidate.endpoint:
            endpoint = candidate.endpoint
        elif hasattr(candidate, "route_path") and candidate.route_path:
            endpoint = candidate.route_path
        elif isinstance(candidate, dict):
            endpoint = candidate.get("target_endpoint") or candidate.get("endpoint") or candidate.get("route_path") or ""
        else:
            endpoint = ""

        if hasattr(candidate, "http_method") and candidate.http_method:
            method = candidate.http_method
        elif isinstance(candidate, dict):
            method = candidate.get("http_method", "GET")
        else:
            method = "GET"

        finding_id = (
            getattr(candidate, "finding_id", None)
            or getattr(candidate, "id", None)
            or (candidate.get("finding_id") or candidate.get("id") if isinstance(candidate, dict) else None)
            or f"fnd_{uuid.uuid4().hex[:8]}"
        )

        prev_class_raw = (
            getattr(candidate, "classification", None)
            or (candidate.get("classification") if isinstance(candidate, dict) else None)
            or "POTENTIAL_VULNERABILITY"
        )
        prev_class = prev_class_raw.value if hasattr(prev_class_raw, "value") else str(prev_class_raw)

        category = (
            getattr(candidate, "vulnerability_category", None)
            or getattr(candidate, "vulnerability_type", None)
            or (candidate.get("vulnerability_category") or candidate.get("vulnerability_type") if isinstance(candidate, dict) else None)
            or "BROKEN_ACCESS_CONTROL"
        )

        effective_roles = [r for r in (test_roles or [Role.USER_B, Role.ANONYMOUS]) if r != owner_role]

        # 2. Reject pure source code locations without an exposed HTTP endpoint
        if not endpoint or endpoint.startswith("source://"):
            return VerifiedPromotionResult(
                finding_id=finding_id,
                target_endpoint=endpoint or "unknown",
                http_method=method,
                previous_classification=prev_class,
                new_classification=FindingClassification.INCONCLUSIVE,
                is_promoted=False,
                status="suspected",
                validation_status="SUSPICIOUS",
                summary="Candidate has no resolvable HTTP route for runtime differential testing; pure source pattern remains unconfirmed.",
                owner_role=owner_role,
                test_roles=effective_roles,
                confidence=ConfidenceLevel.LOW,
                recommended_fix="Map source location to an exposed HTTP endpoint before running runtime differential testing.",
            )

        # 3. Scope validation (Hard scope enforcement via ScopeGuard)
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            test_url = endpoint
        else:
            test_url = f"{self.discovery.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        is_in_scope = False
        try:
            scope_res = self.scope_guard.validate_url(test_url)
            is_in_scope = scope_res.is_allowed
        except Exception:
            is_in_scope = False

        if not is_in_scope:
            return VerifiedPromotionResult(
                finding_id=finding_id,
                target_endpoint=endpoint,
                http_method=method,
                previous_classification=prev_class,
                new_classification=FindingClassification.INCONCLUSIVE,
                is_promoted=False,
                status="suspected",
                validation_status="SUSPICIOUS",
                summary=f"Target URL '{test_url}' is outside authorized testing scope ({settings.target_base_url}). Finding cannot be verified at runtime.",
                owner_role=owner_role,
                test_roles=effective_roles,
                confidence=ConfidenceLevel.LOW,
                recommended_fix="Verify endpoint authorization within authorized target boundary.",
            )

        # 4. Execute multi-role authorization-differential testing
        diff_result = self.test_resource_access(
            endpoint=endpoint,
            owner_role=owner_role,
            test_roles=effective_roles,
            resource_id=resource_id,
            method=method,
        )

        # Case A: Runtime unauthorized access confirmed
        if diff_result.is_confirmed:
            artifact = diff_result.evidence_artifacts[0] if diff_result.evidence_artifacts else None
            owner_status = diff_result.role_responses[owner_role].status_code if owner_role in diff_result.role_responses else 200
            unauth_statuses = [
                f"{r.value}: HTTP {diff_result.role_responses[r].status_code}"
                for r in effective_roles
                if r in diff_result.role_responses
            ]
            repro_steps = [
                f"1. Target Endpoint & Method: {method} {diff_result.resolved_url}",
                f"2. Legitimate Baseline Check: Authenticate as owner role '{owner_role.value}' and send {method} request -> Received HTTP {owner_status} with legitimate resource payload.",
                f"3. Unauthorized Probe Check: Authenticate as unauthorized role(s) ({', '.join(r.value for r in effective_roles)}) and replay identical {method} request -> Observed {', '.join(unauth_statuses)}.",
                "4. Discrepancy & Security Violation: Unauthorized caller obtained sensitive resource data without server-side 401/403 authorization enforcement.",
                f"5. Cryptographic Evidence: Artifact verified with SHA-256 digest: {artifact.evidence_sha256 if artifact else 'N/A'}.",
            ]
            recommended_fix = (
                "Enforce strict server-side authorization checks verifying caller ownership or role permissions "
                "before returning resource data. Never rely solely on client-side routing or unverified IDs."
            )
            summary_msg = (
                f"Runtime differential testing confirmed Broken Access Control on {method} {diff_result.resolved_url}: "
                f"unauthorized caller accessed resource owned by '{owner_role.value}'."
            )

            rec = FindingRecord(
                id=finding_id,
                scan_id="runtime_verification",
                title=f"[Confirmed Runtime: {category}] Unauthorized access to {diff_result.resolved_url}",
                endpoint=diff_result.endpoint,
                target_endpoint=diff_result.resolved_url,
                http_method=method,
                vulnerability_category=str(category),
                vulnerability_type=str(category),
                confirmation_status=FindingStatus.CONFIRMED.value,
                status=FindingStatus.CONFIRMED.value,
                validation_status="CONFIRMED",
                access_verdict=diff_result.overall_verdict.value,
                classification=FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY.value,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.CONFIRMED,
                description=summary_msg,
                impact_explanation="Unauthorized users can access or manipulate resources belonging to other tenants/users, leading to confidential data compromise.",
                remediation_guidance=recommended_fix,
                remediation_recommendation=recommended_fix,
                technical_details={
                    "reproduction_steps": repro_steps,
                    "owner_role": owner_role.value,
                    "test_roles": [r.value for r in effective_roles],
                    "resolved_url": diff_result.resolved_url,
                    "overall_verdict": diff_result.overall_verdict.value,
                },
                evidence=artifact,
            )

            return VerifiedPromotionResult(
                finding_id=finding_id,
                target_endpoint=diff_result.resolved_url,
                http_method=method,
                previous_classification=prev_class,
                new_classification=FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY,
                is_promoted=True,
                status=FindingStatus.CONFIRMED.value,
                validation_status="CONFIRMED",
                summary=summary_msg,
                owner_role=owner_role,
                test_roles=effective_roles,
                reproduction_steps=repro_steps,
                evidence=artifact,
                finding_record=rec,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=SeverityLevel.HIGH,
                recommended_fix=recommended_fix,
            )

        # Case B: Server correctly denied unauthorized access
        if diff_result.overall_verdict == AccessVerdict.CORRECTLY_DENIED:
            repro_steps = [
                f"1. Target Endpoint: {method} {diff_result.resolved_url}",
                "2. Probe unauthorized role(s): Server responded with HTTP 401/403 (Access Correctly Denied).",
                "3. Outcome: Authorization is properly enforced at runtime; potential finding is NOT_REPRODUCIBLE.",
            ]
            return VerifiedPromotionResult(
                finding_id=finding_id,
                target_endpoint=diff_result.resolved_url,
                http_method=method,
                previous_classification=prev_class,
                new_classification=FindingClassification.NOT_REPRODUCIBLE,
                is_promoted=False,
                status=FindingStatus.FALSE_POSITIVE.value,
                validation_status="REJECTED",
                summary=f"Runtime differential testing rejected vulnerability on {method} {diff_result.resolved_url}: unauthorized caller received proper access denial.",
                owner_role=owner_role,
                test_roles=effective_roles,
                reproduction_steps=repro_steps,
                evidence=diff_result.evidence_artifacts[0] if diff_result.evidence_artifacts else None,
                confidence=ConfidenceLevel.HIGH,
                severity=SeverityLevel.LOW,
                recommended_fix="No fix required; authorization controls are enforced as expected.",
            )

        # Case C: Behavioral divergence detected without explicit proof
        if diff_result.overall_verdict == AccessVerdict.SUSPICIOUS_ACCESS:
            repro_steps = [
                f"1. Target Endpoint: {method} {diff_result.resolved_url}",
                "2. Compare owner response with unauthorized response: Behavioral divergence detected without explicit owner match or sensitive data leakage.",
                "3. Outcome: Access remains SUSPICIOUS_ACCESS pending manual review or specialized probes.",
            ]
            return VerifiedPromotionResult(
                finding_id=finding_id,
                target_endpoint=diff_result.resolved_url,
                http_method=method,
                previous_classification=prev_class,
                new_classification=FindingClassification.SUSPICIOUS_ACCESS,
                is_promoted=False,
                status=FindingStatus.SUSPECTED.value,
                validation_status="SUSPICIOUS",
                summary=f"Runtime differential testing observed response divergence on {method} {diff_result.resolved_url}, but evidence does not confirm unauthorized access.",
                owner_role=owner_role,
                test_roles=effective_roles,
                reproduction_steps=repro_steps,
                evidence=diff_result.evidence_artifacts[0] if diff_result.evidence_artifacts else None,
                confidence=ConfidenceLevel.MEDIUM,
                severity=SeverityLevel.MEDIUM,
                recommended_fix="Review response differences between authenticated roles to verify whether sensitive metadata is leaked.",
            )

        # Case D: Inconclusive
        repro_steps = [
            f"1. Target Endpoint: {method} {diff_result.resolved_url}",
            "2. Outcome: Differential test did not yield conclusive authorization evidence.",
        ]
        return VerifiedPromotionResult(
            finding_id=finding_id,
            target_endpoint=diff_result.resolved_url,
            http_method=method,
            previous_classification=prev_class,
            new_classification=FindingClassification.INCONCLUSIVE,
            is_promoted=False,
            status=FindingStatus.SUSPECTED.value,
            validation_status="SUSPICIOUS",
            summary=f"Runtime differential testing was inconclusive for {method} {diff_result.resolved_url}.",
            owner_role=owner_role,
            test_roles=effective_roles,
            reproduction_steps=repro_steps,
            confidence=ConfidenceLevel.LOW,
            severity=SeverityLevel.LOW,
            recommended_fix="Review target endpoint accessibility and parameter requirements.",
        )


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
    """Top-level contract function to execute authorization-differential testing."""
    tester = AuthorizationTester(
        executor=executor,
        session_manager=session_manager,
        scope_guard=scope_guard,
    )
    return tester.test_resource_access(
        endpoint=endpoint,
        owner_role=owner_role,
        test_roles=roles_to_test,
        resource_id=resource_id,
        method=method,
    )
