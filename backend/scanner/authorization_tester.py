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
from typing import Dict, List, Optional, Any, Tuple, Union
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
    UnsupportedMethodError,
    redact_sensitive_text,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

DESTRUCTIVE_MODIFICATION_KEYS = {
    "delete",
    "drop",
    "destroy",
    "truncate",
    "purge",
    "wipe",
    "remove_account",
    "delete_order",
    "delete_basket",
    "close_account",
}


class RoleProbeOutcome(BaseModel):
    """Detailed outcome for a single role tested against an endpoint."""
    role: Role
    response: HttpResponseModel
    verdict: AccessVerdict
    comparison: Optional[ComparisonAnalysis] = None
    evidence: Optional[EvidenceArtifact] = None
    vulnerability_type: Optional[str] = None
    extracted_resource_ids: List[str] = Field(default_factory=list)
    exposed_sensitive_fields: List[str] = Field(default_factory=list)


class DifferentialResult(BaseModel):
    """Structured result of multi-role authorization-differential testing on an endpoint."""
    endpoint: str
    resolved_url: str = ""
    method: str = "GET"
    resource_id: Optional[str] = None
    owner_role: Role = Role.USER_A
    admin_policy: str = "policy_dependent"
    role_responses: Dict[Role, HttpResponseModel] = Field(default_factory=dict)
    probe_outcomes: Dict[Role, RoleProbeOutcome] = Field(default_factory=dict)
    overall_verdict: AccessVerdict = AccessVerdict.CORRECTLY_DENIED
    is_discrepancy_detected: bool = False
    is_confirmed: bool = False
    vulnerability_candidate: Optional[str] = None
    detected_vulnerabilities: List[str] = Field(default_factory=list)
    status_codes_by_role: Dict[str, int] = Field(default_factory=dict)
    resource_ids_by_role: Dict[str, List[str]] = Field(default_factory=dict)
    sensitive_fields_by_role: Dict[str, List[str]] = Field(default_factory=dict)
    permissions_by_role: Dict[str, List[str]] = Field(default_factory=dict)
    permission_differences: List[str] = Field(default_factory=list)
    response_behaviors_by_role: Dict[str, str] = Field(default_factory=dict)
    evidence_artifacts: List[EvidenceArtifact] = Field(default_factory=list)
    finding_records: List[FindingRecord] = Field(default_factory=list)
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
        test_role: Role,
        owner_role: Optional[Role] = None,
    ) -> str:
        """Determines the specific authorization vulnerability classification."""
        if test_role == Role.ANONYMOUS and endpoint.requires_auth:
            return "MISSING_AUTH"
        if owner_role == Role.ADMIN or endpoint.category == EndpointCategory.ADMIN_FUNCTION:
            return "BFLA"
        if endpoint.category == EndpointCategory.USER_OBJECT or endpoint.requires_owner_match:
            return "BOLA_IDOR"
        return "BROKEN_ACCESS_CONTROL"

    @staticmethod
    def _validate_safe_modification_payload(payload: Optional[Dict[str, Any]]) -> None:
        """Ensures modification payloads are benign and contain no destructive directives."""
        if not payload:
            return
        for k, v in payload.items():
            k_lower = str(k).strip().lower()
            v_lower = str(v).strip().lower()
            if k_lower in DESTRUCTIVE_MODIFICATION_KEYS or any(
                d in k_lower for d in ("delete", "drop", "destroy", "truncate", "purge")
            ):
                raise UnsupportedMethodError(
                    f"Destructive modification payload key '{k}' is forbidden by non-destructive testing rules."
                )
            if any(
                d in v_lower
                for d in ("drop table", "delete from", "rm -rf", "destroy_account", "delete_all")
            ):
                raise UnsupportedMethodError(
                    f"Destructive modification payload value in '{k}' is forbidden by non-destructive testing rules."
                )

    def test_resource_access(
        self,
        endpoint: DiscoveredEndpoint | str,
        owner_role: Role = Role.USER_A,
        test_roles: Optional[List[Role]] = None,
        resource_id: Optional[str] = None,
        method: str = "GET",
        human_approved: bool = False,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        safe_test_fixture: bool = False,
        admin_policy: str = "policy_dependent",
        scan_id: str = "default_scan",
    ) -> DifferentialResult:
        """Executes a full authorization-differential test on an endpoint.

        Workflow:
        1. Validates scope, method, and human approval boundaries.
        2. Verifies required sessions are authenticated in SessionManager.
        3. Requests the resource using the legitimate `owner_role` and records baseline.
        4. Requests the same resource using each `test_role` (e.g. User B, Anonymous, Admin).
        5. Compares responses via ResponseAnalyzer (status, JSON structure, ownership, sensitive fields).
        6. Validates and signs cryptographic EvidenceArtifact for suspicious or confirmed findings.
        """
        norm_method = method.strip().upper()
        if norm_method == "DELETE":
            raise UnsupportedMethodError(
                "HTTP DELETE is strictly forbidden by AuthScope non-destructive testing rules."
            )
        if json_body is not None:
            self._validate_safe_modification_payload(json_body)

        effective_human_approved = human_approved or (
            safe_test_fixture and norm_method in ("GET", "HEAD", "POST", "PUT", "PATCH")
        )

        disc_ep, resolved_url, effective_res_id = self._resolve_target_endpoint(
            endpoint=endpoint,
            method=norm_method,
            resource_id=resource_id,
            owner_role=owner_role,
            human_approved=effective_human_approved,
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

        if (
            disc_ep.requires_owner_match
            and disc_ep.resource_type
            and effective_res_id
            and not owner_session.owns_resource(disc_ep.resource_type, effective_res_id)
        ):
            return DifferentialResult(
                endpoint=disc_ep.path,
                resolved_url=resolved_url,
                method=disc_ep.method,
                resource_id=effective_res_id,
                owner_role=owner_role,
                admin_policy=admin_policy,
                overall_verdict=AccessVerdict.INCONCLUSIVE,
                is_discrepancy_detected=False,
                is_confirmed=False,
                summary=(
                    f"Ownership of resource '{effective_res_id}' for role '{owner_role.value}' "
                    "is not explicitly configured; authorization comparison was not sent."
                ),
            )

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
        status_codes_by_role: Dict[str, int] = {}
        resource_ids_by_role: Dict[str, List[str]] = {}
        sensitive_fields_by_role: Dict[str, List[str]] = {}
        permissions_by_role: Dict[str, List[str]] = {}
        permission_differences: List[str] = []
        response_behaviors_by_role: Dict[str, str] = {}
        detected_vulns: List[str] = []

        # Step 1: Request resource using legitimate owner
        self._apply_rate_limit()
        owner_resp = self.executor.send_request(
            role=owner_role,
            method=disc_ep.method,
            url=resolved_url,
            json_body=json_body,
            params=params,
        )
        role_responses[owner_role] = owner_resp
        owner_insp = self.analyzer.inspect_response(owner_resp)
        owner_verdict = (
            AccessVerdict.ALLOWED_ACCESS
            if (owner_insp.is_http_success and not owner_insp.is_empty_payload and not owner_insp.is_spa_html_fallback)
            else AccessVerdict.CORRECTLY_DENIED
        )
        if owner_verdict == AccessVerdict.ALLOWED_ACCESS:
            self.session_manager.record_accessible_resource(owner_role, disc_ep.path)
            self.session_manager.record_permission(owner_role, f"{disc_ep.method}:{disc_ep.path}")

        status_codes_by_role[owner_role.value] = owner_resp.status_code
        resource_ids_by_role[owner_role.value] = list(owner_insp.extracted_resource_ids)
        sensitive_fields_by_role[owner_role.value] = list(owner_insp.sensitive_fields_found)
        permissions_by_role[owner_role.value] = [
            f"{'ALLOWED' if owner_verdict == AccessVerdict.ALLOWED_ACCESS else 'DENIED'}:{disc_ep.method}:{disc_ep.path}"
        ]
        response_behaviors_by_role[owner_role.value] = owner_verdict.value

        probe_outcomes[owner_role] = RoleProbeOutcome(
            role=owner_role,
            response=owner_resp,
            verdict=owner_verdict,
            extracted_resource_ids=list(owner_insp.extracted_resource_ids),
            exposed_sensitive_fields=list(owner_insp.sensitive_fields_found),
        )

        # Step 2: Probe same resource across each unauthorized / peer test role
        overall_verdict = AccessVerdict.CORRECTLY_DENIED
        is_discrepancy = False
        is_confirmed = False
        vuln_candidate: Optional[str] = None
        summary_parts: List[str] = []

        norm_admin_policy = (admin_policy or "policy_dependent").strip().lower()

        for trole in test_roles:
            self._apply_rate_limit()
            test_session = self.session_manager.require_authenticated_session(trole)
            test_resp = self.executor.send_request(
                role=trole,
                method=disc_ep.method,
                url=resolved_url,
                json_body=json_body,
                params=params,
            )
            role_responses[trole] = test_resp
            test_insp = self.analyzer.inspect_response(test_resp)

            # Check whether this role is legitimately expected to have access according to policy
            if trole == Role.ADMIN and owner_role != Role.ADMIN:
                if norm_admin_policy == "allowed":
                    role_allowed_by_policy = True
                elif norm_admin_policy == "denied":
                    role_allowed_by_policy = False
                else:
                    # policy_dependent: Admin is allowed on ADMIN_FUNCTION or PUBLIC or when in expected_allowed_roles
                    # and not flagged as unauthorized on user objects unless admin_policy == "denied"
                    role_allowed_by_policy = (
                        disc_ep.category in (EndpointCategory.PUBLIC, EndpointCategory.ADMIN_FUNCTION)
                        or Role.ADMIN in disc_ep.expected_allowed_roles
                        or norm_admin_policy == "policy_dependent"
                    )
            else:
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
            role_vuln_type: Optional[str] = None

            if final_role_verdict == AccessVerdict.ALLOWED_ACCESS:
                self.session_manager.record_accessible_resource(trole, disc_ep.path)
                self.session_manager.record_permission(trole, f"{disc_ep.method}:{disc_ep.path}")

            if comparison.verdict in (
                AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS,
                AccessVerdict.SUSPICIOUS_ACCESS,
            ):
                role_vuln_type = self._classify_vulnerability_type(disc_ep, trole, owner_role=owner_role)
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

                if role_vuln_type and role_vuln_type not in detected_vulns:
                    detected_vulns.append(role_vuln_type)
                if (
                    role_vuln_type == "BFLA"
                    and trole in (Role.USER_A, Role.USER_B)
                    and "PRIVILEGE_ESCALATION" not in detected_vulns
                ):
                    detected_vulns.append("PRIVILEGE_ESCALATION")

                permission_differences.append(
                    f"Role '{trole.value}' unexpectedly accessed '{disc_ep.method} {disc_ep.path}' "
                    f"(HTTP {test_resp.status_code}, verdict={final_role_verdict.value}, "
                    f"classification={role_vuln_type})."
                )

                if final_role_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS:
                    is_confirmed = True
                    overall_verdict = AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
                    if vuln_candidate is None or trole != Role.ANONYMOUS:
                        vuln_candidate = role_vuln_type
                elif overall_verdict != AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS:
                    overall_verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    if not vuln_candidate:
                        vuln_candidate = role_vuln_type

            elif final_role_verdict == AccessVerdict.ALLOWED_ACCESS and overall_verdict == AccessVerdict.CORRECTLY_DENIED:
                overall_verdict = AccessVerdict.ALLOWED_ACCESS

            status_codes_by_role[trole.value] = test_resp.status_code
            resource_ids_by_role[trole.value] = list(test_insp.extracted_resource_ids)
            sensitive_fields_by_role[trole.value] = list(test_insp.sensitive_fields_found)
            permissions_by_role[trole.value] = [
                f"{'ALLOWED' if final_role_verdict in (AccessVerdict.ALLOWED_ACCESS, AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS) else 'DENIED'}:{disc_ep.method}:{disc_ep.path}"
            ]
            response_behaviors_by_role[trole.value] = final_role_verdict.value

            probe_outcomes[trole] = RoleProbeOutcome(
                role=trole,
                response=test_resp,
                verdict=final_role_verdict,
                comparison=comparison,
                evidence=artifact,
                vulnerability_type=role_vuln_type,
                extracted_resource_ids=list(test_insp.extracted_resource_ids),
                exposed_sensitive_fields=list(test_insp.sensitive_fields_found),
            )
            summary_parts.append(f"[{trole.value}: {final_role_verdict.value}]")

        summary_str = (
            f"Endpoint {disc_ep.method} {disc_ep.path} (resource_id={effective_res_id}): "
            f"owner={owner_role.value} (HTTP {owner_resp.status_code}) -> "
            + ", ".join(summary_parts)
        )

        diff_result = DifferentialResult(
            endpoint=disc_ep.path,
            resolved_url=resolved_url,
            method=disc_ep.method,
            resource_id=effective_res_id,
            owner_role=owner_role,
            admin_policy=norm_admin_policy,
            role_responses=role_responses,
            probe_outcomes=probe_outcomes,
            overall_verdict=overall_verdict,
            is_discrepancy_detected=is_discrepancy,
            is_confirmed=is_confirmed,
            vulnerability_candidate=vuln_candidate,
            detected_vulnerabilities=detected_vulns,
            status_codes_by_role=status_codes_by_role,
            resource_ids_by_role=resource_ids_by_role,
            sensitive_fields_by_role=sensitive_fields_by_role,
            permissions_by_role=permissions_by_role,
            permission_differences=permission_differences,
            response_behaviors_by_role=response_behaviors_by_role,
            evidence_artifacts=evidence_list,
            summary=summary_str,
        )
        diff_result.finding_records = self.build_finding_records(diff_result, scan_id=scan_id)
        return diff_result

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

    def test_bola_idor(
        self,
        endpoint: DiscoveredEndpoint | str,
        resource_id: Optional[str] = None,
        owner_role: Role = Role.USER_A,
        attacker_role: Role = Role.USER_B,
        human_approved: bool = False,
    ) -> DifferentialResult:
        """Executes a strict 10-step ownership-differential BOLA/IDOR test.

        Enforces:
        1. Obtain a genuine User A session and verify authentication.
        2. Obtain a separate genuine User B session and verify authentication.
           If valid separate sessions are unavailable, returns NOT_TESTED.
        3. Identify an actual resource owned by User A.
           If ownership cannot be established without guessing, returns INCONCLUSIVE.
        4. Verify User A can access the resource (baseline).
           If User A baseline fails, returns INCONCLUSIVE.
        5. Request the same resource as User B.
        6. Capture actual response.
        7. Compare access behavior and protected resource data (never rely on 200 alone).
        8. Establish whether User B accessed User A's private resource.
        9. Validate evidence via EvidenceValidator.
        10. Return structured DifferentialResult.
        """
        disc_ep = self.discovery.register_endpoint(endpoint) if isinstance(endpoint, str) else endpoint
        endpoint_str = disc_ep.path

        # Step 1 & 2: Check genuine separate sessions
        user_a_ready = self.session_manager.is_authenticated(owner_role)
        user_b_ready = self.session_manager.is_authenticated(attacker_role)
        if not (user_a_ready and user_b_ready):
            return DifferentialResult(
                endpoint=endpoint_str,
                owner_role=owner_role,
                overall_verdict=AccessVerdict.NOT_TESTED,
                is_discrepancy_detected=False,
                is_confirmed=False,
                summary=f"Valid separate sessions for '{owner_role.value}' and '{attacker_role.value}' are unavailable. Test skipped without guessing credentials."
            )

        # Step 3: Identify an actual resource owned by User A (no guessing arbitrary IDs)
        effective_res_id = resource_id or disc_ep.extracted_resource_id
        if not effective_res_id and TEMPLATE_PARAM_REGEX.search(disc_ep.path):
            owner_session = self.session_manager.get_session(owner_role)
            if disc_ep.resource_type:
                owned_set = owner_session.owned_resources.get(disc_ep.resource_type.lower(), set())
                if owned_set:
                    effective_res_id = sorted(owned_set)[0]

        if not effective_res_id and TEMPLATE_PARAM_REGEX.search(disc_ep.path):
            return DifferentialResult(
                endpoint=endpoint_str,
                owner_role=owner_role,
                overall_verdict=AccessVerdict.INCONCLUSIVE,
                is_discrepancy_detected=False,
                is_confirmed=False,
                summary=f"Resource ownership for '{owner_role.value}' could not be established on '{endpoint_str}'. IDOR test inconclusive without guessing arbitrary IDs."
            )

        owner_session = self.session_manager.get_session(owner_role)
        if (
            disc_ep.requires_owner_match
            and disc_ep.resource_type
            and effective_res_id
            and not owner_session.owns_resource(disc_ep.resource_type, effective_res_id)
        ):
            return DifferentialResult(
                endpoint=endpoint_str,
                resolved_url="",
                owner_role=owner_role,
                resource_id=effective_res_id,
                overall_verdict=AccessVerdict.INCONCLUSIVE,
                is_discrepancy_detected=False,
                is_confirmed=False,
                summary=(
                    f"Ownership of resource '{effective_res_id}' for role '{owner_role.value}' "
                    "is not explicitly configured. No baseline or cross-role request was sent."
                ),
            )

        # Step 4: Verify User A can access the resource (baseline verification)
        resolved_url = self.discovery.build_concrete_url(disc_ep, resource_id=effective_res_id)
        owner_resp = self.executor.send_request(
            role=owner_role,
            method="GET",
            url=resolved_url,
        )
        owner_insp = self.analyzer.inspect_response(owner_resp)
        if not (owner_insp.is_http_success and not owner_insp.is_empty_payload and not owner_insp.is_spa_html_fallback):
            return DifferentialResult(
                endpoint=endpoint_str,
                resolved_url=resolved_url,
                owner_role=owner_role,
                resource_id=effective_res_id,
                overall_verdict=AccessVerdict.INCONCLUSIVE,
                is_discrepancy_detected=False,
                is_confirmed=False,
                summary=f"Baseline request for owner '{owner_role.value}' failed with HTTP {owner_resp.status_code}. Cannot establish valid ownership baseline."
            )

        # Step 5 - 10: Perform full test with attacker
        return self.test_resource_access(
            endpoint=disc_ep,
            owner_role=owner_role,
            test_roles=[attacker_role],
            resource_id=effective_res_id,
            method="GET",
            human_approved=human_approved,
        )

    def test_bfla(
        self,
        endpoint: DiscoveredEndpoint | str,
        admin_role: Role = Role.ADMIN,
        test_roles: Optional[List[Role]] = None,
        human_approved: bool = False,
    ) -> DifferentialResult:
        """Executes a Broken Function Level Authorization (BFLA) test across roles.

        Tests access to administrative/privileged endpoints from lower-privilege roles
        (ANONYMOUS, USER_A, USER_B) compared against ADMIN baseline when configured.
        Requires evidence that lower-privilege identity accessed protected information.
        """
        disc_ep = self.discovery.register_endpoint(endpoint) if isinstance(endpoint, str) else endpoint
        roles_to_probe = test_roles or [Role.ANONYMOUS, Role.USER_A, Role.USER_B]

        if self.session_manager.is_authenticated(admin_role):
            return self.test_resource_access(
                endpoint=disc_ep,
                owner_role=admin_role,
                test_roles=roles_to_probe,
                method="GET",
                human_approved=human_approved,
            )
        else:
            resolved_url = self.discovery.build_concrete_url(disc_ep)
            role_responses: Dict[Role, HttpResponseModel] = {}
            probe_outcomes: Dict[Role, RoleProbeOutcome] = {}
            evidence_list: List[EvidenceArtifact] = []
            is_discrepancy = False
            overall_verdict = AccessVerdict.CORRECTLY_DENIED

            for role in roles_to_probe:
                resp = self.executor.send_request(role=role, method="GET", url=resolved_url)
                role_responses[role] = resp
                insp = self.analyzer.inspect_response(resp)

                if insp.is_http_success and not insp.is_empty_payload and not insp.is_spa_html_fallback:
                    verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    is_discrepancy = True
                    overall_verdict = AccessVerdict.SUSPICIOUS_ACCESS
                    artifact = self.evidence_validator.create_and_sign_evidence(
                        finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                        test_role=role,
                        authorized_role=admin_role,
                        method="GET",
                        url=resolved_url,
                        headers={},
                        response=resp,
                        endpoint=disc_ep.path,
                        expected_behavior=f"Privileged route '{disc_ep.path}' should restrict access to '{role.value}' (HTTP 401/403).",
                        actual_behavior=f"Role '{role.value}' received HTTP {resp.status_code} ({len(resp.body)} bytes).",
                        validation_status=EvidenceValidationStatus.SUSPICIOUS,
                    )
                    evidence_list.append(artifact)
                else:
                    verdict = AccessVerdict.CORRECTLY_DENIED

                probe_outcomes[role] = RoleProbeOutcome(
                    role=role,
                    response=resp,
                    verdict=verdict,
                )

            return DifferentialResult(
                endpoint=disc_ep.path,
                resolved_url=resolved_url,
                method="GET",
                owner_role=admin_role,
                role_responses=role_responses,
                probe_outcomes=probe_outcomes,
                overall_verdict=overall_verdict,
                is_discrepancy_detected=is_discrepancy,
                is_confirmed=False,
                vulnerability_candidate="BFLA" if is_discrepancy else None,
                evidence_artifacts=evidence_list,
                summary=f"BFLA probe for '{disc_ep.path}' completed across {len(roles_to_probe)} roles without admin baseline."
            )

    def test_four_role_access(
        self,
        endpoint: DiscoveredEndpoint | str,
        owner_role: Optional[Role] = None,
        resource_id: Optional[str] = None,
        method: str = "GET",
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        admin_policy: str = "policy_dependent",
        safe_test_fixture: bool = False,
        human_approved: bool = False,
        scan_id: str = "default_scan",
    ) -> DifferentialResult:
        """Executes cross-role request comparison across all four testing roles:
        Anonymous, User A, User B, and Admin.

        Evaluates:
        - Status codes across all four roles.
        - Response bodies, resource IDs, and sensitive field exposure.
        - Permission differences across Anonymous, User A, User B, and Admin.
        - Admin access behavior according to `admin_policy` ('allowed', 'denied', or 'policy_dependent').
        - Authentication failures (MISSING_AUTH), horizontal escalation (BOLA_IDOR),
          and vertical privilege escalation (BFLA / PRIVILEGE_ESCALATION).
        """
        if isinstance(endpoint, str) and endpoint.strip().startswith(("http://", "https://")):
            self.scope_guard.assert_in_scope(endpoint.strip(), method=method)
        raw_ep = endpoint if isinstance(endpoint, DiscoveredEndpoint) else self.discovery.register_endpoint(str(endpoint), method=method)
        effective_owner = owner_role or (
            Role.ADMIN if raw_ep.category == EndpointCategory.ADMIN_FUNCTION else Role.USER_A
        )

        all_four = [Role.ANONYMOUS, Role.USER_A, Role.USER_B, Role.ADMIN]
        candidate_test_roles: List[Role] = []
        unauthenticated_roles: List[Role] = []

        for r in all_four:
            if r == effective_owner:
                continue
            if r == Role.ANONYMOUS or self.session_manager.is_authenticated(r):
                candidate_test_roles.append(r)
            else:
                unauthenticated_roles.append(r)

        if not self.session_manager.is_authenticated(effective_owner):
            if effective_owner == Role.ADMIN:
                res = self.test_bfla(
                    endpoint=raw_ep,
                    admin_role=Role.ADMIN,
                    test_roles=candidate_test_roles or [Role.ANONYMOUS],
                    human_approved=human_approved,
                )
                for ur in unauthenticated_roles + [Role.ADMIN]:
                    res.response_behaviors_by_role[ur.value] = AccessVerdict.NOT_TESTED.value
                res.finding_records = self.build_finding_records(res, scan_id=scan_id)
                return res
            return DifferentialResult(
                endpoint=raw_ep.path,
                method=raw_ep.method,
                owner_role=effective_owner,
                admin_policy=admin_policy,
                overall_verdict=AccessVerdict.NOT_TESTED,
                is_discrepancy_detected=False,
                is_confirmed=False,
                response_behaviors_by_role={
                    r.value: (
                        AccessVerdict.NOT_TESTED.value
                        if not self.session_manager.is_authenticated(r) and r != Role.ANONYMOUS
                        else AccessVerdict.NOT_TESTED.value
                    )
                    for r in all_four
                },
                summary=f"Owner role '{effective_owner.value}' does not have an authenticated session; 4-role test not executed.",
            )

        result = self.test_resource_access(
            endpoint=raw_ep,
            owner_role=effective_owner,
            test_roles=candidate_test_roles,
            resource_id=resource_id,
            method=method,
            human_approved=human_approved,
            json_body=json_body,
            params=params,
            safe_test_fixture=safe_test_fixture,
            admin_policy=admin_policy,
            scan_id=scan_id,
        )
        for ur in unauthenticated_roles:
            result.response_behaviors_by_role[ur.value] = AccessVerdict.NOT_TESTED.value
            result.permissions_by_role[ur.value] = [f"NOT_TESTED:{raw_ep.method}:{raw_ep.path}"]
        return result

    def compare_four_roles(
        self,
        endpoint: DiscoveredEndpoint | str,
        owner_role: Optional[Role] = None,
        resource_id: Optional[str] = None,
        method: str = "GET",
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        admin_policy: str = "policy_dependent",
        safe_test_fixture: bool = False,
        human_approved: bool = False,
        scan_id: str = "default_scan",
    ) -> DifferentialResult:
        """Alias for `test_four_role_access`."""
        return self.test_four_role_access(
            endpoint=endpoint,
            owner_role=owner_role,
            resource_id=resource_id,
            method=method,
            json_body=json_body,
            params=params,
            admin_policy=admin_policy,
            safe_test_fixture=safe_test_fixture,
            human_approved=human_approved,
            scan_id=scan_id,
        )

    def test_unauthorized_modification(
        self,
        endpoint: DiscoveredEndpoint | str,
        method: str = "PUT",
        safe_payload: Optional[Dict[str, Any]] = None,
        resource_id: Optional[str] = None,
        owner_role: Role = Role.USER_A,
        attacker_role: Role = Role.USER_B,
        include_anonymous: bool = True,
        admin_policy: str = "policy_dependent",
        scan_id: str = "default_scan",
    ) -> DifferentialResult:
        """Tests whether an unauthorized role (e.g. User B or Anonymous) can modify a resource
        owned by User A (or perform a privileged Admin mutation) using non-destructive test fixtures.

        Strictly enforces:
        - HTTP DELETE is forbidden.
        - Destructive payload keys/values are rejected.
        - Only controlled non-destructive modification verbs (POST, PUT, PATCH) are allowed.
        """
        norm_method = method.strip().upper()
        if norm_method == "DELETE" or norm_method not in ("POST", "PUT", "PATCH"):
            raise UnsupportedMethodError(
                f"HTTP method '{norm_method}' is not permitted for safe modification testing. "
                "Only non-destructive POST, PUT, or PATCH with safe test fixtures are allowed."
            )

        payload = safe_payload if safe_payload is not None else {
            "test_fixture": True,
            "note": "authscope_non_destructive_probe",
        }
        self._validate_safe_modification_payload(payload)

        roles_to_test: List[Role] = [attacker_role]
        if include_anonymous and Role.ANONYMOUS not in roles_to_test and owner_role != Role.ANONYMOUS:
            roles_to_test.append(Role.ANONYMOUS)

        prev_allowed_methods = list(self.scope_guard.allowed_methods)
        try:
            if norm_method not in self.scope_guard.allowed_methods:
                self.scope_guard.allowed_methods.append(norm_method)

            return self.test_resource_access(
                endpoint=endpoint,
                owner_role=owner_role,
                test_roles=roles_to_test,
                resource_id=resource_id,
                method=norm_method,
                human_approved=True,
                json_body=payload,
                safe_test_fixture=True,
                admin_policy=admin_policy,
                scan_id=scan_id,
            )
        finally:
            self.scope_guard.allowed_methods = prev_allowed_methods

    @staticmethod
    def build_finding_records(
        result: DifferentialResult,
        scan_id: str = "default_scan",
    ) -> List[FindingRecord]:
        """Builds structured `FindingRecord` objects with full sanitized evidence,
        expected vs actual behavior, explanation, reproducibility steps, and risk assessment.
        """
        records: List[FindingRecord] = []
        if not result.evidence_artifacts:
            return records

        from backend.analysis.remediation import RemediationEngine

        rem_engine = RemediationEngine()
        owner_resp = result.role_responses.get(result.owner_role)
        owner_status = owner_resp.status_code if owner_resp else 200

        for artifact in result.evidence_artifacts:
            trole = artifact.test_role
            outcome = result.probe_outcomes.get(trole)
            vuln_type = (
                (outcome.vulnerability_type if outcome and outcome.vulnerability_type else None)
                or result.vulnerability_candidate
                or "BROKEN_ACCESS_CONTROL"
            )
            is_conf = artifact.validation_status == EvidenceValidationStatus.CONFIRMED

            if vuln_type == "MISSING_AUTH":
                title = f"Missing Authentication on Protected Endpoint ({result.method} {result.endpoint})"
                explanation = (
                    f"Unauthenticated role '{trole.value}' was able to access protected endpoint "
                    f"'{result.method} {result.endpoint}' without valid credentials, exposing protected data."
                )
                impact = (
                    "Unauthenticated attackers can read or interact with protected application data "
                    "without logging in, bypassing authentication controls."
                )
                severity = SeverityLevel.HIGH if is_conf else SeverityLevel.MEDIUM
            elif vuln_type in ("BFLA", "PRIVILEGE_ESCALATION"):
                title = f"Vertical Privilege Escalation / BFLA ({result.method} {result.endpoint})"
                explanation = (
                    f"Non-administrative role '{trole.value}' accessed administrative or privileged endpoint "
                    f"'{result.method} {result.endpoint}' normally restricted to '{result.owner_role.value}'."
                )
                impact = (
                    "Lower-privilege users can invoke administrative functions or retrieve tenant-wide "
                    "configuration and user records (Vertical Privilege Escalation)."
                )
                severity = SeverityLevel.CRITICAL if is_conf else SeverityLevel.HIGH
            else:
                is_mod = result.method.upper() in ("POST", "PUT", "PATCH")
                action_word = "modify" if is_mod else "read"
                title = f"Horizontal Privilege Escalation / BOLA-IDOR ({result.method} {result.endpoint})"
                explanation = (
                    f"Authenticated role '{trole.value}' was able to {action_word} resource "
                    f"'{result.resource_id or result.endpoint}' owned by '{result.owner_role.value}' "
                    f"via '{result.method} {result.endpoint}'."
                )
                impact = (
                    f"Authenticated users can {action_word} private resources belonging to other users "
                    "(Horizontal Privilege Escalation / Broken Object Level Authorization)."
                )
                severity = SeverityLevel.HIGH if is_conf else SeverityLevel.MEDIUM

            confidence = ConfidenceLevel.CONFIRMED if is_conf else ConfidenceLevel.MEDIUM
            rem_rec = rem_engine.generate_recommendation(
                vulnerability_type=vuln_type,
                endpoint=result.endpoint,
                resource_type=None,
            )

            repro_steps = [
                f"1. Authenticate as baseline owner role '{result.owner_role.value}' and send '{result.method} {result.resolved_url}' -> HTTP {owner_status}.",
                f"2. Switch session to testing role '{trole.value}' and send identical '{result.method} {result.resolved_url}' -> HTTP {artifact.response_status}.",
                f"3. Compare responses: '{trole.value}' received protected data/operation response matching '{result.owner_role.value}' baseline instead of HTTP 401/403.",
                f"4. Verify cryptographic evidence SHA-256 signature: {artifact.evidence_sha256}.",
            ]

            risk_assessment = {
                "severity": severity.value,
                "confidence": confidence.value,
                "vulnerability_type": vuln_type,
                "exploitability": "High — reproducible via standard HTTP requests with role session switching.",
                "business_impact": impact,
                "cwe_reference": rem_rec.cwe_reference,
                "owasp_reference": rem_rec.owasp_reference,
            }

            request_details = {
                "method": artifact.request_method,
                "url": artifact.request_url,
                "testing_role": trole.value,
                "authorized_owner_role": result.owner_role.value,
                "headers": artifact.request_headers,
                "body_excerpt": redact_sensitive_text(str(getattr(artifact, "request_body_excerpt", "") or "")),
            }

            sanitized_response_details = {
                "status_code": artifact.response_status,
                "headers": artifact.response_headers,
                "sanitized_body_excerpt": artifact.sanitized_response_evidence,
                "evidence_sha256": artifact.evidence_sha256,
            }

            rec = FindingRecord(
                id=artifact.finding_id,
                scan_id=scan_id,
                title=title,
                vulnerability_category=vuln_type,
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                status=FindingStatus.CONFIRMED.value if is_conf else FindingStatus.SUSPECTED.value,
                confirmation_status=FindingStatus.CONFIRMED.value if is_conf else FindingStatus.SUSPECTED.value,
                validation_status="CONFIRMED" if is_conf else "SUSPICIOUS",
                endpoint=result.endpoint,
                target_endpoint=result.endpoint,
                http_method=result.method,
                resource_id=result.resource_id,
                affected_roles=[trole],
                affected_role=trole.value,
                access_verdict=(
                    AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value
                    if is_conf
                    else AccessVerdict.SUSPICIOUS_ACCESS.value
                ),
                classification=(
                    FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY.value
                    if is_conf
                    else FindingClassification.SUSPICIOUS_ACCESS.value
                ),
                description=explanation,
                impact_explanation=impact,
                expected_behavior=artifact.expected_behavior,
                actual_behavior=artifact.actual_behavior,
                remediation_guidance=rem_rec.code_Patch_example,
                remediation_recommendation=rem_rec.remediation_steps,
                evidence=artifact,
                evidence_reference=artifact.evidence_id,
                technical_details={
                    "vulnerability_type": vuln_type,
                    "affected_endpoint": result.endpoint,
                    "http_method": result.method,
                    "testing_role": trole.value,
                    "request_details": request_details,
                    "sanitized_response_details": sanitized_response_details,
                    "expected_behavior": artifact.expected_behavior,
                    "actual_behavior": artifact.actual_behavior,
                    "explanation": explanation,
                    "reproducibility_steps": repro_steps,
                    "risk_assessment": risk_assessment,
                    "status_codes_by_role": result.status_codes_by_role,
                    "response_behaviors_by_role": result.response_behaviors_by_role,
                    "permission_differences": result.permission_differences,
                },
            )
            records.append(rec)

        return records

    def save_findings_to_repository(
        self,
        result: DifferentialResult,
        repository: Any,
        scan_id: str = "default_scan",
        confirmed_only: bool = False,
    ) -> List[str]:
        """Persists generated FindingRecord and EvidenceArtifact objects to FindingRepository."""
        records = result.finding_records or self.build_finding_records(result, scan_id=scan_id)
        saved_ids: List[str] = []
        for rec in records:
            if confirmed_only and rec.validation_status != "CONFIRMED":
                continue
            rec.scan_id = scan_id
            repository.save_finding(rec)
            saved_ids.append(rec.id)
        return saved_ids

    @staticmethod
    def build_canonical_finding(
        result: DifferentialResult,
        assessment_id: str = "default_assessment",
    ) -> Optional[Dict[str, Any]]:
        """Constructs a canonical finding dictionary satisfying Phase 5.3 contract."""
        if not result.evidence_artifacts and not result.is_discrepancy_detected:
            return None

        from backend.utils.helpers import compute_sha256

        artifact = result.evidence_artifacts[0] if result.evidence_artifacts else None
        finding_id = artifact.finding_id if artifact else f"fnd_{uuid.uuid4().hex[:8]}"
        testing_role = artifact.test_role.value if artifact else Role.USER_B.value

        owner_resp = result.role_responses.get(result.owner_role)
        baseline_resp_data = {
            "status_code": owner_resp.status_code if owner_resp else 0,
            "content_length": owner_resp.content_length if owner_resp else 0,
            "body_preview": owner_resp.body[:500] if owner_resp else "",
        }

        test_role_enum = Role(testing_role) if testing_role in [r.value for r in Role] else Role.USER_B
        test_resp = result.role_responses.get(test_role_enum) or (list(result.role_responses.values())[-1] if result.role_responses else None)
        comp_resp_data = {
            "status_code": test_resp.status_code if test_resp else 0,
            "content_length": test_resp.content_length if test_resp else 0,
            "body_preview": test_resp.body[:500] if test_resp else "",
        }

        sanitized_ev = artifact.sanitized_response_evidence if artifact else (test_resp.body[:1500] if test_resp else "")

        response_hashes = {
            "baseline_sha256": compute_sha256(owner_resp.body) if owner_resp and owner_resp.body else None,
            "comparison_sha256": compute_sha256(test_resp.body) if test_resp and test_resp.body else None,
            "evidence_sha256": artifact.evidence_sha256 if artifact else None,
        }

        val_status = artifact.validation_status.value if artifact and hasattr(artifact.validation_status, "value") else str(result.overall_verdict.value)
        confirmation_reason = (
            f"Vulnerability '{result.vulnerability_candidate or 'BOLA_IDOR'}' validated: "
            f"Testing role '{testing_role}' successfully retrieved protected resource data owned by '{result.owner_role.value}'."
            if result.is_confirmed
            else f"Status {val_status}: {result.summary}"
        )

        return {
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "target_url": result.resolved_url,
            "endpoint": result.endpoint,
            "method": result.method,
            "testing_role": testing_role,
            "baseline_response": baseline_resp_data,
            "comparison_response": comp_resp_data,
            "sanitized_evidence": sanitized_ev,
            "response_hashes": response_hashes,
            "validation_status": val_status,
            "confirmation_reason": confirmation_reason,
        }

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
    json_body: Optional[Dict[str, Any]] = None,
    admin_policy: str = "policy_dependent",
    safe_test_fixture: bool = False,
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
        json_body=json_body,
        admin_policy=admin_policy,
        safe_test_fixture=safe_test_fixture,
    )
