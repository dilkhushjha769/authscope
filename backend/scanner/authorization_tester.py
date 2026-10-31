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
