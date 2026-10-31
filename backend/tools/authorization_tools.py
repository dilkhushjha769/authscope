"""Authorization Testing Tools for AuthScope Tool Registry.

Exposes controlled authorization-differential testing, IDOR detection, and
access-control discrepancy analysis backed by AuthorizationTester.
"""

from typing import Dict, Any, List, Optional

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.endpoint_discovery import EndpointDiscovery
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.tools.schemas import (
    CompareEndpointAccessInput,
    CompareEndpointAccessOutput,
    DetectIdorInput,
    DetectIdorOutput,
    RoleComparisonResult,
    TestAccessControlInput,
    TestAccessControlOutput,
    ToolExecutionContext,
)
from backend.utils.helpers import InvalidDataError, InvalidTargetURLError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class AuthorizationTools:
    """Provides authorization testing tools backed by AuthorizationTester."""

    def __init__(
        self,
        tester: Optional[AuthorizationTester] = None,
        scope_guard: Optional[ScopeGuard] = None,
        session_manager: Optional[SessionManager] = None,
        executor: Optional[RequestExecutor] = None
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager()
        self.executor = executor or RequestExecutor(scope_guard=self.scope_guard)
        self.tester = tester or AuthorizationTester(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
            executor=self.executor
        )

    def _parse_role(self, role_str: str) -> Role:
        """Parses role string to Role enum with safety validation."""
        role_map = {
            "ANONYMOUS": Role.ANONYMOUS,
            "USER_A": Role.USER_A,
            "USER_B": Role.USER_B,
            "ADMIN": Role.ADMIN,
        }
        upper_role = role_str.strip().upper()
        if upper_role not in role_map:
            raise InvalidDataError(
                f"Invalid role '{role_str}'. Permitted roles: {list(role_map.keys())}"
            )
        return role_map[upper_role]

    def compare_endpoint_access(
        self,
        payload: CompareEndpointAccessInput,
        context: Optional[ToolExecutionContext] = None
    ) -> CompareEndpointAccessOutput:
        """Executes multi-role authorization-differential testing on an endpoint."""
        owner = self._parse_role(payload.owner_role)
        test_roles = [self._parse_role(r) for r in payload.test_roles]

        human_approved = context.human_approved if context else False

        result = self.tester.test_resource_access(
            endpoint=payload.endpoint,
            owner_role=owner,
            test_roles=test_roles,
            resource_id=payload.resource_id,
            method="GET",
            human_approved=human_approved
        )

        role_results: List[RoleComparisonResult] = []
        for role, outcome in result.probe_outcomes.items():
            role_results.append(
                RoleComparisonResult(
                    role=role.value,
                    status_code=outcome.response.status_code,
                    verdict=outcome.verdict.value if hasattr(outcome.verdict, "value") else str(outcome.verdict),
                    is_access_granted=200 <= outcome.response.status_code < 300
                )
            )

        summary = (
            f"Endpoint '{payload.endpoint}' tested against {len(test_roles)} roles. "
            f"Discrepancy: {result.is_discrepancy_detected}, Confirmed: {result.is_confirmed}."
        )

        return CompareEndpointAccessOutput(
            endpoint=payload.endpoint,
            resolved_url=result.resolved_url,
            resource_id=result.resource_id,
            is_discrepancy_detected=result.is_discrepancy_detected,
            is_confirmed=result.is_confirmed,
            vulnerability_candidate=result.vulnerability_candidate,
            role_results=role_results,
            summary=summary
        )

    def test_access_control(
        self,
        payload: TestAccessControlInput,
        context: Optional[ToolExecutionContext] = None
    ) -> TestAccessControlOutput:
        """Tests access control on an endpoint for a single role."""
        target_role = self._parse_role(payload.role)
        diff_res = self.tester.test_resource_access(
            endpoint=payload.endpoint,
            owner_role=Role.USER_A,
            test_roles=[target_role],
            resource_id=payload.resource_id,
            method="GET",
            human_approved=context.human_approved if context else False
        )

        outcome = diff_res.probe_outcomes.get(target_role)
        if outcome:
            status_code = outcome.response.status_code
            verdict = outcome.verdict.value if hasattr(outcome.verdict, "value") else str(outcome.verdict)
            evidence_id = outcome.evidence.evidence_id if outcome.evidence else None
        else:
            status_code = 0
            verdict = "UNTESTED"
            evidence_id = None

        return TestAccessControlOutput(
            endpoint=payload.endpoint,
            role=payload.role,
            status_code=status_code,
            verdict=verdict,
            is_access_granted=200 <= status_code < 300,
            evidence_id=evidence_id
        )

    def detect_idor(
        self,
        payload: DetectIdorInput,
        context: Optional[ToolExecutionContext] = None
    ) -> DetectIdorOutput:
        """Specialized test verifying if an attacker role can access a victim-owned resource."""
        attacker = self._parse_role(payload.attacker_role)
        diff_res = self.tester.test_resource_access(
            endpoint=payload.endpoint_template,
            owner_role=Role.USER_A,
            test_roles=[attacker],
            resource_id=payload.victim_resource_id,
            method="GET",
            human_approved=context.human_approved if context else False
        )

        is_idor = (
            diff_res.is_discrepancy_detected
            and diff_res.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
        )
        vulnerability_title = "Broken Object Level Authorization (BOLA/IDOR)" if is_idor else None
        summary = (
            f"Tested resource '{payload.victim_resource_id}' with attacker '{payload.attacker_role}'. "
            f"IDOR detected: {is_idor}."
        )

        return DetectIdorOutput(
            is_idor_detected=is_idor,
            victim_resource_id=payload.victim_resource_id,
            attacker_role=payload.attacker_role,
            evidence_summary=summary,
            vulnerability_title=vulnerability_title
        )
