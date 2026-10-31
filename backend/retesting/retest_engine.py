"""Evidence-grounded, non-destructive verification of previously confirmed findings."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.core.target_registry import TargetRegistry
from backend.scanner.authorization_tester import AuthorizationTester
from backend.scanner.response_analyzer import AccessVerdict
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import RetestLogRecord
from backend.utils.helpers import AuthScopeException, MissingSessionError, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)
VERIFICATION_STATUSES = {
    "FIXED", "STILL VULNERABLE", "PARTIALLY FIXED", "INCONCLUSIVE", "NOT_TESTED"
}


class RetestEngine:
    """Replays the original GET authorization comparison with current scope and sessions."""

    def __init__(
        self,
        repository: FindingRepository,
        tester: AuthorizationTester | None = None,
        scope_guard: ScopeGuard | None = None,
        session_manager: SessionManager | None = None,
        base_url: str | None = None,
    ) -> None:
        self.repository = repository
        self.scope_guard = scope_guard or (tester.scope_guard if tester else ScopeGuard())
        self.session_manager = session_manager or (tester.session_manager if tester else SessionManager(load_from_env=True))
        self.tester = tester or AuthorizationTester(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
            base_url=base_url or "http://localhost:3000",
        )

    def retest_finding(self, finding_id: str) -> RetestLogRecord:
        """Replay original evidence's GET vector and classify only from engine evidence."""
        finding = self.repository.get_finding(finding_id)
        if finding is None:
            return self._record(finding_id, "NOT_TESTED", "The original finding could not be loaded.")

        # Dispatch multi-step attack chains to chain retest engine
        if (
            finding.vulnerability_category == "MULTI_STEP_CHAIN"
            or (finding.technical_details and "chain_id" in finding.technical_details)
        ):
            return self.retest_attack_chain(finding_id)

        original = finding.evidence
        if not original or not original.request_url or not original.evidence_sha256:
            return self._record(
                finding_id, "INCONCLUSIVE",
                "Original signed request evidence is missing; no retest request was sent.",
                previous_status=finding.status,
            )
        if not self._original_evidence_is_valid(original):
            return self._record(
                finding_id, "INCONCLUSIVE",
                "Original evidence failed integrity validation; no retest request was sent.",
                previous_status=finding.status,
            )
        if original.request_method.upper() != "GET" or finding.http_method.upper() != "GET":
            return self._record(
                finding_id, "NOT_TESTED", "Only the original GET verification vector is permitted.",
                previous_status=finding.status,
            )

        assessment_scope = self._assessment_scope(finding)
        if assessment_scope is None:
            return self._record(
                finding_id, "NOT_TESTED", "The assessment has no active authorized target profile; no request was sent.",
                previous_status=finding.status,
            )
        assessment = self.repository.get_scan_session(finding.scan_id)
        if assessment is not None:
            target_check = assessment_scope.validate_request(url=assessment.target_url, method="GET")
            if not target_check.is_allowed:
                return self._record(
                    finding_id, "NOT_TESTED", "Assessment target is no longer authorized; no request was sent.",
                    previous_status=finding.status, detail={"scope_reason": target_check.reason},
                )

        scope = assessment_scope.validate_request(url=original.request_url, method="GET")
        if not scope.is_allowed:
            return self._record(
                finding_id, "NOT_TESTED", "Scope validation failed; no request was sent.",
                previous_status=finding.status,
                detail={"scope_reason": scope.reason},
            )

        try:
            owner = Role(original.authorized_role)
            tester_role = Role(original.test_role or finding.affected_role)
            if owner == tester_role:
                return self._record(finding_id, "INCONCLUSIVE", "Original owner and test roles are not distinct.", previous_status=finding.status)
            self.session_manager.require_authenticated_session(owner)
            self.session_manager.require_authenticated_session(tester_role)
            result = self.tester.test_resource_access(
                endpoint=original.request_url,
                owner_role=owner,
                test_roles=[tester_role],
                resource_id=original.resource_id or finding.resource_id,
                method="GET",
            )
        except MissingSessionError as exc:
            return self._record(
                finding_id, "NOT_TESTED", "A required test identity is unavailable; no result was inferred.",
                previous_status=finding.status, detail={"reason": str(exc)},
            )
        except AuthScopeException as exc:
            logger.warning("Fix verification could not execute", extra={"finding_id": finding_id, "error_type": type(exc).__name__})
            return self._record(
                finding_id, "NOT_TESTED", "The safe scoped retest could not run.",
                previous_status=finding.status, detail={"reason": str(exc)},
            )

        owner_probe = result.probe_outcomes.get(owner)
        test_probe = result.probe_outcomes.get(tester_role)
        owner_baseline_valid = bool(owner_probe and owner_probe.verdict == AccessVerdict.ALLOWED_ACCESS)
        denial_evidence: dict[str, Any] | None = None
        if not owner_baseline_valid or test_probe is None:
            status = "INCONCLUSIVE"
        elif test_probe.verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS and result.is_confirmed:
            status = "STILL VULNERABLE"
        elif test_probe.verdict == AccessVerdict.CORRECTLY_DENIED:
            denial_evidence = self._sign_denial_evidence(finding, original, owner, tester_role, test_probe)
            status = "FIXED" if denial_evidence else "INCONCLUSIVE"
        elif test_probe.verdict == AccessVerdict.SUSPICIOUS_ACCESS:
            status = "INCONCLUSIVE"
        else:
            status = "INCONCLUSIVE"

        before = {
            "finding_title": finding.title,
            "severity": str(getattr(finding.severity, "value", finding.severity)),
            "assessment_status": assessment.status if assessment else "unknown",
            "endpoint": redact_sensitive_text(original.request_url),
            "method": original.request_method,
            "owner_role": str(getattr(original.authorized_role, "value", original.authorized_role)),
            "test_role": str(getattr(original.test_role, "value", original.test_role)),
            "response_status": original.response_status,
            "evidence_excerpt": original.sanitized_response_evidence[:1000],
            "security_behavior": original.actual_behavior,
            "evidence_sha256": original.evidence_sha256,
            "finding_status": str(getattr(finding.status, "value", finding.status)),
        }
        after = self._after_evidence(result, owner, tester_role)
        if denial_evidence:
            after["verification_evidence"] = denial_evidence
        regression_checks = self._run_regression_checks(finding, original, owner, tester_role) if status == "FIXED" else {
            "status": "NOT_TESTED", "reason": "Related-route checks run only after the original test is denied."
        }
        if regression_checks.get("confirmed_vulnerable"):
            status = "PARTIALLY FIXED"
        details: dict[str, Any] = {
            "before": before,
            "after": after,
            "engine_verdict": result.overall_verdict.value,
            "owner_baseline_valid": owner_baseline_valid,
            "regression_checks": regression_checks,
        }
        summary = self._explanation(status, before, after)
        return self._record(finding_id, status, summary, previous_status=finding.status, detail=details)

    def retest_attack_chain(self, finding_id: str) -> RetestLogRecord:
        """Replays a multi-endpoint attack chain sequence to verify whether the vulnerability is fixed."""
        finding = self.repository.get_finding(finding_id)
        if finding is None:
            return self._record(finding_id, "NOT_TESTED", "The original finding could not be loaded.")

        tech_details = finding.technical_details or {}
        steps_data = tech_details.get("steps") or []
        chain_id = tech_details.get("chain_id") or finding_id
        if not steps_data or len(steps_data) < 2:
            return self._record(
                finding_id,
                "INCONCLUSIVE",
                "Original attack chain step telemetry is incomplete or missing.",
                previous_status=finding.status,
            )

        assessment_scope = self._assessment_scope(finding)
        if assessment_scope is None:
            return self._record(
                finding_id,
                "NOT_TESTED",
                "The assessment has no active authorized target profile; no request was sent.",
                previous_status=finding.status,
            )

        from backend.scanner.attack_chain_executor import (
            AttackChainExecutor,
            ChainExecutionStatus,
            StepExecutionStatus,
        )

        target_base_url = getattr(
            self.tester,
            "base_url",
            getattr(getattr(self.tester, "discovery", None), "base_url", "http://localhost:3000"),
        )
        executor = AttackChainExecutor(
            scope_guard=assessment_scope,
            session_manager=self.session_manager,
            executor=self.tester.executor,
            analyzer=self.tester.analyzer,
            validator=getattr(self.tester, "evidence_validator", None),
            repository=self.repository,
            base_url=target_base_url,
        )

        candidate_dict = {
            "candidate_id": chain_id,
            "scenario": tech_details.get("scenario") or finding.vulnerability_type,
            "chain_name": tech_details.get("chain_name") or finding.title,
            "steps": steps_data,
        }

        retest_run = executor.execute_chain(
            chain=candidate_dict,
            target_url=target_base_url,
            scan_id=finding.scan_id,
            save_finding=False,
        )

        vulnerable_step_id = tech_details.get("vulnerable_step_id")
        orig_vulnerable_step = next(
            (s for s in steps_data if s.get("step_id") == vulnerable_step_id),
            steps_data[-1] if steps_data else None,
        )

        before_summary = {
            "chain_id": chain_id,
            "vulnerable_step_id": vulnerable_step_id,
            "vulnerable_endpoint": orig_vulnerable_step.get("endpoint_path") if orig_vulnerable_step else None,
            "method": orig_vulnerable_step.get("method") if orig_vulnerable_step else None,
            "role_used": orig_vulnerable_step.get("role_used") if orig_vulnerable_step else None,
            "original_status": orig_vulnerable_step.get("status_code") if orig_vulnerable_step else None,
            "finding_status": str(getattr(finding.status, "value", finding.status)),
        }

        after_summary = {
            "status": retest_run.status.value,
            "steps_executed": retest_run.steps_executed,
            "step_results": [
                {
                    "step_id": s.step_id,
                    "endpoint": s.endpoint_path,
                    "role": s.role_used,
                    "status_code": s.status_code,
                    "verdict": s.verdict.value,
                }
                for s in retest_run.step_results
            ],
        }

        if retest_run.status == ChainExecutionStatus.CONFIRMED:
            status = "STILL VULNERABLE"
            summary = "The tested attack chain still demonstrated unauthorized cross-user access. The vulnerability remains."
        elif retest_run.status == ChainExecutionStatus.NOT_VULNERABLE:
            status = "FIXED"
            summary = "The attack chain baseline was validated, but subsequent unauthorized requests were correctly denied. The attack chain issue is fixed."
        elif retest_run.status in (ChainExecutionStatus.BLOCKED_BY_SCOPE, ChainExecutionStatus.BLOCKED_BY_SAFETY):
            status = "NOT_TESTED"
            summary = f"Chain retest was blocked: {retest_run.summary}"
        else:
            status = "INCONCLUSIVE"
            summary = "The chain retest did not collect conclusive evidence."

        if status == "FIXED":
            finding.status = "remediated"
            finding.confirmation_status = "remediated"
            finding.retest_status = "fixed"
        elif status in {"STILL VULNERABLE", "PARTIALLY FIXED"}:
            finding.retest_status = status.lower()
        else:
            finding.retest_status = status.lower()
        self.repository.save_finding(finding)

        details = {
            "before": before_summary,
            "after": after_summary,
            "chain_execution": retest_run.model_dump(),
        }
        return self._record(finding_id, status, summary, previous_status=finding.status, detail=details)

    def _sign_denial_evidence(self, finding: Any, original: Any, owner: Role, tester_role: Role, probe: Any) -> dict[str, Any] | None:
        """Sign the denial response and require evidence completeness before calling it fixed."""
        from backend.analysis.evidence_validator import EvidenceValidationStatus, EvidenceValidator

        validator = getattr(self.tester, "evidence_validator", None) or EvidenceValidator()
        try:
            artifact = validator.create_and_sign_evidence(
                finding_id=finding.id,
                test_role=tester_role,
                authorized_role=owner,
                method="GET",
                url=original.request_url,
                headers=self.session_manager.get_session(tester_role).get_headers(),
                response=probe.response,
                endpoint=finding.target_endpoint,
                resource_id=original.resource_id or finding.resource_id,
                expected_behavior="A non-owner identity must not receive the protected resource.",
                actual_behavior=f"The controlled comparison denied the non-owner request with HTTP {probe.response.status_code}.",
                validation_status=EvidenceValidationStatus.SUSPICIOUS,
            )
        except (AuthScopeException, ValueError, TypeError):
            return None
        if not validator.validate_artifact_completeness(artifact):
            return None
        return {
            "response_status": artifact.response_status,
            "evidence_sha256": artifact.evidence_sha256,
            "sanitized_excerpt": artifact.sanitized_response_evidence[:500],
            "validation_status": "COMPLETE_DENIAL_EVIDENCE",
        }

    @staticmethod
    def _original_evidence_is_valid(evidence: Any) -> bool:
        """Validate stored signature lazily to avoid scanner package import cycles."""
        from backend.analysis.evidence_validator import EvidenceValidator

        return EvidenceValidator().validate_artifact_completeness(evidence)

    def _run_regression_checks(self, finding: Any, original: Any, owner: Role, test_role: Role) -> dict[str, Any]:
        """Probe at most three discovered same-resource GET routes with explicit ownership proof."""
        session = self.repository.get_scan_session(finding.scan_id)
        if session is None or not original.resource_id:
            return {"status": "NOT_TESTED", "reason": "Assessment inventory or concrete resource ID is unavailable.", "checked": []}
        owner_session = self.session_manager.require_authenticated_session(owner)
        inventory = self.repository.list_discovered_endpoints(finding.scan_id)
        original_path, _, _ = self.tester._resolve_target_endpoint(
            endpoint=original.request_url, method="GET", resource_id=original.resource_id,
            owner_role=owner,
        )
        candidates = []
        for entry in inventory:
            if entry.method.upper() != "GET" or entry.path == original_path.path:
                continue
            if entry.category != original_path.category.value:
                continue
            try:
                candidate = self.tester.discovery.register_endpoint(path=entry.path, method="GET")
            except AuthScopeException:
                continue
            if candidate.resource_type != original_path.resource_type or not candidate.requires_owner_match:
                continue
            if not candidate.resource_type or not owner_session.owns_resource(candidate.resource_type, original.resource_id):
                continue
            candidates.append(candidate)

        checked: list[dict[str, Any]] = []
        confirmed_vulnerable = False
        for candidate in candidates[:3]:
            check = self.scope_guard.validate_request(
                url=self.tester.discovery.build_concrete_url(candidate, resource_id=original.resource_id),
                method="GET",
            )
            if not check.is_allowed:
                checked.append({"endpoint": candidate.path, "status": "NOT_TESTED", "reason": "Scope validation failed."})
                continue
            try:
                regression = self.tester.test_resource_access(
                    endpoint=candidate, owner_role=owner, test_roles=[test_role],
                    resource_id=original.resource_id, method="GET",
                )
            except AuthScopeException:
                checked.append({"endpoint": candidate.path, "status": "NOT_TESTED", "reason": "Required control unavailable."})
                continue
            vulnerable = regression.is_confirmed and regression.overall_verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
            confirmed_vulnerable = confirmed_vulnerable or vulnerable
            checked.append({
                "endpoint": candidate.path,
                "status": "STILL VULNERABLE" if vulnerable else (
                    "FIXED" if regression.overall_verdict == AccessVerdict.CORRECTLY_DENIED else "INCONCLUSIVE"
                ),
                "summary": regression.summary,
            })
        return {
            "status": "COMPLETED" if checked else "NOT_TESTED",
            "checked": checked,
            "confirmed_vulnerable": confirmed_vulnerable,
            "reason": None if checked else "No same-resource discovered route had verified owner control.",
        }

    def _assessment_scope(self, finding: Any) -> ScopeGuard | None:
        """Bind a fresh guard to the assessment's current authorized target profile."""
        assessment = self.repository.get_scan_session(finding.scan_id)
        if assessment is None:
            # Direct unit/library use still receives the configured static hard scope.
            return self.scope_guard
        registry = TargetRegistry()
        profile_id = (assessment.config or {}).get("target_profile")
        profile = registry.repository.get_target_profile(profile_id) if profile_id else None
        if profile is None:
            from urllib.parse import urlsplit

            hostname = urlsplit(assessment.target_url).hostname
            profile = registry.repository.get_profile_by_hostname(hostname) if hostname else None
        if profile is None or not profile.is_active():
            return None
        bound = ScopeGuard(
            allowed_hosts=list(self.scope_guard.allowed_hosts),
            allowed_ports=list(self.scope_guard.allowed_ports),
            allowed_schemes=list(self.scope_guard.allowed_schemes),
            allowed_methods=list(self.scope_guard.allowed_methods),
            target_registry=registry,
            enable_dynamic_registry=True,
        )
        bound.bind_target_profile(profile)
        self.scope_guard = bound
        self.tester.scope_guard = bound
        self.tester.executor.scope_guard = bound
        self.tester.discovery.scope_guard = bound
        return bound

    @staticmethod
    def _after_evidence(result: Any, owner: Role, test_role: Role) -> dict[str, Any]:
        observations: dict[str, Any] = {}
        for role in (owner, test_role):
            probe = result.probe_outcomes.get(role)
            if probe is None:
                continue
            body = probe.response.body or ""
            sanitized_body = redact_sensitive_text(body)
            observations[role.value] = {
                "status": probe.response.status_code,
                "verdict": probe.verdict.value,
                "body_sha256": hashlib.sha256(sanitized_body.encode("utf-8")).hexdigest(),
                "body_excerpt": sanitized_body[:500],
                "evidence_sha256": probe.evidence.evidence_sha256 if probe.evidence else None,
            }
        return {"endpoint": redact_sensitive_text(result.resolved_url), "method": result.method, "roles": observations}

    @staticmethod
    def _explanation(status: str, before: dict[str, Any], after: dict[str, Any]) -> str:
        """Produce a deterministic plain-language explanation from engine-assigned status."""
        test_role = before["test_role"]
        if status == "FIXED":
            return "The owner account could still read the resource, while the tested account was denied access. This controlled comparison supports that the tested authorization issue is fixed."
        if status == "STILL VULNERABLE":
            return "The tested account could still access protected resource data in a verified comparison. The original authorization issue remains."
        if status == "PARTIALLY FIXED":
            return "The original endpoint now denies the tested account, but a related discovered route still reproduced the same access issue. The fix needs to cover that route too."
        return "The retest did not collect enough reliable evidence to decide whether the issue was fixed. Review the session, scope, and response evidence before drawing a conclusion."

    @staticmethod
    def _record(
        finding_id: str,
        status: str,
        summary: str,
        previous_status: Any = "unknown",
        detail: dict[str, Any] | None = None,
    ) -> RetestLogRecord:
        if status not in VERIFICATION_STATUSES:
            status = "INCONCLUSIVE"
        vulnerable = status in {"STILL VULNERABLE", "PARTIALLY FIXED"}
        return RetestLogRecord(
            id=f"verify_{uuid.uuid4().hex}", finding_id=finding_id,
            previous_status=str(getattr(previous_status, "value", previous_status)),
            new_status=status, is_vulnerable=vulnerable, summary=summary, notes=summary,
            differential_result=detail or {},
        )
