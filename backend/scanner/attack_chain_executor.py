"""Multi-Endpoint Attack-Chain Execution, Validation, and Verification Engine.

Member 2 Core Responsibility:
Accepts candidate attack chains from Member 1's planner (or structured candidate objects),
performs deterministic security and scope validation, executes multi-step chains across
the four testing roles (Anonymous, User A, User B, Admin), extracts and binds resource
identifiers between dependent steps, verifies authorization boundaries with cryptographic
evidence, computes deterministic severity and remediation, and persists findings to SQLite.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from pydantic import BaseModel, Field

from backend.agent.attack_chain import (
    AttackChainCandidate,
    AttackChainStep,
    ChainScenario,
    InputBinding,
    RelationshipType,
)
from backend.analysis.evidence_validator import (
    EvidenceValidationStatus,
    EvidenceValidator,
)
from backend.analysis.remediation import RemediationEngine, RemediationRecommendation
from backend.agent.schemas import ConfidenceLevel
from backend.analysis.severity_engine import DeterministicSeverityResult, SeverityEngine
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, RoleSession, SessionManager
from backend.scanner.authorization_tester import DESTRUCTIVE_MODIFICATION_KEYS
from backend.scanner.endpoint_discovery import DiscoveredEndpoint, EndpointCategory
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.scanner.response_analyzer import AccessVerdict, ResponseAnalyzer
from backend.scanner.source_analyzer import FindingClassification
from backend.storage.finding_repository import FindingRepository
from backend.storage.models import (
    EvidenceArtifact,
    FindingRecord,
    FindingStatus,
    SeverityLevel,
    VulnerabilityType,
)
from backend.utils.helpers import (
    AuthScopeException,
    MissingSessionError,
    ScopeViolationError,
    UnsupportedMethodError,
    compute_sha256,
    redact_sensitive_text,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_TEMPLATE_REGEX = re.compile(r"\{([A-Za-z0-9_]+)\}|:([A-Za-z0-9_]+)")
_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH"}
_IDENTIFIER_FIELDS = {
    "id",
    "userid",
    "user_id",
    "basketid",
    "basket_id",
    "orderid",
    "order_id",
    "addressid",
    "address_id",
    "cardid",
    "card_id",
    "documentid",
    "document_id",
    "productid",
    "product_id",
    "resourceid",
    "resource_id",
}


# ==============================================================================
# Execution Enums & Models
# ==============================================================================


class ChainExecutionStatus(str, Enum):
    """Overall outcome of a multi-step attack chain execution."""
    CONFIRMED = "CONFIRMED"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
    BLOCKED_BY_SAFETY = "BLOCKED_BY_SAFETY"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class StepExecutionStatus(str, Enum):
    """Execution status of an individual chain step."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class ChainValidationResult(BaseModel):
    """Result of deterministic pre-execution validation of an attack chain."""
    is_valid: bool
    chain_id: str
    scenario: str
    step_count: int
    rejection_reasons: List[str] = Field(default_factory=list)
    validated_target_url: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)


class StepExecutionResult(BaseModel):
    """Telemetry, evidence, and authorization evaluation for a single executed step."""
    step_id: str
    endpoint_path: str
    resolved_url: str
    method: str
    role_used: str
    status_code: int
    is_success: bool
    status: StepExecutionStatus
    verdict: AccessVerdict
    response_excerpt: str
    extracted_identifiers: Dict[str, str] = Field(default_factory=dict)
    expected_behavior: str
    actual_behavior: str
    resource_ownership_result: Optional[str] = None
    permission_evaluated: Optional[str] = None
    evidence_artifact_id: Optional[str] = None
    evidence_sha256: Optional[str] = None
    error_message: Optional[str] = None


class ChainExecutionResult(BaseModel):
    """Complete multi-endpoint attack chain execution and verification record."""
    chain_id: str
    chain_name: str
    scenario: str
    target_url: str
    scan_id: str
    status: ChainExecutionStatus
    is_confirmed: bool
    steps_executed: int
    total_steps: int
    step_results: List[StepExecutionResult] = Field(default_factory=list)
    extracted_context: Dict[str, str] = Field(default_factory=dict)
    vulnerability_category: str
    severity: str
    confidence: str
    remediation_steps: List[str] = Field(default_factory=list)
    remediation_code_patch: Optional[str] = None
    finding_id: Optional[str] = None
    summary: str
    reproducibility_steps: List[str] = Field(default_factory=list)
    execution_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ==============================================================================
# Chain Validation Engine
# ==============================================================================


class AttackChainValidator:
    """Performs strict, deterministic security and scope validation on attack chains.

    Enforces:
    1. Authorized target validation via ScopeGuard.
    2. Every step endpoint belongs strictly to allowed scope.
    3. Permitted HTTP methods only (rejecting destructive DELETE/DROP).
    4. Safe modification payloads (no destructive keys).
    5. Valid parameter and binding references.
    6. Prerequisite dependencies reference prior steps only (acyclic).
    7. Chain length bounded between 2 and 5 steps.
    8. Selected testing roles are recognized and authenticated where required.
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        session_manager: Optional[SessionManager] = None,
        base_url: str = "http://localhost:3000",
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager(load_from_env=True)
        self.base_url = base_url.rstrip("/")

    def validate_chain(
        self,
        chain: Union[AttackChainCandidate, Dict[str, Any]],
        target_url: Optional[str] = None,
        role_override: Optional[Union[Role, str]] = None,
    ) -> ChainValidationResult:
        """Deterministically validates a candidate attack chain before execution."""
        base = (target_url or self.base_url).rstrip("/")
        rejection_reasons: List[str] = []
        warnings: List[str] = []

        # Coerce candidate to dictionary representation
        data = chain.model_dump() if isinstance(chain, AttackChainCandidate) else dict(chain)
        chain_id = str(data.get("candidate_id") or data.get("chain_id") or f"chain_{uuid.uuid4().hex[:8]}")
        scenario = str(data.get("scenario") or "BOLA_IDOR")
        steps = data.get("steps") or []

        # 1. Target scope validation
        target_check = self.scope_guard.validate_request(url=f"{base}/", method="GET")
        if not target_check.is_allowed:
            rejection_reasons.append(
                f"Target URL '{base}' is not authorized: {target_check.reason}"
            )

        # 2. Bounded chain length check
        if not (2 <= len(steps) <= 5):
            rejection_reasons.append(
                f"Chain step count ({len(steps)}) must be between 2 and 5."
            )

        # 3. Step-by-step validation
        seen_step_ids: Set[str] = set()

        for idx, step_data in enumerate(steps):
            step_id = str(step_data.get("step_id") or f"step-{idx + 1}")
            path = str(step_data.get("path") or step_data.get("endpoint_path") or "")
            method = str(step_data.get("method") or "GET").strip().upper()

            # Unique step ID check
            if step_id in seen_step_ids:
                rejection_reasons.append(f"Duplicate step_id '{step_id}' found in chain.")
            seen_step_ids.add(step_id)

            # Path format check
            if not path or not path.startswith("/") or "\\" in path or ".." in path:
                rejection_reasons.append(
                    f"Step '{step_id}': Invalid relative path '{path}'."
                )

            # Permitted HTTP methods check (No DELETE)
            if method not in _ALLOWED_METHODS or method == "DELETE":
                rejection_reasons.append(
                    f"Step '{step_id}': HTTP method '{method}' is not permitted. Only non-destructive methods {_ALLOWED_METHODS} are allowed."
                )

            # ScopeGuard endpoint validation (test representative URL)
            test_path = _TEMPLATE_REGEX.sub("1", path)
            full_test_url = f"{base}/{test_path.lstrip('/')}"
            step_scope = self.scope_guard.validate_request(url=full_test_url, method=method)
            if not step_scope.is_allowed:
                rejection_reasons.append(
                    f"Step '{step_id}': Endpoint '{path}' violates scope: {step_scope.reason}"
                )

            # Dependency & input bindings check
            depends_on = step_data.get("depends_on_step_ids") or []
            for dep in depends_on:
                if dep not in seen_step_ids or dep == step_id:
                    rejection_reasons.append(
                        f"Step '{step_id}': Prerequisite dependency '{dep}' is invalid or references a non-prior step."
                    )

            bindings = step_data.get("input_bindings") or []
            for b in bindings:
                b_src = b.get("source_step_id") if isinstance(b, dict) else getattr(b, "source_step_id", None)
                if b_src and b_src not in seen_step_ids:
                    rejection_reasons.append(
                        f"Step '{step_id}': Input binding source step '{b_src}' has not been executed prior to this step."
                    )

            # Check safe test payload if modification method
            if method in {"POST", "PUT", "PATCH"}:
                payload = step_data.get("json_body") or step_data.get("payload")
                if payload and isinstance(payload, dict):
                    destructive_keys = [
                        k for k in payload.keys()
                        if any(d in k.lower() for d in DESTRUCTIVE_MODIFICATION_KEYS)
                    ]
                    if destructive_keys:
                        rejection_reasons.append(
                            f"Step '{step_id}': Destructive keys {destructive_keys} detected in modification payload."
                        )

        # 4. Role authentication check
        if role_override:
            role_obj = Role(role_override) if not isinstance(role_override, Role) else role_override
            if role_obj != Role.ANONYMOUS and not self.session_manager.is_authenticated(role_obj):
                rejection_reasons.append(
                    f"Testing role '{role_obj.value}' lacks an active authenticated session."
                )

        is_valid = len(rejection_reasons) == 0
        return ChainValidationResult(
            is_valid=is_valid,
            chain_id=chain_id,
            scenario=scenario,
            step_count=len(steps),
            rejection_reasons=rejection_reasons,
            validated_target_url=base if is_valid else None,
            warnings=warnings,
        )


# ==============================================================================
# Multi-Step Attack-Chain Executor
# ==============================================================================


class AttackChainExecutor:
    """Executes multi-endpoint attack chains with cross-role authorization verification.

    Features:
    - Integrates the four testing roles: Anonymous, User A, User B, Admin.
    - Evaluates prerequisite success before executing dependent steps.
    - Resolves and passes parameters (IDOR/BOLA resource IDs) between steps.
    - Validates actual response data contrary to policy (never relying on HTTP 200 alone).
    - Signs evidence artifacts and persists findings into SQLite via FindingRepository.
    - Calculates deterministic severity via SeverityEngine.
    - Generates concrete remediation via RemediationEngine.
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        session_manager: Optional[SessionManager] = None,
        executor: Optional[RequestExecutor] = None,
        analyzer: Optional[ResponseAnalyzer] = None,
        validator: Optional[EvidenceValidator] = None,
        repository: Optional[FindingRepository] = None,
        severity_engine: Optional[SeverityEngine] = None,
        remediation_engine: Optional[RemediationEngine] = None,
        base_url: str = "http://localhost:3000",
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager(load_from_env=True)
        self.executor = executor or RequestExecutor(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
        )
        self.analyzer = analyzer or ResponseAnalyzer()
        self.validator = validator or EvidenceValidator()
        self.repository = repository or FindingRepository()
        self.severity_engine = severity_engine or SeverityEngine()
        self.remediation_engine = remediation_engine or RemediationEngine()
        self.chain_validator = AttackChainValidator(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
            base_url=base_url,
        )
        self.base_url = base_url.rstrip("/")

    def execute_chain(
        self,
        chain: Union[AttackChainCandidate, Dict[str, Any]],
        target_url: Optional[str] = None,
        scan_id: str = "default_chain_scan",
        role_assignments: Optional[Dict[str, Union[Role, str]]] = None,
        save_finding: bool = True,
    ) -> ChainExecutionResult:
        """Executes a multi-endpoint attack chain safely and verifies authorization boundaries."""
        base = (target_url or self.base_url).rstrip("/")
        role_assignments = role_assignments or {}

        # Step 1: Pre-execution validation
        validation = self.chain_validator.validate_chain(chain=chain, target_url=base)
        data = chain.model_dump() if isinstance(chain, AttackChainCandidate) else dict(chain)
        chain_id = validation.chain_id
        scenario = validation.scenario
        chain_name = str(data.get("chain_name") or f"{scenario} Attack Chain ({chain_id})")
        steps = data.get("steps") or []

        if not validation.is_valid:
            logger.warning(
                "Attack chain rejected by pre-execution validator",
                extra={"chain_id": chain_id, "reasons": validation.rejection_reasons},
            )
            blocked_status = (
                ChainExecutionStatus.BLOCKED_BY_SCOPE
                if any("scope" in r.lower() for r in validation.rejection_reasons)
                else ChainExecutionStatus.BLOCKED_BY_SAFETY
            )
            return ChainExecutionResult(
                chain_id=chain_id,
                chain_name=chain_name,
                scenario=scenario,
                target_url=base,
                scan_id=scan_id,
                status=blocked_status,
                is_confirmed=False,
                steps_executed=0,
                total_steps=len(steps),
                step_results=[],
                vulnerability_category=scenario,
                severity="NONE",
                confidence="LOW",
                summary=f"Attack chain '{chain_id}' was rejected: {'; '.join(validation.rejection_reasons)}",
            )

        # Step 2: Multi-step execution context
        extracted_context: Dict[str, str] = {}
        step_results: List[StepExecutionResult] = []
        confirmed_violation = False
        execution_failed = False
        last_evidence_artifact: Optional[EvidenceArtifact] = None
        vulnerable_step: Optional[StepExecutionResult] = None

        for idx, step_data in enumerate(steps):
            step_id = str(step_data.get("step_id") or f"step-{idx + 1}")
            path_template = str(step_data.get("path") or step_data.get("endpoint_path") or "")
            method = str(step_data.get("method") or "GET").strip().upper()
            depends_on = step_data.get("depends_on_step_ids") or []
            input_bindings = step_data.get("input_bindings") or []

            # Check prerequisites
            prereqs_met = True
            for dep in depends_on:
                matching_res = next((r for r in step_results if r.step_id == dep), None)
                if not matching_res or matching_res.status != StepExecutionStatus.SUCCESS:
                    prereqs_met = False
                    break

            if not prereqs_met:
                step_results.append(
                    StepExecutionResult(
                        step_id=step_id,
                        endpoint_path=path_template,
                        resolved_url="",
                        method=method,
                        role_used="NOT_EXECUTED",
                        status_code=0,
                        is_success=False,
                        status=StepExecutionStatus.BLOCKED,
                        verdict=AccessVerdict.NOT_TESTED,
                        response_excerpt="",
                        expected_behavior="Prerequisites must succeed before executing dependent step.",
                        actual_behavior="Prerequisite step failed; step skipped for safety.",
                        error_message="Prerequisite step failed or was skipped.",
                    )
                )
                continue

            # Resolve parameter bindings (e.g. {id} -> extracted resource ID)
            resolved_path = path_template
            for b in input_bindings:
                param = b.get("parameter") if isinstance(b, dict) else getattr(b, "parameter", None)
                src_step = b.get("source_step_id") if isinstance(b, dict) else getattr(b, "source_step_id", None)
                src_field = b.get("source_field", "resource_id") if isinstance(b, dict) else getattr(b, "source_field", "resource_id")

                # Lookup in context
                bound_val = (
                    extracted_context.get(f"{src_step}.{src_field}")
                    or extracted_context.get(f"{src_step}.id")
                    or extracted_context.get(f"{src_step}.resource_id")
                )
                if bound_val and param:
                    resolved_path = re.sub(r"\{" + re.escape(param) + r"\}", str(bound_val), resolved_path, flags=re.IGNORECASE)
                    resolved_path = re.sub(r":" + re.escape(param) + r"\b", str(bound_val), resolved_path, flags=re.IGNORECASE)

            # If template placeholders remain, check for fallback concrete ID or owned resource
            unresolved = _TEMPLATE_REGEX.findall(resolved_path)
            if unresolved:
                # Fallback to User A's registered basket/order or default fixture 1
                fallback_id = "1"
                for u in unresolved:
                    token_name = u[0] or u[1]
                    resolved_path = resolved_path.replace(f"{{{token_name}}}", fallback_id)
                    resolved_path = resolved_path.replace(f":{token_name}", fallback_id)

            resolved_url = f"{base}/{resolved_path.lstrip('/')}"

            # Determine testing role for this step
            step_role = self._resolve_step_role(
                step_id=step_id,
                step_data=step_data,
                role_assignments=role_assignments,
                step_index=idx,
                scenario=scenario,
            )

            # Execute HTTP probe through RequestExecutor
            try:
                self.scope_guard.assert_in_scope(resolved_url, method=method)
                json_payload = step_data.get("json_body") or step_data.get("payload")
                resp = self.executor.send_request(
                    role=step_role,
                    method=method,
                    url=resolved_url,
                    json_body=json_payload,
                )
            except AuthScopeException as exc:
                step_results.append(
                    StepExecutionResult(
                        step_id=step_id,
                        endpoint_path=resolved_path,
                        resolved_url=resolved_url,
                        method=method,
                        role_used=step_role.value,
                        status_code=0,
                        is_success=False,
                        status=StepExecutionStatus.FAILED,
                        verdict=AccessVerdict.NOT_TESTED,
                        response_excerpt="",
                        expected_behavior="Safe HTTP request execution within authorized scope.",
                        actual_behavior=f"Security guard rejected execution: {exc}",
                        error_message=str(exc),
                    )
                )
                execution_failed = True
                break

            # Extract resource identifiers from response body
            step_identifiers = self._extract_identifiers(resp.body)
            for k, v in step_identifiers.items():
                extracted_context[f"{step_id}.{k}"] = v
            if step_identifiers:
                first_val = next(iter(step_identifiers.values()))
                extracted_context[f"{step_id}.resource_id"] = first_val
                extracted_context[f"{step_id}.id"] = first_val

            # Evaluate step authorization & false positive prevention
            step_eval = self._evaluate_step_authorization(
                step_id=step_id,
                step_data=step_data,
                resolved_url=resolved_url,
                method=method,
                role=step_role,
                response=resp,
                scenario=scenario,
                step_index=idx,
                extracted_context=extracted_context,
            )
            step_results.append(step_eval)

            if step_eval.verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS:
                confirmed_violation = True
                vulnerable_step = step_eval
                # Create signed evidence artifact for the vulnerable pivot
                owner_role = (
                    Role.ADMIN if "ADMIN" in scenario or "admin" in resolved_path.lower() else Role.USER_A
                )
                artifact = self.validator.create_and_sign_evidence(
                    finding_id=f"fnd_chain_{chain_id[:8]}",
                    test_role=step_role,
                    authorized_role=owner_role,
                    method=method,
                    url=resolved_url,
                    headers=resp.headers,
                    response=resp,
                    endpoint=resolved_path,
                    resource_id=extracted_context.get(f"{step_id}.resource_id"),
                    expected_behavior=step_eval.expected_behavior,
                    actual_behavior=step_eval.actual_behavior,
                    validation_status=EvidenceValidationStatus.CONFIRMED,
                )
                last_evidence_artifact = artifact
                step_eval.evidence_artifact_id = artifact.evidence_id
                step_eval.evidence_sha256 = artifact.evidence_sha256

        # Step 3: Determine overall chain execution status
        if execution_failed:
            overall_status = ChainExecutionStatus.EXECUTION_FAILED
        elif confirmed_violation:
            overall_status = ChainExecutionStatus.CONFIRMED
        elif any(r.verdict == AccessVerdict.SUSPICIOUS_ACCESS for r in step_results):
            overall_status = ChainExecutionStatus.INCONCLUSIVE
        else:
            overall_status = ChainExecutionStatus.NOT_VULNERABLE

        # Step 4: Calculate severity and remediation for confirmed chain
        severity_str = "NONE"
        confidence_str = "LOW"
        remediation_steps: List[str] = []
        code_patch: Optional[str] = None
        finding_id: Optional[str] = None

        if overall_status == ChainExecutionStatus.CONFIRMED and vulnerable_step:
            vuln_cat = self._normalize_vulnerability_category(scenario, vulnerable_step.endpoint_path)
            # Deterministic SeverityEngine calculation with anti-inflation safeguards
            is_admin_impact = "admin" in vulnerable_step.endpoint_path.lower() or "ADMIN" in scenario
            ds = 3 if is_admin_impact else 2
            pg = 3 if is_admin_impact else 2
            ex = 3
            pi = 3 if is_admin_impact else 2
            ac = 1  # Multi-step chain has moderate complexity

            sev_res = self.severity_engine.calculate_from_factors(
                data_sensitivity=ds,
                privilege_gained=pg,
                exploitability=ex,
                potential_impact=pi,
                attack_complexity=ac,
                evidence_confidence=2,
            )
            severity_str = sev_res.final_severity.value
            confidence_str = sev_res.confidence.value

            # Remediation recommendation
            rec = self.remediation_engine.generate_recommendation(
                vulnerability_type=vuln_cat,
                endpoint=vulnerable_step.endpoint_path,
            )
            raw_steps = rec.remediation_steps
            if isinstance(raw_steps, str):
                split_steps = [s.strip() for s in raw_steps.split(". ") if s.strip()]
                remediation_steps = [s + ("." if not s.endswith(".") else "") for s in split_steps] if len(split_steps) > 1 else ([raw_steps] if raw_steps else [])
            elif isinstance(raw_steps, (list, tuple)):
                remediation_steps = [str(s) for s in raw_steps]
            else:
                remediation_steps = [str(raw_steps)] if raw_steps else []
            code_patch = getattr(rec, "code_patch_example", getattr(rec, "code_Patch_example", ""))

            # Persist finding to SQLite if requested
            if save_finding:
                finding_id = self._persist_chain_finding(
                    chain_id=chain_id,
                    chain_name=chain_name,
                    scenario=vuln_cat,
                    scan_id=scan_id,
                    target_url=base,
                    vulnerable_step=vulnerable_step,
                    step_results=step_results,
                    artifact=last_evidence_artifact,
                    severity=sev_res.final_severity,
                    confidence=sev_res.confidence,
                    remediation=rec,
                    extracted_context=extracted_context,
                )

        repro_steps = [
            f"1. Target authorized domain '{base}'.",
            *[
                f"{i + 2}. [{r.role_used}] Execute {r.method} {r.endpoint_path} -> HTTP {r.status_code} ({r.verdict.value})."
                for i, r in enumerate(step_results)
            ],
        ]
        if last_evidence_artifact:
            repro_steps.append(
                f"Evidence cryptographic SHA-256: {last_evidence_artifact.evidence_sha256}"
            )

        summary_msg = (
            f"Attack chain '{chain_id}' ({scenario}) completed across {len(step_results)} steps: "
            f"{overall_status.value}."
        )

        return ChainExecutionResult(
            chain_id=chain_id,
            chain_name=chain_name,
            scenario=scenario,
            target_url=base,
            scan_id=scan_id,
            status=overall_status,
            is_confirmed=(overall_status == ChainExecutionStatus.CONFIRMED),
            steps_executed=len(step_results),
            total_steps=len(steps),
            step_results=step_results,
            extracted_context=extracted_context,
            vulnerability_category=scenario,
            severity=severity_str,
            confidence=confidence_str,
            remediation_steps=remediation_steps,
            remediation_code_patch=code_patch,
            finding_id=finding_id,
            summary=summary_msg,
            reproducibility_steps=repro_steps,
        )

    # --------------------------------------------------------------------------
    # Helper & Evaluation Methods
    # --------------------------------------------------------------------------

    def _resolve_step_role(
        self,
        step_id: str,
        step_data: Dict[str, Any],
        role_assignments: Dict[str, Union[Role, str]],
        step_index: int,
        scenario: str,
    ) -> Role:
        """Determines the appropriate testing role for each step based on chain logic."""
        # 1. Explicit caller override
        if step_id in role_assignments:
            assigned = role_assignments[step_id]
            return Role(assigned) if not isinstance(assigned, Role) else assigned

        explicit_role = step_data.get("role") or step_data.get("testing_role") or step_data.get("role_used")
        if explicit_role:
            return Role(str(explicit_role).lower())

        # 2. Canonical chain semantics
        # Step 1: Baseline resource discovery (User A for BOLA/IDOR, Admin for Admin routes, Anonymous for public)
        if step_index == 0:
            if "ADMIN" in scenario:
                return Role.ADMIN if self.session_manager.is_authenticated(Role.ADMIN) else Role.USER_A
            return Role.USER_A if self.session_manager.is_authenticated(Role.USER_A) else Role.ANONYMOUS

        # Step 2+: Cross-user or unauthenticated probe
        if "PRIVILEGE" in scenario or "ADMIN" in scenario:
            return Role.USER_B if self.session_manager.is_authenticated(Role.USER_B) else Role.USER_A
        if "BOLA" in scenario or "IDOR" in scenario:
            return Role.USER_B if self.session_manager.is_authenticated(Role.USER_B) else Role.ANONYMOUS

        return Role.USER_B

    def _extract_identifiers(self, body_text: str) -> Dict[str, str]:
        """Extracts confirmed resource IDs from response JSON bodies."""
        if not body_text or not body_text.strip().startswith(("{", "[")):
            return {}
        extracted: Dict[str, str] = {}
        try:
            parsed = json.loads(body_text)
            self._walk_and_extract(parsed, extracted)
        except Exception:
            pass
        return extracted

    def _walk_and_extract(self, val: Any, out: Dict[str, str], prefix: str = "") -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                k_lower = k.lower().replace("-", "_")
                if k_lower in _IDENTIFIER_FIELDS or k_lower.endswith("_id") or k_lower.endswith("id"):
                    if isinstance(v, (str, int)) and str(v).strip():
                        out.setdefault(k_lower, str(v))
                if isinstance(v, (dict, list)):
                    self._walk_and_extract(v, out, prefix=f"{prefix}{k}.")
        elif isinstance(val, list):
            for item in val[:3]:
                if isinstance(item, (dict, list)):
                    self._walk_and_extract(item, out, prefix=prefix)

    def _evaluate_step_authorization(
        self,
        step_id: str,
        step_data: Dict[str, Any],
        resolved_url: str,
        method: str,
        role: Role,
        response: HttpResponseModel,
        scenario: str,
        step_index: int,
        extracted_context: Dict[str, str],
    ) -> StepExecutionResult:
        """Evaluates whether an individual step succeeded and whether an authorization breach occurred."""
        insp = self.analyzer.inspect_response(response)
        code = response.status_code
        status = StepExecutionStatus.SUCCESS if insp.is_http_success else StepExecutionStatus.FAILED

        # Default behaviors
        exp_behavior = (
            f"Endpoint should allow legitimate access for {role.value}."
            if step_index == 0
            else f"Protected resource should reject unauthorized role '{role.value}' with HTTP 401 or 403."
        )
        act_behavior = f"Role '{role.value}' received HTTP {code}."
        verdict = AccessVerdict.ALLOWED_ACCESS if insp.is_http_success else AccessVerdict.CORRECTLY_DENIED

        # False-positive filtering
        if insp.is_spa_html_fallback:
            act_behavior = "Received SPA HTML fallback shell under HTTP 200 (not vulnerable)."
            verdict = AccessVerdict.CORRECTLY_DENIED
            status = StepExecutionStatus.SUCCESS
        elif insp.has_error_indicator and insp.is_http_success:
            act_behavior = "Received soft error envelope in JSON (not vulnerable)."
            verdict = AccessVerdict.CORRECTLY_DENIED
            status = StepExecutionStatus.SUCCESS
        elif insp.is_empty_payload and insp.is_http_success:
            act_behavior = "Received empty JSON payload (not vulnerable)."
            verdict = AccessVerdict.CORRECTLY_DENIED
            status = StepExecutionStatus.SUCCESS
        elif not insp.is_http_success:
            verdict = AccessVerdict.CORRECTLY_DENIED
            status = StepExecutionStatus.FAILED
            act_behavior = f"Request returned HTTP {code}."
        elif step_index > 0:
            if role in (Role.USER_B, Role.ANONYMOUS):
                verdict = AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS
                if "PRIVILEGE" in scenario or "admin" in resolved_url.lower():
                    act_behavior = (
                        f"Lower-privileged role '{role.value}' accessed administrative endpoint "
                        f"(HTTP {code}) and received administrative data."
                    )
                else:
                    act_behavior = (
                        f"Role '{role.value}' successfully accessed resource "
                        f"(HTTP {code}) and received structured data."
                    )
            else:
                verdict = AccessVerdict.ALLOWED_ACCESS
                act_behavior = f"Role '{role.value}' received HTTP {code} on step {step_index + 1}."

        return StepExecutionResult(
            step_id=step_id,
            endpoint_path=resolved_url.replace(self.base_url, ""),
            resolved_url=resolved_url,
            method=method,
            role_used=role.value,
            status_code=code,
            is_success=status == StepExecutionStatus.SUCCESS,
            status=status,
            verdict=verdict,
            response_excerpt=redact_sensitive_text(response.body[:500]),
            extracted_identifiers={k: v for k, v in extracted_context.items() if k.startswith(f"{step_id}.")},
            expected_behavior=exp_behavior,
            actual_behavior=act_behavior,
            resource_ownership_result=(
                "CROSS_USER_ACCESS" if verdict == AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS else "PROTECTED"
            ),
        )

    def _normalize_vulnerability_category(self, scenario: str, endpoint: str) -> str:
        s_upper = scenario.upper()
        if "PRIVILEGE" in s_upper or "BFLA" in s_upper or "admin" in endpoint.lower():
            return "BFLA"
        if "BOLA" in s_upper or "IDOR" in s_upper or "RELATED" in s_upper:
            return "BOLA_IDOR"
        return "MULTI_STEP_CHAIN"

    def _persist_chain_finding(
        self,
        chain_id: str,
        chain_name: str,
        scenario: str,
        scan_id: str,
        target_url: str,
        vulnerable_step: StepExecutionResult,
        step_results: List[StepExecutionResult],
        artifact: Optional[EvidenceArtifact],
        severity: SeverityLevel,
        confidence: ConfidenceLevel,
        remediation: RemediationRecommendation,
        extracted_context: Dict[str, str],
    ) -> str:
        """Persists a confirmed attack chain finding to SQLite via FindingRepository."""
        f_id = f"fnd_chain_{chain_id[:8]}_{uuid.uuid4().hex[:4]}"
        explanation = (
            f"Multi-step attack chain '{chain_name}' successfully demonstrated {scenario} on "
            f"'{vulnerable_step.endpoint_path}' using role '{vulnerable_step.role_used}'."
        )

        finding_rec = FindingRecord(
            id=f_id,
            scan_id=scan_id,
            title=f"Multi-Endpoint Attack Chain: {scenario} on {vulnerable_step.endpoint_path}",
            vulnerability_category=VulnerabilityType.MULTI_STEP_CHAIN.value,
            vulnerability_type=scenario,
            severity=severity,
            confidence=confidence,
            status=FindingStatus.CONFIRMED.value,
            confirmation_status=FindingStatus.CONFIRMED.value,
            validation_status=EvidenceValidationStatus.CONFIRMED.value,
            endpoint=vulnerable_step.endpoint_path,
            target_endpoint=vulnerable_step.endpoint_path,
            http_method=vulnerable_step.method,
            resource_id=extracted_context.get(f"{vulnerable_step.step_id}.resource_id"),
            affected_roles=[vulnerable_step.role_used],
            affected_role=vulnerable_step.role_used,
            access_verdict=AccessVerdict.CONFIRMED_UNAUTHORIZED_ACCESS.value,
            classification=FindingClassification.CONFIRMED_RUNTIME_VULNERABILITY.value,
            description=explanation,
            impact_explanation=explanation,
            expected_behavior=vulnerable_step.expected_behavior,
            actual_behavior=vulnerable_step.actual_behavior,
            remediation_guidance=getattr(remediation, "code_patch_example", getattr(remediation, "code_Patch_example", "")),
            remediation_recommendation=(
                remediation.remediation_steps
                if isinstance(remediation.remediation_steps, str)
                else "\n".join(remediation.remediation_steps)
            ),
            evidence=artifact,
            evidence_reference=artifact.evidence_id if artifact else None,
            technical_details={
                "chain_id": chain_id,
                "chain_name": chain_name,
                "scenario": scenario,
                "vulnerable_step_id": vulnerable_step.step_id,
                "vulnerable_endpoint": vulnerable_step.endpoint_path,
                "http_method": vulnerable_step.method,
                "testing_role": vulnerable_step.role_used,
                "steps": [s.model_dump() for s in step_results],
                "extracted_context": extracted_context,
                "risk_assessment": {
                    "severity": severity.value,
                    "confidence": confidence.value,
                    "cwe_reference": remediation.cwe_reference,
                    "owasp_reference": remediation.owasp_reference,
                },
                "reproducibility_steps": [
                    f"1. Target base URL: {target_url}",
                    *[
                        f"{i + 2}. [{s.role_used}] {s.method} {s.endpoint_path} -> HTTP {s.status_code}"
                        for i, s in enumerate(step_results)
                    ],
                ],
            },
        )
        self.repository.save_finding(finding_rec)
        logger.info(
            "Persisted confirmed attack chain finding to SQLite",
            extra={"finding_id": f_id, "chain_id": chain_id, "scan_id": scan_id},
        )
        return f_id
