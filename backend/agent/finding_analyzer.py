"""Finding Analyzer: Evidence-driven cognitive analysis of authorization findings.

Converts structured security evidence into technically grounded vulnerability
narratives, root cause analyses, impact statements, and confirmation statuses
under strict anti-hallucination guardrails.

Architectural Guarantees:
1. Zero Network Operations: Operates purely on supplied Pydantic models in memory.
2. Trusted Metadata Enforcement: Confirmation status is determined solely by trusted
   evidence validation metadata, preventing Claude or any AI from independently
   upgrading an unvalidated finding to CONFIRMED.
3. Decoupled Pipeline: Separates evidence inspection and rule-based validation from
   AI narrative synthesis.
4. Dependency Injection: Accepts optional AI clients / mock providers for testing.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Set
import json
import re

from backend.agent.prompts import (
    SYSTEM_ANALYSIS_PROMPT,
    build_finding_analysis_prompt,
)
from backend.agent.schemas import (
    AffectedResource,
    ConfidenceLevel,
    ConfirmationStatus,
    EvidenceType,
    EvidenceValidation,
    FindingAnalysis,
    FindingAnalysisInput,
    SecurityEvidence,
    ValidationStatus,
    VulnerabilityCategory,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Helper Data Structures for Decoupled Evidence Processing
# ==============================================================================


@dataclass
class EvidenceInspectionResult:
    """Internal summary produced by inspecting raw security evidence."""
    evidence_types: Set[EvidenceType]
    affected_endpoints: Set[str]
    is_differential: bool
    has_contradictory_evidence: bool
    contradiction_details: List[str]
    missing_evidence_items: List[str]
    all_validated: bool
    any_inconclusive: bool
    observed_behaviors: List[str]
    expected_behaviors: List[str]


@dataclass
class VulnerabilityContext:
    """Determined contextual classification of the authorization flaw."""
    likely_category: VulnerabilityCategory
    failed_security_control: str
    technical_root_cause: str
    summary_title: str


class AIClientProtocol(Protocol):
    """Protocol for injected AI client to enable testing with mock providers."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        ...


# ==============================================================================
# Finding Analyzer Core Implementation
# ==============================================================================


class FindingAnalyzer:
    """Cognitive analyzer for security evidence and authorization vulnerability findings."""

    def __init__(self, ai_client: Optional[AIClientProtocol] = None):
        """Initializes the analyzer with optional injected AI client.

        Args:
            ai_client: Optional AI client or mock provider implementing `complete()`.
        """
        self.ai_client = ai_client

    def analyze(self, input_data: FindingAnalysisInput | Dict[str, Any]) -> FindingAnalysis:
        """Executes the complete finding analysis workflow.

        Args:
            input_data: Validated FindingAnalysisInput model or dictionary.

        Returns:
            Validated FindingAnalysis Pydantic model.
        """
        # Normalize dict input to FindingAnalysisInput if necessary
        if isinstance(input_data, dict):
            # Support legacy format gracefully if provided
            if "raw_evidence" in input_data and "security_evidence" not in input_data:
                input_model = self._convert_legacy_evidence(input_data["raw_evidence"])
            else:
                input_model = FindingAnalysisInput.model_validate(input_data)
        else:
            input_model = input_data

        logger.info(
            "Starting cognitive finding analysis",
            extra={
                "finding_id": input_model.finding_id,
                "category": input_model.vulnerability_category.value,
                "evidence_count": len(input_model.security_evidence),
            },
        )

        # STEP 1: Inspect evidence
        inspection = self.inspect_evidence(input_model.security_evidence)

        # STEP 2: Determine vulnerability context
        vuln_context = self.determine_vulnerability_context(input_model, inspection)

        # STEP 3: Determine confirmation status (using trusted metadata)
        confirmation_status = self.determine_confirmation_status(input_model, inspection)

        # STEP 4: Estimate confidence
        confidence_level = self.estimate_confidence(confirmation_status, inspection)

        # STEP 5: Explain impact
        potential_impact = self.analyze_impact(input_model, inspection, vuln_context)

        # If an AI client is injected, allow AI synthesis but strictly enforce confirmation rules
        if self.ai_client is not None:
            return self._analyze_with_ai(
                input_model,
                inspection,
                vuln_context,
                confirmation_status,
                confidence_level,
                potential_impact,
            )

        # Otherwise, synthesize deterministic, evidence-grounded analysis
        return self._synthesize_structured_analysis(
            input_data=input_model,
            inspection=inspection,
            vuln_context=vuln_context,
            confirmation_status=confirmation_status,
            confidence_level=confidence_level,
            potential_impact=potential_impact,
        )

    # --------------------------------------------------------------------------
    # Step 1: Evidence Inspection
    # --------------------------------------------------------------------------

    def inspect_evidence(self, evidence_list: List[SecurityEvidence]) -> EvidenceInspectionResult:
        """Inspects all supplied evidence, checks for discrepancies, contradictions, and gaps."""
        evidence_types = {e.evidence_type for e in evidence_list}
        affected_endpoints = {e.affected_endpoint for e in evidence_list}
        observed_behaviors = [e.observed_behavior for e in evidence_list]
        expected_behaviors = [e.expected_behavior for e in evidence_list]

        is_differential = EvidenceType.DIFFERENTIAL_RESPONSE in evidence_types
        has_contradictions = False
        contradiction_details: List[str] = []
        missing_evidence: List[str] = []

        all_validated = all(e.validation_status == ValidationStatus.VALIDATED for e in evidence_list)
        any_inconclusive = any(
            e.validation_status in (ValidationStatus.INCONCLUSIVE, ValidationStatus.REFUTED)
            for e in evidence_list
        )

        # Contradiction Detection: Check if observed behavior indicates both allowed and denied access
        has_denied = any(
            re.search(r"\b(401|403|denied|forbidden|unauthorized|blocked)\b", obs, re.IGNORECASE)
            for obs in observed_behaviors
        )
        has_allowed = any(
            re.search(r"\b(200|201|204|success|returned|accessible)\b", obs, re.IGNORECASE)
            for obs in observed_behaviors
        )

        if has_denied and has_allowed and not is_differential:
            has_contradictions = True
            contradiction_details.append(
                "Contradictory behavior observed: Evidence indicates both blocked and permitted access "
                "without distinct role differential context."
            )

        # Gap Detection: Check for missing baseline in differential tests
        if not is_differential and len(evidence_list) == 1:
            missing_evidence.append(
                "Absence of comparative role baseline: Test was conducted under a single identity "
                "without comparing owner baseline vs peer attacker response."
            )

        # Check for missing cryptographic evidence references
        for e in evidence_list:
            if not e.supporting_evidence_refs:
                missing_evidence.append(f"Evidence {e.evidence_id} lacks cryptographic checksum or wire log references.")

        return EvidenceInspectionResult(
            evidence_types=evidence_types,
            affected_endpoints=affected_endpoints,
            is_differential=is_differential,
            has_contradictory_evidence=has_contradictions,
            contradiction_details=contradiction_details,
            missing_evidence_items=missing_evidence,
            all_validated=all_validated,
            any_inconclusive=any_inconclusive,
            observed_behaviors=observed_behaviors,
            expected_behaviors=expected_behaviors,
        )

    # --------------------------------------------------------------------------
    # Step 2: Vulnerability Context Determination
    # --------------------------------------------------------------------------

    def determine_vulnerability_context(
        self,
        input_data: FindingAnalysisInput,
        inspection: EvidenceInspectionResult,
    ) -> VulnerabilityContext:
        """Determines the failed security control and technical root cause from evidence."""
        category = input_data.vulnerability_category
        resource = input_data.affected_resource
        endpoint = resource.endpoint

        if category == VulnerabilityCategory.BOLA_IDOR:
            title = f"Broken Object Level Authorization (IDOR) on {endpoint}"
            failed_control = "Object-level authorization check verifying resource ownership."
            root_cause = (
                f"The endpoint {endpoint} retrieves or modifies target entity '{resource.resource_id}' "
                f"using untrusted client input without validating that the authenticated session identity "
                f"({input_data.user_role_context or 'active user'}) matches the resource owner "
                f"({resource.owner_identity or 'authorized user'})."
            )
        elif category == VulnerabilityCategory.BFLA:
            title = f"Broken Function Level Authorization (BFLA) on {endpoint}"
            failed_control = "Role-based access control (RBAC) middleware verifying administrative privilege."
            root_cause = (
                f"The restricted route {endpoint} executes privileged business logic without asserting "
                f"that the calling identity possesses required administrative role claims."
            )
        elif category == VulnerabilityCategory.MISSING_AUTH:
            title = f"Missing Authentication Control on Sensitive Route {endpoint}"
            failed_control = "Authentication middleware establishing and verifying identity."
            root_cause = (
                f"The private endpoint {endpoint} exposes sensitive resource state without requiring "
                f"or validating HTTP session tokens or Authorization headers."
            )
        elif category == VulnerabilityCategory.PRIVILEGE_ESCALATION:
            title = f"Privilege Escalation Flaw on {endpoint}"
            failed_control = "Role boundary enforcement and privilege assignment filter."
            root_cause = (
                f"User identity in role '{input_data.user_role_context or 'standard'}' was permitted to "
                f"assume elevated capabilities or access restricted functionality on {endpoint}."
            )
        else:
            title = f"Authorization Discrepancy on {endpoint} ({category.value})"
            failed_control = "Authorization logic and access control enforcement filter."
            root_cause = (
                f"Discrepancy detected between observed and expected access permissions on {endpoint}."
            )

        return VulnerabilityContext(
            likely_category=category,
            failed_security_control=failed_control,
            technical_root_cause=root_cause,
            summary_title=title,
        )

    # --------------------------------------------------------------------------
    # Step 3: Confirmation Status Determination (Trusted Metadata Gate)
    # --------------------------------------------------------------------------

    def determine_confirmation_status(
        self,
        input_data: FindingAnalysisInput,
        inspection: EvidenceInspectionResult,
    ) -> ConfirmationStatus:
        """Determines confirmation status using trusted validation metadata.

        RULE: Only independently validated evidence satisfying project criteria
        can support a CONFIRMED status. AI models cannot upgrade this status.
        """
        # Contradictory or explicitly inconclusive evidence is immediately INCONCLUSIVE
        if inspection.has_contradictory_evidence or inspection.any_inconclusive:
            return ConfirmationStatus.INCONCLUSIVE

        # Check independent validation metadata
        val_meta = input_data.evidence_validation
        if val_meta is not None:
            if val_meta.validation_status == ValidationStatus.INCONCLUSIVE:
                return ConfirmationStatus.INCONCLUSIVE
            if val_meta.validation_status == ValidationStatus.REFUTED:
                return ConfirmationStatus.FALSE_POSITIVE

            # To confirm: validation metadata must be validated AND all evidence must be validated
            if (
                val_meta.is_validated
                and val_meta.validation_status == ValidationStatus.VALIDATED
                and inspection.all_validated
            ):
                return ConfirmationStatus.CONFIRMED

        # Check evidence-level validation if no validation metadata block exists
        if inspection.all_validated and not inspection.missing_evidence_items:
            # If all individual evidence items are validated by trusted tools
            return ConfirmationStatus.CONFIRMED

        # Default to SUSPECTED for preliminary, unvalidated evidence
        return ConfirmationStatus.SUSPECTED

    # --------------------------------------------------------------------------
    # Step 4: Confidence Estimation
    # --------------------------------------------------------------------------

    def estimate_confidence(
        self,
        confirmation_status: ConfirmationStatus,
        inspection: EvidenceInspectionResult,
    ) -> ConfidenceLevel:
        """Estimates analytical confidence based on confirmation status and evidence quality."""
        if confirmation_status == ConfirmationStatus.CONFIRMED:
            return ConfidenceLevel.CONFIRMED

        if confirmation_status == ConfirmationStatus.INCONCLUSIVE or inspection.has_contradictory_evidence:
            return ConfidenceLevel.LOW

        if inspection.is_differential and len(inspection.missing_evidence_items) == 0:
            return ConfidenceLevel.HIGH

        if inspection.is_differential:
            return ConfidenceLevel.MEDIUM

        return ConfidenceLevel.LOW

    # --------------------------------------------------------------------------
    # Step 5: Impact Analysis
    # --------------------------------------------------------------------------

    def analyze_impact(
        self,
        input_data: FindingAnalysisInput,
        inspection: EvidenceInspectionResult,
        vuln_context: VulnerabilityContext,
    ) -> str:
        """Synthesizes supported impact based on empirical evidence and resource sensitivity."""
        resource = input_data.affected_resource
        category = input_data.vulnerability_category
        role = input_data.user_role_context or "unauthorized identity"

        impacts: List[str] = []

        if category == VulnerabilityCategory.BOLA_IDOR:
            impacts.append(
                f"Unauthorized data access: The caller ({role}) can view or manipulate data records "
                f"({resource.resource_id}) belonging to {resource.owner_identity or 'another user'}."
            )
            impacts.append(
                "Horizontal privilege escalation: Breach of multi-tenant data isolation enabling "
                "cross-user confidentiality compromise."
            )
        elif category == VulnerabilityCategory.BFLA:
            impacts.append(
                f"Vertical privilege escalation: Unprivileged role ({role}) can trigger administrative "
                f"functions and privileged state changes on {resource.endpoint}."
            )
            impacts.append("Security management compromise: Bypass of privileged operation restrictions.")
        elif category == VulnerabilityCategory.MISSING_AUTH:
            impacts.append(
                f"Information disclosure: Unauthenticated anonymous callers can extract private entity "
                f"data from {resource.endpoint}."
            )
        elif category == VulnerabilityCategory.PRIVILEGE_ESCALATION:
            impacts.append(
                f"Privilege escalation: Standard user context escalated to elevated access levels on {resource.endpoint}."
            )
        else:
            impacts.append(
                f"Security boundary breach: Potential unauthorized state change or information leak on {resource.endpoint}."
            )

        # Distinguish observed consequences from theoretical extensions
        impact_statement = " ".join(impacts)
        if inspection.missing_evidence_items:
            impact_statement += " Note: Full business impact severity is contingent upon resolving identified evidence gaps."

        return impact_statement

    # --------------------------------------------------------------------------
    # Step 6: Synthesis & AI Fallback
    # --------------------------------------------------------------------------

    def _synthesize_structured_analysis(
        self,
        input_data: FindingAnalysisInput,
        inspection: EvidenceInspectionResult,
        vuln_context: VulnerabilityContext,
        confirmation_status: ConfirmationStatus,
        confidence_level: ConfidenceLevel,
        potential_impact: str,
    ) -> FindingAnalysis:
        """Constructs a validated FindingAnalysis model deterministically."""
        # Build technical explanation
        observed_str = "; ".join(inspection.observed_behaviors)
        expected_str = "; ".join(inspection.expected_behaviors)
        explanation = (
            f"Vulnerability Analysis for {input_data.vulnerability_category.value}: "
            f"During testing, the following behavior was observed: '{observed_str}'. "
            f"In contrast, the secure expected behavior is: '{expected_str}'. "
            f"Failed security control: {vuln_context.failed_security_control}."
        )

        limitations = list(inspection.missing_evidence_items)
        if inspection.contradiction_details:
            limitations.extend(inspection.contradiction_details)

        # Anti-hallucination check: ensure unvalidated evidence cannot be marked CONFIRMED
        if confirmation_status == ConfirmationStatus.CONFIRMED and not inspection.all_validated:
            confirmation_status = ConfirmationStatus.SUSPECTED
            confidence_level = ConfidenceLevel.HIGH

        return FindingAnalysis(
            title=vuln_context.summary_title,
            vulnerability_explanation=explanation,
            technical_root_cause=vuln_context.technical_root_cause,
            affected_resources=[input_data.affected_resource],
            potential_impact=potential_impact,
            supporting_evidence=input_data.security_evidence,
            confidence_level=confidence_level,
            confirmation_status=confirmation_status,
            limitations_and_missing_info=limitations,
        )

    def _analyze_with_ai(
        self,
        input_data: FindingAnalysisInput,
        inspection: EvidenceInspectionResult,
        vuln_context: VulnerabilityContext,
        trusted_confirmation_status: ConfirmationStatus,
        trusted_confidence_level: ConfidenceLevel,
        potential_impact: str,
    ) -> FindingAnalysis:
        """Synthesizes analysis using injected AI client, enforcing strict confirmation gates."""
        prompt = build_finding_analysis_prompt(input_data)
        try:
            raw_response = self.ai_client.complete(
                system_prompt=SYSTEM_ANALYSIS_PROMPT,
                user_prompt=prompt,
            )
            # Clean possible markdown wrapping if returned
            clean_json = raw_response.strip()
            if clean_json.startswith("```"):
                clean_json = re.sub(r"^```(?:json)?\s*", "", clean_json)
                clean_json = re.sub(r"\s*```$", "", clean_json)

            data = json.loads(clean_json)

            # CRITICAL SECURITY RULE: Claude MUST NOT independently upgrade confirmation status!
            # If trusted status is not CONFIRMED, enforce trusted status regardless of AI output.
            if trusted_confirmation_status != ConfirmationStatus.CONFIRMED:
                data["confirmation_status"] = trusted_confirmation_status.value
                data["confidence_level"] = trusted_confidence_level.value

            # Ensure supporting evidence from input is retained
            data["supporting_evidence"] = [e.model_dump() for e in input_data.security_evidence]
            data["affected_resources"] = [input_data.affected_resource.model_dump()]

            return FindingAnalysis.model_validate(data)
        except Exception as exc:
            logger.warning(
                "AI synthesis failed or returned invalid schema; falling back to deterministic synthesis",
                extra={"error": str(exc)},
            )
            return self._synthesize_structured_analysis(
                input_data=input_data,
                inspection=inspection,
                vuln_context=vuln_context,
                confirmation_status=trusted_confirmation_status,
                confidence_level=trusted_confidence_level,
                potential_impact=potential_impact,
            )

    # --------------------------------------------------------------------------
    # Backward Compatibility Helper
    # --------------------------------------------------------------------------

    def _convert_legacy_evidence(self, raw_evidence: Dict[str, Any]) -> FindingAnalysisInput:
        """Converts legacy dictionary evidence into a valid FindingAnalysisInput model."""
        endpoint = raw_evidence.get("endpoint", raw_evidence.get("url", "/unknown"))
        method = raw_evidence.get("method", "GET")

        evidence = SecurityEvidence(
            evidence_id=f"evi_legacy_{abs(hash(endpoint)) % 100000:05d}",
            evidence_type=EvidenceType.DIFFERENTIAL_RESPONSE,
            description=raw_evidence.get("description", "Discovered access discrepancy"),
            source_component="LegacyAdapter",
            affected_endpoint=endpoint,
            http_method=method,
            observed_behavior=raw_evidence.get("observed", "Unauthorized access succeeded"),
            expected_behavior=raw_evidence.get("expected", "Access should be restricted with 403 Forbidden"),
            validation_status=ValidationStatus.UNVALIDATED,
        )

        resource = AffectedResource(
            resource_id=raw_evidence.get("resource_id", "res_default"),
            resource_type="API_ENDPOINT",
            endpoint=endpoint,
            application_name="OWASP Juice Shop",
        )

        return FindingAnalysisInput(
            finding_id=f"fnd_legacy_{abs(hash(endpoint)) % 100000:05d}",
            vulnerability_category=VulnerabilityCategory.BOLA_IDOR,
            security_evidence=[evidence],
            affected_resource=resource,
        )
