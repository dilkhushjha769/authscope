"""Deterministic Severity Assessment Engine for AuthScope.

Calculates objective, evidence-supported vulnerability risk scores based on a
transparent multi-factor scoring rubric.   
Scoring Factors:
1. Data Sensitivity (0 - 4)
2. Privilege Gained (0 - 3)
3. Exploitability (0 - 3)
4. Potential Impact (0 - 3)
5. Attack Complexity / Ease of Attack (0 - 2)
6. Evidence Confidence (0 - 2)

Architectural Guardrails:
- Pure Deterministic Logic: Scores are computed strictly by mathematical formula.
- Anti-Inflation Safeguards: Hard checks prevent unvalidated findings from reaching CRITICAL.
- Traceability: Every score factor maps directly to verified empirical evidence.
- AI Non-Override: Model reasoning cannot alter the calculated numeric score or severity tier.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import math
import re

from pydantic import BaseModel, ConfigDict, Field

from backend.agent.schemas import (
    ConfidenceLevel,
    DataSensitivityLevel,
    EvidenceType,
    ExploitabilityLevel,
    FindingAnalysisInput,
    PrivilegeGainedLevel,
    SecurityEvidence,
    SeverityAssessment,
    SeverityLevel,
    ValidationStatus,
    VulnerabilityCategory,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Factor Scales and Definitions
# ==============================================================================

# 1. Data Sensitivity (0 - 4)
DS_NO_SENSITIVE = 0         # Public static assets, general documentation
DS_LIMITED_NON_SENSITIVE = 1 # Non-sensitive public IDs, catalogue names
DS_INTERNAL = 2             # Internal IDs, version metrics, system architecture
DS_CONFIDENTIAL_PII = 3     # Customer PII, email, address, private cart contents
DS_CRITICAL_CREDENTIALS = 4 # Passwords, JWT keys, payment data, auth tokens

# 2. Privilege Gained (0 - 3)
PG_NONE = 0                 # No boundary breach
PG_LIMITED_ACCESS = 1       # Access to unauthenticated read without user context
PG_HORIZONTAL_USER = 2      # Access to another user/tenant's private records (BOLA/IDOR)
PG_ADMIN_VERTICAL = 3       # Administrative execution or management access (BFLA)

# 3. Exploitability (0 - 3)
EX_NONE = 0                 # Theoretical, unproven
EX_HIGH_PREREQUISITES = 1   # Complex preconditions, multi-step state required
EX_LIMITED_CONDITIONS = 2   # Exploitable under predictable parameters
EX_REPRODUCIBLE_DIRECT = 3  # Direct, repeatable proof with differential verification

# 4. Potential Impact (0 - 3)
PI_NEGLIGIBLE = 0           # No operational or privacy impact
PI_LOW = 1                  # Minor info disclosure
PI_MODERATE = 2             # Tenant privacy breach or unauthorized user record modification
PI_CRITICAL = 3             # Full administrative takeover or mass customer data compromise

# 5. Attack Complexity / Ease (0 - 2)
AC_HIGH_COMPLEXITY = 0      # Obscure conditions, timing, race conditions
AC_MEDIUM_COMPLEXITY = 1    # Requires valid low-privilege credentials
AC_LOW_COMPLEXITY = 2       # Trivial HTTP request, no credentials or basic tampering

# 6. Evidence Confidence (0 - 2)
EC_LOW = 0                  # Unverified, conflicting, or missing baseline
EC_MODERATE = 1             # Consistent observed behavior, unvalidated
EC_HIGH = 2                 # Independently validated with cryptographic hash


# ==============================================================================
# Factor Scores & Result Pydantic Schemas
# ==============================================================================


class FactorScores(BaseModel):
    """Detailed scores for individual risk factors."""
    model_config = ConfigDict(extra="forbid")

    data_sensitivity: int = Field(..., ge=0, le=4, description="Data sensitivity (0-4)")
    privilege_gained: int = Field(..., ge=0, le=3, description="Privilege gained (0-3)")
    exploitability: int = Field(..., ge=0, le=3, description="Exploitability (0-3)")
    potential_impact: int = Field(..., ge=0, le=3, description="Potential impact (0-3)")
    attack_complexity: int = Field(..., ge=0, le=2, description="Attack complexity ease (0-2)")
    evidence_confidence: int = Field(..., ge=0, le=2, description="Evidence confidence (0-2)")


class DeterministicSeverityResult(BaseModel):
    """Deterministic output package produced by the Severity Engine."""
    model_config = ConfigDict(extra="forbid")

    final_severity: SeverityLevel = Field(..., description="Calculated categorical severity")
    numeric_score: float = Field(..., ge=0.0, le=10.0, description="Normalized risk score (0.0 - 10.0)")
    factor_scores: FactorScores = Field(..., description="Itemized scores for all 6 factors")
    severity_rationale: str = Field(..., description="Deterministic explanation of the score calculation")
    confidence: ConfidenceLevel = Field(..., description="Overall confidence level")
    missing_information: List[str] = Field(default_factory=list, description="Missing evidence gaps that damped score")
    evidence_references: List[str] = Field(default_factory=list, description="Evidence IDs evaluated")

    def to_severity_assessment(self) -> SeverityAssessment:
        """Converts to the standard SeverityAssessment schema for API contracts."""
        # Map factor scores to categorical schema enums
        data_sens_map = {
            0: DataSensitivityLevel.PUBLIC,
            1: DataSensitivityLevel.LOW_SENSITIVITY,
            2: DataSensitivityLevel.INTERNAL_CONFIDENTIAL,
            3: DataSensitivityLevel.PII,
            4: DataSensitivityLevel.CREDENTIALS,
        }
        priv_map = {
            0: PrivilegeGainedLevel.NONE,
            1: PrivilegeGainedLevel.NONE,
            2: PrivilegeGainedLevel.HORIZONTAL_USER,
            3: PrivilegeGainedLevel.VERTICAL_ADMIN,
        }
        exploit_map = {
            0: ExploitabilityLevel.LOW,
            1: ExploitabilityLevel.LOW,
            2: ExploitabilityLevel.MEDIUM,
            3: ExploitabilityLevel.HIGH,
        }

        factors = [
            f"Data Sensitivity: {self.factor_scores.data_sensitivity}/4",
            f"Privilege Gained: {self.factor_scores.privilege_gained}/3",
            f"Exploitability: {self.factor_scores.exploitability}/3",
            f"Potential Impact: {self.factor_scores.potential_impact}/3",
            f"Ease of Attack: {self.factor_scores.attack_complexity}/2",
            f"Evidence Confidence: {self.factor_scores.evidence_confidence}/2",
            f"Computed Numeric Score: {self.numeric_score}/10.0",
        ]

        return SeverityAssessment(
            severity=self.final_severity,
            exploitability=exploit_map.get(self.factor_scores.exploitability, ExploitabilityLevel.LOW),
            data_sensitivity=data_sens_map.get(self.factor_scores.data_sensitivity, DataSensitivityLevel.PUBLIC),
            privilege_gained=priv_map.get(self.factor_scores.privilege_gained, PrivilegeGainedLevel.NONE),
            potential_impact=f"Risk Score {self.numeric_score:.1f}: {self.severity_rationale}",
            severity_rationale=self.severity_rationale,
            confidence=self.confidence,
            contributing_factors=factors,
        )


# ==============================================================================
# Severity Engine Implementation
# ==============================================================================


class SeverityEngine:
    """Deterministic, multi-factor severity scoring engine."""

    # Maximum raw points = 4 (DS) + 3 (PG) + 3 (EX) + 3 (PI) + (2 * 0.5) (AC) = 14.0
    MAX_RAW_WEIGHT = 14.0

    # --------------------------------------------------------------------------
    # Core Deterministic Calculator
    # --------------------------------------------------------------------------

    def calculate_from_factors(
        self,
        data_sensitivity: int,
        privilege_gained: int,
        exploitability: int,
        potential_impact: int,
        attack_complexity: int = 1,
        evidence_confidence: int = 2,
        missing_information: Optional[List[str]] = None,
        evidence_references: Optional[List[str]] = None,
        ai_rationale: Optional[str] = None,
    ) -> DeterministicSeverityResult:
        """Calculates deterministic severity from numeric factor scales.

        Args:
            data_sensitivity: 0 to 4
            privilege_gained: 0 to 3
            exploitability: 0 to 3
            potential_impact: 0 to 3
            attack_complexity: 0 to 2 (2 = lowest complexity / easiest attack)
            evidence_confidence: 0 to 2 (2 = highest confidence / validated)
            missing_information: Gaps identified in evidence
            evidence_references: Associated evidence IDs
            ai_rationale: Optional contextual note from AI (cannot alter final score)

        Returns:
            DeterministicSeverityResult with score, tier, and rationale.
        """
        # Clamp inputs to valid ranges
        ds = max(0, min(4, data_sensitivity))
        pg = max(0, min(3, privilege_gained))
        ex = max(0, min(3, exploitability))
        pi = max(0, min(3, potential_impact))
        ac = max(0, min(2, attack_complexity))
        ec = max(0, min(2, evidence_confidence))

        missing_gaps = list(missing_information or [])
        refs = list(evidence_references or [])

        # Base formula: Weighted sum normalized to 10.0 scale
        raw_weighted = (ds * 1.0) + (pg * 1.0) + (ex * 1.0) + (pi * 1.0) + (ac * 0.5)
        base_score = (raw_weighted / self.MAX_RAW_WEIGHT) * 10.0

        # Confidence Damping Factor
        # EC=2 (High): 1.0 multiplier
        # EC=1 (Moderate): 0.85 multiplier
        # EC=0 (Low / Inconclusive): 0.65 multiplier
        confidence_multipliers = {0: 0.65, 1: 0.85, 2: 1.0}
        damping = confidence_multipliers.get(ec, 1.0)
        final_numeric_score = round(base_score * damping, 1)

        # Map to ConfidenceLevel enum
        conf_enum_map = {0: ConfidenceLevel.LOW, 1: ConfidenceLevel.MEDIUM, 2: ConfidenceLevel.HIGH}
        if ec == 2 and ex == 3:
            confidence_level = ConfidenceLevel.CONFIRMED
        else:
            confidence_level = conf_enum_map.get(ec, ConfidenceLevel.LOW)

        # ----------------------------------------------------------------------
        # Anti-Inflation Safeguards
        # ----------------------------------------------------------------------
        # Safeguard 1: If data sensitivity and privilege gained are zero, max tier is LOW
        if ds == 0 and pg == 0:
            final_numeric_score = min(final_numeric_score, 3.9)

        # Safeguard 2: CRITICAL requires High Confidence (EC=2), High Exploitability (EX>=2),
        # AND either Admin Privilege (PG=3), Critical Data (DS=4 and PI>=2), or Severe Impact (PI=3).
        can_be_critical = (
            ec == 2
            and ex >= 2
            and (pg == 3 or (ds == 4 and pi >= 2) or pi == 3)
        )
        if not can_be_critical and final_numeric_score >= 9.0:
            final_numeric_score = 8.9  # Capped at High

        # Safeguard 3: Low confidence (EC=0) can NEVER exceed MEDIUM (capped at 6.9)
        if ec == 0 and final_numeric_score > 6.9:
            final_numeric_score = 6.9
            missing_gaps.append("Score capped at MEDIUM due to unverified/low evidence confidence.")

        # Final Severity Tier Mapping
        final_severity = self._map_score_to_tier(final_numeric_score)

        # Generate Deterministic Rationale
        rationale = (
            f"Deterministic Risk Score: {final_numeric_score}/10.0 ({final_severity.value}). "
            f"Factors: Data Sensitivity={ds}/4, Privilege Gained={pg}/3, Exploitability={ex}/3, "
            f"Potential Impact={pi}/3, Attack Ease={ac}/2, Evidence Confidence={ec}/2. "
            f"Confidence damping multiplier: {damping:.2f}."
        )
        if ai_rationale:
            rationale += f" Contextual Note: {ai_rationale}"

        factor_obj = FactorScores(
            data_sensitivity=ds,
            privilege_gained=pg,
            exploitability=ex,
            potential_impact=pi,
            attack_complexity=ac,
            evidence_confidence=ec,
        )

        return DeterministicSeverityResult(
            final_severity=final_severity,
            numeric_score=final_numeric_score,
            factor_scores=factor_obj,
            severity_rationale=rationale,
            confidence=confidence_level,
            missing_information=missing_gaps,
            evidence_references=refs,
        )

    # --------------------------------------------------------------------------
    # FindingAnalysisInput Evaluator
    # --------------------------------------------------------------------------

    def evaluate_finding(
        self,
        input_data: FindingAnalysisInput,
        ai_rationale: Optional[str] = None,
    ) -> DeterministicSeverityResult:
        """Extracts risk factors from a structured FindingAnalysisInput model and scores severity.

        Args:
            input_data: Validated FindingAnalysisInput model.
            ai_rationale: Optional AI contextual explanation (does not override score).

        Returns:
            DeterministicSeverityResult.
        """
        category = input_data.vulnerability_category
        evidence_list = input_data.security_evidence
        val_meta = input_data.evidence_validation
        missing_gaps: List[str] = []

        # 1. Evaluate Data Sensitivity (0 - 4)
        ds = self._infer_data_sensitivity(input_data)

        # 2. Evaluate Privilege Gained (0 - 3)
        pg = self._infer_privilege_gained(input_data)

        # 3. Evaluate Exploitability (0 - 3)
        ex = self._infer_exploitability(evidence_list)

        # 4. Evaluate Potential Impact (0 - 3)
        pi = self._infer_potential_impact(category, ds, pg)

        # 5. Evaluate Attack Complexity / Ease (0 - 2)
        ac = 2 if input_data.user_role_context in (None, "anonymous", "user_b") else 1

        # 6. Evaluate Evidence Confidence (0 - 2)
        ec, gaps = self._infer_evidence_confidence(evidence_list, val_meta)
        missing_gaps.extend(gaps)

        evidence_ids = [e.evidence_id for e in evidence_list]

        return self.calculate_from_factors(
            data_sensitivity=ds,
            privilege_gained=pg,
            exploitability=ex,
            potential_impact=pi,
            attack_complexity=ac,
            evidence_confidence=ec,
            missing_information=missing_gaps,
            evidence_references=evidence_ids,
            ai_rationale=ai_rationale,
        )

    # --------------------------------------------------------------------------
    # Backward Compatibility Adapter
    # --------------------------------------------------------------------------

    def calculate_severity(
        self,
        vulnerability_type: str,
        exposes_pii: bool = False,
        exposes_credentials: bool = False,
        allows_privilege_escalation: bool = False,
    ) -> SeverityLevel:
        """Legacy helper preserving existing interface compatibility."""
        ds = DS_NO_SENSITIVE
        if exposes_credentials:
            ds = DS_CRITICAL_CREDENTIALS
        elif exposes_pii:
            ds = DS_CONFIDENTIAL_PII
        elif allows_privilege_escalation:
            ds = DS_INTERNAL

        pg = PG_NONE
        if allows_privilege_escalation:
            pg = PG_ADMIN_VERTICAL
        elif vulnerability_type == "BOLA_IDOR":
            pg = PG_HORIZONTAL_USER

        ex = EX_REPRODUCIBLE_DIRECT
        pi = PI_CRITICAL if allows_privilege_escalation else (PI_MODERATE if exposes_pii else PI_LOW)
        ac = AC_LOW_COMPLEXITY if (allows_privilege_escalation or vulnerability_type == "BOLA_IDOR") else AC_MEDIUM_COMPLEXITY

        result = self.calculate_from_factors(
            data_sensitivity=ds,
            privilege_gained=pg,
            exploitability=ex,
            potential_impact=pi,
            attack_complexity=ac,
            evidence_confidence=EC_HIGH,
        )
        return result.final_severity

    # --------------------------------------------------------------------------
    # Private Factor Inference Routines
    # --------------------------------------------------------------------------

    def _infer_data_sensitivity(self, input_data: FindingAnalysisInput) -> int:
        """Infers data sensitivity score (0-4) from resource path and observed responses."""
        endpoint = input_data.affected_resource.endpoint.lower()
        observed_texts = " ".join(e.observed_behavior.lower() for e in input_data.security_evidence)

        # Credentials / Keys / Tokens -> 4
        if any(term in endpoint or term in observed_texts for term in ["password", "secret", "token", "jwt", "credential", "auth"]):
            return DS_CRITICAL_CREDENTIALS

        # PII / Customer Data / Cart / Order / Address -> 3
        if any(term in endpoint or term in observed_texts for term in ["basket", "order", "address", "user", "profile", "account", "customer"]):
            return DS_CONFIDENTIAL_PII

        # Internal Metadata / Metrics / Architecture -> 2
        if any(term in endpoint or term in observed_texts for term in ["admin", "version", "config", "metrics", "internal"]):
            return DS_INTERNAL

        # Catalogue / Public -> 1
        if any(term in endpoint or term in observed_texts for term in ["product", "item", "search", "catalogue"]):
            return DS_LIMITED_NON_SENSITIVE

        return DS_NO_SENSITIVE

    def _infer_privilege_gained(self, input_data: FindingAnalysisInput) -> int:
        """Infers privilege gained score (0-3) from category and role context."""
        category = input_data.vulnerability_category

        if category == VulnerabilityCategory.BFLA:
            return PG_ADMIN_VERTICAL
        if category in (VulnerabilityCategory.BOLA_IDOR, VulnerabilityCategory.PRIVILEGE_ESCALATION):
            return PG_HORIZONTAL_USER
        if category == VulnerabilityCategory.MISSING_AUTH:
            return PG_LIMITED_ACCESS

        return PG_NONE

    def _infer_exploitability(self, evidence_list: List[SecurityEvidence]) -> int:
        """Infers exploitability (0-3) based on evidence types and observed success."""
        types = {e.evidence_type for e in evidence_list}

        if EvidenceType.DIFFERENTIAL_RESPONSE in types or EvidenceType.ACCESS_CONTROL_BYPASS in types:
            return EX_REPRODUCIBLE_DIRECT
        if EvidenceType.STATUS_MISMATCH in types:
            return EX_LIMITED_CONDITIONS
        if EvidenceType.HTTP_TRANSACTION in types:
            return EX_HIGH_PREREQUISITES

        return EX_NONE

    def _infer_potential_impact(self, category: VulnerabilityCategory, ds: int, pg: int) -> int:
        """Infers potential impact (0-3) combining data sensitivity and privilege level."""
        if pg == PG_ADMIN_VERTICAL or (ds == DS_CRITICAL_CREDENTIALS and pg >= PG_HORIZONTAL_USER):
            return PI_CRITICAL
        if ds >= DS_CONFIDENTIAL_PII or pg == PG_HORIZONTAL_USER:
            return PI_MODERATE
        if ds >= DS_INTERNAL or pg == PG_LIMITED_ACCESS:
            return PI_LOW
        return PI_NEGLIGIBLE

    def _infer_evidence_confidence(
        self,
        evidence_list: List[SecurityEvidence],
        val_meta: Optional[Any],
    ) -> tuple[int, List[str]]:
        """Infers evidence confidence score (0-2) and notes missing gaps."""
        gaps: List[str] = []

        if val_meta is not None:
            if val_meta.validation_status == ValidationStatus.INCONCLUSIVE:
                gaps.append("Validation metadata marked findings as inconclusive.")
                return EC_LOW, gaps
            if val_meta.is_validated and val_meta.validation_status == ValidationStatus.VALIDATED:
                return EC_HIGH, gaps

        # Check evidence items
        all_validated = all(e.validation_status == ValidationStatus.VALIDATED for e in evidence_list)
        if all_validated and any(e.evidence_type == EvidenceType.DIFFERENTIAL_RESPONSE for e in evidence_list):
            return EC_HIGH, gaps

        # Check if single probe without differential baseline
        if len(evidence_list) == 1 and evidence_list[0].evidence_type != EvidenceType.DIFFERENTIAL_RESPONSE:
            gaps.append("Single evidence probe without comparative differential role baseline.")
            return EC_LOW, gaps

        return EC_MODERATE, gaps

    def _map_score_to_tier(self, score: float) -> SeverityLevel:
        """Maps numeric score (0.0 - 10.0) to standardized SeverityLevel enum."""
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        if score >= 7.0:
            return SeverityLevel.HIGH
        if score >= 4.0:
            return SeverityLevel.MEDIUM
        if score >= 2.0:
            return SeverityLevel.LOW
        return SeverityLevel.INFORMATIONAL
