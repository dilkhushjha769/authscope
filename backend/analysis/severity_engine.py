"""Severity Engine: Sensitivity-aware risk scoring based on CVSS 3.1 criteria."""

from enum import Enum
from typing import Dict, Any
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SeverityEngine:
    """Calculates objective risk scores combining vulnerability type and data sensitivity."""

    def calculate_severity(
        self,
        vulnerability_type: str,
        exposes_pii: bool = False,
        exposes_credentials: bool = False,
        allows_privilege_escalation: bool = False
    ) -> SeverityLevel:
        """Computes standardized severity.

        TODO (Phase 7): Implement full CVSS 3.1 scoring matrix calculator.
        """
        if exposes_credentials or (vulnerability_type == "BOLA_IDOR" and exposes_pii):
            return SeverityLevel.HIGH
        elif allows_privilege_escalation:
            return SeverityLevel.CRITICAL
        elif vulnerability_type == "BOLA_IDOR":
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

