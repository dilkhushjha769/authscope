"""Source code integration interface.

Bridges the existing SourceAnalyzer, CodeMapper, ExplanationEngine, and
RemediationEngine with the new MemoryManager.

Rules:
- NEVER invent source file paths or line numbers.
- NEVER claim a finding is confirmed without validated evidence.
- Clearly distinguish black-box analysis from actual source-code analysis.
- When no source repository is available, source_location MUST be None.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.storage.models import FindingRecord
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


class SourceAnalysisResult(BaseModel):
    """Structured explanation of a finding with optional source code mapping."""

    finding_id: str = Field(description="ID of the finding being explained")
    what_happened: str = Field(description="Plain-English description of the observed behaviour")
    why_security_problem: str = Field(description="Why this is a security vulnerability")
    evidence_summary: str = Field(description="Sanitized evidence excerpt (no credentials)")
    potential_impact: str = Field(description="Attacker-perspective impact")
    likely_root_cause: str = Field(description="Likely technical root cause")
    # Source code fields — None when no source repo was supplied
    source_location: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Actual source file path and line range, or None if source unavailable",
    )
    suggested_fix: Optional[str] = Field(
        default=None,
        description="Suggested corrected code, or None if source unavailable",
    )
    how_to_retest: str = Field(description="Step-by-step retesting procedure")
    analysis_type: str = Field(
        default="black_box",
        description="'source_code' when repo provided, 'black_box' otherwise",
    )
    disclaimer: str = Field(
        default=(
            "This analysis is based on observed HTTP behaviour only. "
            "No source code was inspected."
        ),
        description="Honest statement of analysis limitations",
    )


# ---------------------------------------------------------------------------
# Integration class
# ---------------------------------------------------------------------------


class SourceCodeIntegration:
    """Integrates ExplanationEngine, CodeMapper, and RemediationEngine.

    Accepts an optional *repo_root* path.  When *repo_root* is provided and
    resolves to a real directory, SourceAnalyzer is invoked to attempt actual
    source-code mapping.  Without it only black-box HTTP evidence is used.
    """

    def __init__(
        self,
        repo_root: Optional[str] = None,
        code_mapper: Optional[Any] = None,
        explanation_engine: Optional[Any] = None,
    ) -> None:
        self._repo_root: Optional[Path] = None
        if repo_root:
            candidate = Path(repo_root)
            if candidate.exists() and candidate.is_dir():
                self._repo_root = candidate
            else:
                logger.warning(
                    "SourceCodeIntegration: repo_root does not exist — black-box only",
                    extra={"repo_root": repo_root},
                )

        self._code_mapper = code_mapper
        self._explanation_engine = explanation_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_finding(
        self,
        finding: FindingRecord,
        repo_root: Optional[str] = None,
    ) -> SourceAnalysisResult:
        """Produce a structured explanation of *finding*.

        Args:
            finding:   The validated FindingRecord to explain.
            repo_root: Optional path to the target application source tree.
                       When ``None`` the existing ``self._repo_root`` is used.
                       When neither is available, source-code mapping is skipped.

        Returns:
            SourceAnalysisResult with honest labels for analysis_type.
        """
        # Resolve repo_root for this call
        effective_repo: Optional[Path] = self._repo_root
        if repo_root:
            candidate = Path(repo_root)
            if candidate.exists() and candidate.is_dir():
                effective_repo = candidate

        # Build base result from evidence and knowledge
        result = self._build_base_result(finding)

        # Attempt source-code mapping if repo is available
        if effective_repo is not None:
            result = self._enrich_with_source(result, finding, effective_repo)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_base_result(self, finding: FindingRecord) -> SourceAnalysisResult:
        """Construct a black-box result from the finding's evidence metadata."""
        evidence = finding.evidence
        evidence_summary = ""
        if evidence:
            evidence_summary = (
                f"HTTP {evidence.request_method} {evidence.request_url} → "
                f"HTTP {evidence.response_status}. "
                f"{evidence.sanitized_response_body[:500]}"
            ).strip()
        elif finding.actual_behavior:
            evidence_summary = finding.actual_behavior[:500]

        vuln_type = finding.vulnerability_type or finding.vulnerability_category
        what_happened = (
            f"During authorization testing of '{finding.endpoint}' "
            f"({finding.http_method}), an unauthorized request received an "
            f"unexpected response.  Actual behaviour: {finding.actual_behavior or 'see evidence'}."
        )
        why_problem = _why_problem_for_type(vuln_type)
        impact = _impact_for_type(vuln_type)
        root_cause = _root_cause_for_type(vuln_type)
        retest = (
            f"Authenticate as an unauthorized role and send {finding.http_method} "
            f"to {finding.endpoint}.  Expect HTTP 401 or 403."
        )

        return SourceAnalysisResult(
            finding_id=finding.id,
            what_happened=what_happened,
            why_security_problem=why_problem,
            evidence_summary=evidence_summary,
            potential_impact=impact,
            likely_root_cause=root_cause,
            source_location=None,          # explicitly None — no source
            suggested_fix=None,            # explicitly None — no source
            how_to_retest=retest,
            analysis_type="black_box",
            disclaimer=(
                "This analysis is based on observed HTTP behaviour only. "
                "No source code was inspected. "
                "Provide a source repository for code-level analysis."
            ),
        )

    def _enrich_with_source(
        self,
        base: SourceAnalysisResult,
        finding: FindingRecord,
        repo_root: Path,
    ) -> SourceAnalysisResult:
        """Attempt to locate the handler in *repo_root* and enrich *base*."""
        # Delegate to CodeMapper if available
        if self._code_mapper is not None:
            try:
                mapped = self._code_mapper.map_endpoint(
                    finding.endpoint, finding.http_method
                )
                if mapped:
                    source_location: Dict[str, Any] = {
                        "file": str(mapped.get("file", "")),
                        "line_start": mapped.get("line_start"),
                        "line_end": mapped.get("line_end"),
                        "handler": mapped.get("handler"),
                        "note": "Actual source location from CodeMapper",
                    }
                    suggested_fix = mapped.get("suggested_fix") or None
                    return base.model_copy(
                        update={
                            "source_location": source_location,
                            "suggested_fix": suggested_fix,
                            "analysis_type": "source_code",
                            "disclaimer": (
                                "Source-code analysis performed via CodeMapper. "
                                "File path and line numbers reflect actual repository content."
                            ),
                        }
                    )
            except Exception as exc:
                logger.warning(
                    "SourceCodeIntegration: CodeMapper lookup failed",
                    extra={"error": str(exc), "finding_id": finding.id},
                )

        # If CodeMapper unavailable — attempt a direct file-system search
        # (safe: read-only grep, no invented paths)
        try:
            hit = _grep_endpoint_in_repo(finding.endpoint, repo_root)
            if hit:
                return base.model_copy(
                    update={
                        "source_location": hit,
                        "analysis_type": "source_code",
                        "disclaimer": (
                            "Source-code analysis performed by static text search. "
                            "Verify file path and line numbers before action."
                        ),
                    }
                )
        except Exception as exc:
            logger.warning(
                "SourceCodeIntegration: static grep failed",
                extra={"error": str(exc)},
            )

        # Could not locate source — keep black-box result
        logger.info(
            "SourceCodeIntegration: source mapping unsuccessful — returning black-box result",
            extra={"finding_id": finding.id, "repo": str(repo_root)},
        )
        return base


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _grep_endpoint_in_repo(
    endpoint: str, repo_root: Path
) -> Optional[Dict[str, Any]]:
    """Search *repo_root* source files for *endpoint* string.

    Returns a location dict if found, otherwise None.
    Searches only text files with typical web-framework extensions.
    """
    # Normalize endpoint: remove leading slash and query-string
    target = endpoint.split("?")[0].strip("/")
    if not target:
        return None

    extensions = {".py", ".js", ".ts", ".rb", ".go", ".java", ".php"}
    for src_file in repo_root.rglob("*"):
        if src_file.suffix not in extensions:
            continue
        if any(part.startswith(".") or part in ("node_modules", "__pycache__", ".git")
               for part in src_file.parts):
            continue
        try:
            lines = src_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            for lineno, line in enumerate(lines, start=1):
                if target in line:
                    return {
                        "file": str(src_file.relative_to(repo_root)),
                        "line_start": lineno,
                        "line_end": lineno,
                        "handler": line.strip()[:200],
                        "note": "Located by static text search in repository",
                    }
        except Exception:
            continue
    return None


def _why_problem_for_type(vuln_type: str) -> str:
    mapping = {
        "BOLA_IDOR": (
            "The server did not verify that the requesting user owns the resource. "
            "Any user can access another user's private data by changing an ID in the URL."
        ),
        "BFLA": (
            "An administrative or privileged function is accessible to a lower-privileged role. "
            "The server relies on the UI to hide sensitive endpoints instead of enforcing access at the API level."
        ),
        "MISSING_AUTH": (
            "The endpoint does not require any form of authentication. "
            "Anyone — including unauthenticated internet users — can access it."
        ),
        "PRIVILEGE_ESCALATION": (
            "A low-privileged user can perform actions reserved for administrators or higher-privileged roles."
        ),
        "MASS_ASSIGNMENT": (
            "The server accepts and applies user-supplied fields that should be read-only or restricted, "
            "allowing attackers to modify sensitive properties."
        ),
        "MULTI_STEP_CHAIN": (
            "A sequence of individually-harmless operations combines to bypass authorization controls."
        ),
    }
    return mapping.get(vuln_type.upper(), "An authorization control is not enforced correctly.")


def _impact_for_type(vuln_type: str) -> str:
    mapping = {
        "BOLA_IDOR": "Unauthorized read, modification, or deletion of other users' private data.",
        "BFLA": "Regular users can perform administrative operations such as modifying configuration or deleting accounts.",
        "MISSING_AUTH": "Complete exposure of the endpoint to the public internet.",
        "PRIVILEGE_ESCALATION": "Attackers can escalate to admin privileges and fully compromise the application.",
        "MASS_ASSIGNMENT": "Attackers can elevate roles, set admin flags, or modify pricing/balances.",
        "MULTI_STEP_CHAIN": "Complex attack chains that individually appear benign but cumulatively bypass security.",
    }
    return mapping.get(vuln_type.upper(), "Unauthorized access to protected resources or operations.")


def _root_cause_for_type(vuln_type: str) -> str:
    mapping = {
        "BOLA_IDOR": (
            "Resource lookups use user-supplied IDs directly without validating ownership "
            "(e.g., SELECT * FROM resources WHERE id = ? without AND user_id = ?)."
        ),
        "BFLA": (
            "Role-based access control middleware is missing or bypassed on administrative routes."
        ),
        "MISSING_AUTH": "Authentication middleware is absent from the route definition.",
        "PRIVILEGE_ESCALATION": "Role checks are absent or implemented only on the client side.",
        "MASS_ASSIGNMENT": (
            "Object models accept all incoming fields without an allowlist of writable properties."
        ),
        "MULTI_STEP_CHAIN": (
            "Individual state transitions are authorized but no guard validates the complete workflow sequence."
        ),
    }
    return mapping.get(vuln_type.upper(), "Server-side authorization checks are missing or insufficient.")

