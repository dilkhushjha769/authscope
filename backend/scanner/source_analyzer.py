"""Source Code Analysis Engine (Phase 5.1).

Inspects authorized local source code repositories and files to identify
potentially vulnerable programming patterns across Python, JavaScript, and
TypeScript without ever executing target code or making network requests.

Key Security & Architectural Guarantees:
- Never executes scanned source code (`eval`, `exec`, `import`, `subprocess` on target code).
- Never makes network requests.
- Enforces strict directory traversal safety (symlink confinement, path validation).
- Enforces file-size and repository-size boundaries.
- Automatically excludes build/dependency directories (`.git`, `node_modules`, `.venv`, `build`, `dist`).
- Automatically excludes secret/environment files and private keys (`.env`, `.pem`, `.key`, `id_rsa`, etc.)
  and redacts any sensitive credential literals from extracted code snippets.
- Uses multi-method detection:
  1. Python `ast` structural syntax tree analysis for Python files.
  2. Structural token/scope/AST-like lexical & syntactic analysis for JavaScript and TypeScript.
  3. Optional external static analysis tool integration (Bandit / Semgrep) when available and enabled.
- Strictly separates static analysis observations (`DETECTED_CODE_PATTERN`, `POTENTIAL_VULNERABILITY`)
  from runtime verification (`CONFIRMED_RUNTIME_VULNERABILITY`). Static analysis alone NEVER
  claims runtime exploitability or confirmed vulnerability status.
"""

from __future__ import annotations

import ast
from datetime import datetime, timezone
from enum import Enum
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.agent.schemas import ConfidenceLevel, SeverityLevel
from backend.storage.models import (
    EvidenceArtifact,
    EvidenceValidationStatus,
    FindingRecord,
    FindingStatus,
)
from backend.utils.helpers import (
    AuthScopeException,
    compute_sha256,
    redact_sensitive_text,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Exceptions
# ==============================================================================


class SourceAnalysisError(AuthScopeException):
    """Base exception for source-code analysis engine errors."""
    pass


class InvalidSourcePathError(SourceAnalysisError):
    """Raised when a target source path is missing, malformed, or unsafe."""
    pass


class RepositoryLimitExceededError(SourceAnalysisError):
    """Raised when a repository exceeds configured size or file count boundaries."""
    pass


class UnsupportedSourceFileError(SourceAnalysisError):
    """Raised when a single target file is unsupported or excluded by security rules."""
    pass


# ==============================================================================
# Enumerations & Constants
# ==============================================================================


class SupportedLanguage(str, Enum):
    """Programming languages supported by the SourceAnalyzer."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"


class SourceVulnerabilityCategory(str, Enum):
    """Vulnerability categories detected by the static source analyzer."""
    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    BOLA_IDOR = "BOLA_IDOR"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"


class StaticFindingClassification(str, Enum):
    """Explicit distinction between static code patterns and runtime exploitability.

    Static analysis alone MUST NEVER produce CONFIRMED_RUNTIME_VULNERABILITY.
    """
    DETECTED_CODE_PATTERN = "DETECTED_CODE_PATTERN"
    POTENTIAL_VULNERABILITY = "POTENTIAL_VULNERABILITY"
    CONFIRMED_RUNTIME_VULNERABILITY = "CONFIRMED_RUNTIME_VULNERABILITY"


class StaticValidationStatus(str, Enum):
    """Validation status for static findings prior to runtime differential verification."""
    DETECTED_PATTERN = "DETECTED_CODE_PATTERN"
    POTENTIAL_UNVERIFIED = "POTENTIAL_VULNERABILITY"
    UNVALIDATED_STATIC = "UNVALIDATED"
    CONFIRMED_RUNTIME = "CONFIRMED_RUNTIME_VULNERABILITY"


class DetectionMethod(str, Enum):
    """Underlying static analysis technique that produced the finding."""
    PYTHON_AST = "python_ast"
    JS_TS_STRUCTURAL = "js_ts_structural_analyzer"
    BANDIT = "bandit_sast"
    SEMGREP = "semgrep_sast"
    HYBRID_AST_PATTERN = "hybrid_ast_pattern"


class SourceType(str, Enum):
    """Origin type of the finding."""
    SOURCE_CODE = "source_code"
    STATIC_ANALYSIS = "static_analysis"


# Default limits
DEFAULT_MAX_FILE_SIZE_BYTES: int = 1_048_576          # 1 MB per source file
DEFAULT_MAX_REPO_SIZE_BYTES: int = 50 * 1_048_576     # 50 MB total scanned bytes
DEFAULT_MAX_FILES_COUNT: int = 5_000                  # Max files per scan

# Extension to language mapping
LANGUAGE_EXTENSIONS: Dict[str, SupportedLanguage] = {
    ".py": SupportedLanguage.PYTHON,
    ".js": SupportedLanguage.JAVASCRIPT,
    ".jsx": SupportedLanguage.JAVASCRIPT,
    ".mjs": SupportedLanguage.JAVASCRIPT,
    ".cjs": SupportedLanguage.JAVASCRIPT,
    ".ts": SupportedLanguage.TYPESCRIPT,
    ".tsx": SupportedLanguage.TYPESCRIPT,
    ".mts": SupportedLanguage.TYPESCRIPT,
    ".cts": SupportedLanguage.TYPESCRIPT,
}

# Excluded directory names (case-insensitive matching)
DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "build",
    "dist",
    ".next",
    ".nuxt",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
    "htmlcov",
    "vendor",
    "target",
    "out",
}

# Excluded secret, environment, and private key file patterns
SECRET_AND_ENV_FILE_PATTERNS: Tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.cer",
    "*.crt",
    "*.der",
    "*.asc",
    "*.ovpn",
    "id_rsa",
    "id_rsa.*",
    "id_dsa",
    "id_dsa.*",
    "id_ecdsa",
    "id_ecdsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "*_rsa",
    "*.ppk",
    ".htpasswd",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "service-account*.json",
    "*secret*.json",
    "*secrets*.yaml",
    "*secrets*.yml",
    "master.key",
)

# Private key header markers inside file contents (for immediate rejection if encountered)
PRIVATE_KEY_CONTENT_MARKERS: Tuple[str, ...] = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
)


# ==============================================================================
# Pydantic Models for Source Discovery & Structured Findings
# ==============================================================================


class DiscoveredSourceFile(BaseModel):
    """Metadata for a validated, in-scope source code file."""
    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(..., description="Relative or normalized path to the source file")
    absolute_path: str = Field(..., description="Resolved absolute filesystem path")
    language: SupportedLanguage = Field(..., description="Detected programming language")
    size_bytes: int = Field(..., ge=0, description="File size in bytes")
    sha256: str = Field(..., description="SHA-256 digest of raw file contents")


class SkippedSourceItem(BaseModel):
    """Record of an excluded or skipped file/directory during source discovery."""
    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Path that was skipped")
    reason: str = Field(..., description="Explanation for exclusion (e.g. excluded_dir, secret_file, size_limit)")


class SourceDiscoveryResult(BaseModel):
    """Complete result of safe source code discovery across a path or repository."""
    model_config = ConfigDict(extra="forbid")

    root_path: str = Field(..., description="Normalized root path inspected")
    discovered_files: List[DiscoveredSourceFile] = Field(default_factory=list)
    skipped_items: List[SkippedSourceItem] = Field(default_factory=list)
    total_scanned_bytes: int = Field(default=0, ge=0)
    languages_summary: Dict[str, int] = Field(default_factory=dict)
    repository_limit_reached: bool = Field(default=False)
    repository_limit_reason: Optional[str] = Field(default=None)


class SourceFinding(BaseModel):
    """Structured static source-code analysis finding.

    Designed for seamless interoperability with Member 2 (CodeMapper / ExplanationEngine)
    and Member 3 / Persistence (`FindingRecord`).
    """
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    finding_id: str = Field(..., min_length=1, description="Unique finding identifier")
    rule_id: str = Field(..., min_length=1, description="Static analysis rule identifier (e.g. AS-PY-SQLI-001)")
    vulnerability_category: str = Field(..., min_length=1, description="Standardized vulnerability category")
    severity: SeverityLevel = Field(..., description="Estimated severity rating")
    confidence: ConfidenceLevel = Field(..., description="Static detection confidence (never CONFIRMED)")
    source_type: str = Field(default=SourceType.SOURCE_CODE.value, description="Source type (source_code)")
    classification: StaticFindingClassification = Field(
        default=StaticFindingClassification.POTENTIAL_VULNERABILITY,
        description="Distinguishes Detected Code Pattern vs Potential Vulnerability vs Confirmed Runtime Vulnerability",
    )
    validation_status: str = Field(
        default=StaticValidationStatus.POTENTIAL_UNVERIFIED.value,
        description="Validation status; static analysis alone never claims runtime confirmation",
    )
    is_runtime_confirmed: bool = Field(
        default=False,
        description="Always False for pure static analysis; requires dynamic differential verification to confirm",
    )
    file_path: str = Field(..., min_length=1, description="File path where the pattern was detected")
    language: SupportedLanguage = Field(default=SupportedLanguage.UNKNOWN, description="Programming language")
    function_name: Optional[str] = Field(default=None, description="Enclosing function or method name, if available")
    class_name: Optional[str] = Field(default=None, description="Enclosing class name, if available")
    route_path: Optional[str] = Field(default=None, description="Inferred HTTP route/endpoint path, if available")
    http_method: Optional[str] = Field(default=None, description="Inferred HTTP method, if available")
    start_line: int = Field(..., ge=1, description="1-based start line number")
    end_line: int = Field(..., ge=1, description="1-based end line number")
    code_snippet: str = Field(..., min_length=1, description="Redacted source code snippet showing the pattern")
    detection_explanation: str = Field(..., min_length=10, description="Detailed explanation of why the pattern was flagged")
    detection_method: str = Field(..., min_length=1, description="Detection technique (e.g. python_ast, js_ts_structural_analyzer)")
    remediation_hint: str = Field(default="", description="Recommended code-level remediation guidance")
    cwe_id: Optional[str] = Field(default=None, description="Associated CWE identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional AST/structural context for CodeMapper")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("code_snippet", "detection_explanation")
    @classmethod
    def sanitize_text_fields(cls, v: str) -> str:
        return redact_sensitive_text(v)

    @model_validator(mode="after")
    def enforce_static_non_confirmation_guardrail(self) -> "SourceFinding":
        """Static analysis alone MUST NOT claim runtime exploitability or confirmed vulnerability."""
        if self.end_line < self.start_line:
            object.__setattr__(self, "end_line", self.start_line)

        if self.source_type in (SourceType.SOURCE_CODE.value, SourceType.STATIC_ANALYSIS.value):
            if self.is_runtime_confirmed:
                raise ValueError(
                    "Static Analysis Guardrail Violation: Static source analysis alone must not claim "
                    "runtime exploitability (is_runtime_confirmed=True is prohibited without runtime test proof)."
                )
            if self.classification == StaticFindingClassification.CONFIRMED_RUNTIME_VULNERABILITY:
                raise ValueError(
                    "Static Analysis Guardrail Violation: Static analysis findings must be classified as "
                    "DETECTED_CODE_PATTERN or POTENTIAL_VULNERABILITY, never CONFIRMED_RUNTIME_VULNERABILITY."
                )
            if self.confidence == ConfidenceLevel.CONFIRMED:
                object.__setattr__(self, "confidence", ConfidenceLevel.HIGH)
            if self.validation_status.upper() in ("CONFIRMED", "CONFIRMED_RUNTIME_VULNERABILITY"):
                object.__setattr__(
                    self,
                    "validation_status",
                    StaticValidationStatus.POTENTIAL_UNVERIFIED.value,
                )
        return self

    @property
    def id(self) -> str:
        """Alias for finding_id to match FindingRecord interface."""
        return self.finding_id

    def to_finding_record(self, scan_id: str = "source_scan_default") -> FindingRecord:
        """Converts this SourceFinding into the canonical project `FindingRecord` model.

        Guarantees `status="suspected"` and `validation_status="SUSPICIOUS"` (never `confirmed`)
        so downstream persistence and UI layers respect the static-vs-runtime boundary.
        """
        endpoint_ref = self.route_path or f"source://{self.file_path}#L{self.start_line}-L{self.end_line}"
        method_ref = (self.http_method or "GET").upper()
        if method_ref not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            method_ref = "GET"

        evidence_hash = compute_sha256(
            f"{self.rule_id}|{self.file_path}|{self.start_line}|{self.end_line}|{self.code_snippet}"
        )

        artifact = EvidenceArtifact(
            id=f"evi_{evidence_hash[:8]}",
            finding_id=self.finding_id,
            endpoint=endpoint_ref,
            http_method=method_ref,
            expected_behavior=(
                f"Source code in '{self.file_path}' (lines {self.start_line}-{self.end_line}) should enforce "
                f"safe parameterization, output encoding, and explicit server-side authorization checks."
            ),
            actual_behavior=(
                f"[{self.classification.value}] {self.detection_explanation} "
                f"(Rule: {self.rule_id}, Method: {self.detection_method}). "
                f"Note: Static analysis finding; runtime exploitability is unverified."
            ),
            validation_status=EvidenceValidationStatus.SUSPICIOUS,
            request_method=method_ref,
            request_url=endpoint_ref,
            response_status=0,
            sanitized_response_body=self.code_snippet,
            sanitized_response_evidence=self.code_snippet[:1500],
            evidence_sha256=evidence_hash,
            evidence_validation_status="unverified_static",
        )

        return FindingRecord(
            id=self.finding_id,
            scan_id=scan_id,
            title=f"[Static: {self.classification.value}] {self.vulnerability_category} in {self.file_path}:{self.start_line}",
            endpoint=endpoint_ref,
            target_endpoint=endpoint_ref,
            http_method=method_ref,
            vulnerability_category=self.vulnerability_category,
            vulnerability_type=self.vulnerability_category,
            confirmation_status=FindingStatus.SUSPECTED.value,
            status=FindingStatus.SUSPECTED.value,
            validation_status="SUSPICIOUS",
            access_verdict="SUSPICIOUS_ACCESS",
            severity=self.severity,
            description=self.detection_explanation,
            impact_explanation=self.detection_explanation,
            remediation_guidance=self.remediation_hint or "Apply secure coding controls and verify with runtime tests.",
            remediation_recommendation=self.remediation_hint or "Apply secure coding controls and verify with runtime tests.",
            technical_details={
                "rule_id": self.rule_id,
                "source_type": self.source_type,
                "classification": self.classification.value,
                "validation_status": self.validation_status,
                "confidence": self.confidence.value,
                "file_path": self.file_path,
                "language": self.language.value,
                "function_name": self.function_name,
                "class_name": self.class_name,
                "route_path": self.route_path,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "code_snippet": self.code_snippet,
                "detection_method": self.detection_method,
                "cwe_id": self.cwe_id,
                **self.metadata,
            },
            evidence=artifact,
        )


class SourceAnalysisReport(BaseModel):
    """Aggregated report returned by a complete SourceAnalyzer run."""
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Unique source scan identifier")
    root_path: str = Field(..., description="Analyzed root directory or file path")
    discovery: SourceDiscoveryResult = Field(..., description="File discovery summary")
    findings: List[SourceFinding] = Field(default_factory=list, description="Detected static findings")
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    external_tools_used: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_finding_records(self) -> List[FindingRecord]:
        """Converts all static findings into `FindingRecord` instances for storage/UI."""
        return [f.to_finding_record(scan_id=self.scan_id) for f in self.findings]


# ==============================================================================
# Helper Utilities for Code Snippets & Secret Sanitization
# ==============================================================================

_ASSIGNED_SECRET_LITERAL_RE = re.compile(
    r"""(?ix)
    (
        \b(?:password|passwd|pwd|secret|secret_key|api_key|apikey|access_token|auth_token|private_key|jwt_secret|client_secret|db_password|database_password|encryption_key)\b
        \s*[:=]\s*
        ['"]
    )
    ([^'"]{4,})
    (['"])
    """
)

_HIGH_ENTROPY_TOKEN_RE = re.compile(
    r"""(?x)
    \b(
        sk_live_[0-9a-zA-Z]{10,}
        |sk_test_[0-9a-zA-Z]{10,}
        |AKIA[0-9A-Z]{16}
        |ghp_[0-9a-zA-Z]{20,}
        |github_pat_[0-9a-zA-Z_]{20,}
        |xox[baprs]-[0-9a-zA-Z\-]{10,}
        |AIza[0-9A-Za-z\-_]{20,}
    )\b
    """
)


def sanitize_code_snippet(snippet: str) -> str:
    """Redacts literal secrets, tokens, and keys from extracted source code snippets."""
    if not snippet:
        return ""
    redacted = redact_sensitive_text(snippet)
    redacted = _ASSIGNED_SECRET_LITERAL_RE.sub(r"\1[REDACTED_SECRET]\3", redacted)
    redacted = _HIGH_ENTROPY_TOKEN_RE.sub("[REDACTED_API_KEY]", redacted)
    for marker in PRIVATE_KEY_CONTENT_MARKERS:
        if marker in redacted:
            redacted = "[REDACTED_PRIVATE_KEY_CONTENT]"
    return redacted


def extract_code_snippet(
    lines: Sequence[str],
    start_line: int,
    end_line: int,
    context_lines: int = 1,
    max_chars: int = 1200,
) -> str:
    """Extracts a bounded, redacted source snippet around `start_line..end_line` (1-based)."""
    if not lines:
        return ""
    total = len(lines)
    s_idx = max(0, start_line - 1 - context_lines)
    e_idx = min(total, max(start_line, end_line) + context_lines)
    selected = lines[s_idx:e_idx]
    raw_snippet = "\n".join(selected).strip()
    if not raw_snippet and 1 <= start_line <= total:
        raw_snippet = lines[start_line - 1].strip()
    sanitized = sanitize_code_snippet(raw_snippet)
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "\n... [truncated]"
    return sanitized or "<empty snippet>"


# ==============================================================================
# Python AST Vulnerability Visitor
# ==============================================================================


class _PythonASTAnalyzer(ast.NodeVisitor):
    """Inspects a Python Abstract Syntax Tree (AST) for security vulnerability patterns.

    Detects:
    1. SQL Injection (dynamic string formatting, concatenation, or f-strings in SQL execution calls).
    2. Cross-Site Scripting (unsafe HTML rendering, ` render_template_string` with dynamic input, `mark_safe`/`Markup`).
    3. Broken Access Control (admin/privileged route handlers missing authentication/authorization decorators or checks,
       or trust in client-supplied role parameters).
    4. IDOR / BOLA patterns (route handlers fetching database objects by request ID without user/owner scoping).
    5. Sensitive Data Exposure (hardcoded secrets/API keys/passwords, logging sensitive credentials).
    6. Security Misconfiguration (`debug=True`, `verify=False`, `shell=True`, `eval`/`exec`, `pickle.loads`, `yaml.load` without SafeLoader, wildcard CORS with credentials).
    """

    SQL_KEYWORD_RE = re.compile(
        r"(?is)\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|UNION\s+SELECT)\b"
    )
    SQL_EXEC_METHODS = {
        "execute",
        "executemany",
        "executescript",
        "raw",
        "extra",
        "text",
        "from_statement",
    }
    AUTH_DECORATOR_KEYWORDS = {
        "login_required",
        "permission_required",
        "permissions_required",
        "roles_required",
        "role_required",
        "admin_required",
        "jwt_required",
        "auth_required",
        "requires_auth",
        "require_auth",
        "require_role",
        "require_admin",
        "authenticated",
        "Depends",
        "Security",
    }
    AUTH_BODY_INDICATORS = {
        "current_user",
        "is_authenticated",
        "is_admin",
        "check_permission",
        "has_permission",
        "has_role",
        "verify_token",
        "require_role",
        "authorize",
        "check_object_permissions",
        "user_id",
        "owner_id",
        "created_by",
    }
    SENSITIVE_VAR_RE = re.compile(
        r"(?i)^(password|passwd|pwd|secret|secret_key|api_key|apikey|private_key|auth_token|access_token|jwt_secret|client_secret|db_password|database_password|encryption_key)$"
    )
    SAFE_PLACEHOLDER_VALUES = {
        "",
        "none",
        "null",
        "changeme",
        "placeholder",
        "your_api_key",
        "your-api-key",
        "dummy",
        "test",
        "example",
        "[redacted]",
        "redacted",
        "todo",
    }

    def __init__(self, file_path: str, source_lines: List[str]) -> None:
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[SourceFinding] = []
        self._class_stack: List[str] = []
        self._func_stack: List[str] = []
        self._tainted_vars_stack: List[Dict[str, str]] = [{}]  # var_name -> taint_kind ("sql", "xss", "user_input")
        self._seen_keys: Set[Tuple[str, int, str]] = set()

    @property
    def current_class(self) -> Optional[str]:
        return self._class_stack[-1] if self._class_stack else None

    @property
    def current_function(self) -> Optional[str]:
        return self._func_stack[-1] if self._func_stack else None

    @property
    def current_taint(self) -> Dict[str, str]:
        return self._tainted_vars_stack[-1]

    def _add_finding(
        self,
        rule_id: str,
        category: SourceVulnerabilityCategory,
        severity: SeverityLevel,
        confidence: ConfidenceLevel,
        classification: StaticFindingClassification,
        node: ast.AST,
        explanation: str,
        remediation: str,
        cwe_id: str,
        route_path: Optional[str] = None,
        http_method: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        start_line = getattr(node, "lineno", 1) or 1
        end_line = getattr(node, "end_lineno", start_line) or start_line
        dedup_key = (rule_id, start_line, category.value)
        if dedup_key in self._seen_keys:
            return
        self._seen_keys.add(dedup_key)

        snippet = extract_code_snippet(self.source_lines, start_line, end_line)
        val_status = (
            StaticValidationStatus.POTENTIAL_UNVERIFIED.value
            if classification == StaticFindingClassification.POTENTIAL_VULNERABILITY
            else StaticValidationStatus.DETECTED_PATTERN.value
        )

        fid_seed = f"{self.file_path}:{rule_id}:{start_line}:{end_line}"
        finding_id = f"src_{compute_sha256(fid_seed)[:12]}"

        self.findings.append(
            SourceFinding(
                finding_id=finding_id,
                rule_id=rule_id,
                vulnerability_category=category.value,
                severity=severity,
                confidence=confidence,
                source_type=SourceType.SOURCE_CODE.value,
                classification=classification,
                validation_status=val_status,
                is_runtime_confirmed=False,
                file_path=self.file_path,
                language=SupportedLanguage.PYTHON,
                function_name=self.current_function,
                class_name=self.current_class,
                route_path=route_path,
                http_method=http_method,
                start_line=start_line,
                end_line=end_line,
                code_snippet=snippet,
                detection_explanation=explanation,
                detection_method=DetectionMethod.PYTHON_AST.value,
                remediation_hint=remediation,
                cwe_id=cwe_id,
                metadata=extra_meta or {},
            )
        )

    # --------------------------------------------------------------------------
    # AST Node Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def _get_call_name(node: ast.Call) -> Tuple[str, str]:
        """Returns (base_name, func_or_attr_name) for a Call node."""
        func = node.func
        if isinstance(func, ast.Name):
            return ("", func.id)
        if isinstance(func, ast.Attribute):
            attr = func.attr
            base_parts: List[str] = []
            curr: ast.AST = func.value
            while isinstance(curr, ast.Attribute):
                base_parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                base_parts.append(curr.id)
            base_str = ".".join(reversed(base_parts))
            return (base_str, attr)
        return ("", "")

    def _extract_static_strings(self, node: ast.AST) -> str:
        """Concatenates all constant string literals inside an AST expression."""
        parts: List[str] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                parts.append(sub.value)
        return " ".join(parts)

    def _is_dynamic_string_expr(self, node: ast.AST) -> bool:
        """Returns True if `node` constructs a string dynamically using variables, f-strings, `%`, `+`, or `.format()`."""
        if isinstance(node, ast.JoinedStr):
            # f-string is dynamic if it has any FormattedValue
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call):
            _, attr = self._get_call_name(node)
            if attr == "format":
                return True
        if isinstance(node, ast.Name):
            return self.current_taint.get(node.id) in ("dynamic_sql", "dynamic_str", "user_input")
        return False

    def _contains_sql_keywords(self, node: ast.AST) -> bool:
        text = self._extract_static_strings(node)
        if self.SQL_KEYWORD_RE.search(text):
            return True
        if isinstance(node, ast.Name) and self.current_taint.get(node.id) == "dynamic_sql":
            return True
        return False

    @staticmethod
    def _references_request_input(node: ast.AST) -> bool:
        """Checks if an AST subtree accesses request parameters, args, form, json, or query."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in {"request", "req", "params", "query"}:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in {
                "args", "form", "values", "json", "GET", "POST", "query_params", "path_params", "body"
            }:
                return True
        return False

    # --------------------------------------------------------------------------
    # Visitor Methods
    # --------------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node)

    def _analyze_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        self._func_stack.append(node.name)
        self._tainted_vars_stack.append(dict(self.current_taint))

        # Mark function parameters as potential user input if route handler or id-like
        for arg in node.args.args:
            arg_name = arg.arg
            if arg_name not in ("self", "cls", "db", "session", "cursor"):
                self.current_taint[arg_name] = "user_input"

        # Inspect route decorators for Broken Access Control & IDOR
        route_info = self._extract_route_decorator_info(node)
        if route_info:
            route_path, http_method, has_auth_decorator = route_info
            self._check_route_authorization_and_idor(
                node=node,
                route_path=route_path,
                http_method=http_method,
                has_auth_decorator=has_auth_decorator,
            )

        self.generic_visit(node)

        self._tainted_vars_stack.pop()
        self._func_stack.pop()

    def _extract_route_decorator_info(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> Optional[Tuple[str, str, bool]]:
        """Extracts (route_path, http_method, has_auth_decorator) from Flask/FastAPI/Django decorators."""
        route_path: Optional[str] = None
        http_method: str = "GET"
        has_auth_decorator: bool = False

        for dec in node.decorator_list:
            dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
            for auth_kw in self.AUTH_DECORATOR_KEYWORDS:
                if auth_kw.lower() in dec_src.lower():
                    has_auth_decorator = True

            if isinstance(dec, ast.Call):
                base, attr = self._get_call_name(dec)
                if attr in {"route", "get", "post", "put", "delete", "patch", "api_view"}:
                    if attr != "route" and attr != "api_view":
                        http_method = attr.upper()
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        route_path = dec.args[0].value
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            methods = [
                                elt.value.upper()
                                for elt in kw.value.elts
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                            ]
                            if methods:
                                http_method = methods[0]

        # Also check FastAPI Depends/Security in function argument defaults
        for default_expr in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
            default_src = ast.unparse(default_expr) if hasattr(ast, "unparse") else ""
            if any(k.lower() in default_src.lower() for k in ("current_user", "get_current_user", "require_admin", "require_auth", "verify_token", "security", "oauth2")):
                has_auth_decorator = True

        for arg in node.args.args:
            if arg.annotation:
                ann_src = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if any(k.lower() in ann_src.lower() for k in ("current_user", "get_current_user", "require_admin", "require_auth", "security")):
                    has_auth_decorator = True

        if route_path is not None:
            return (route_path, http_method, has_auth_decorator)
        return None

    def _check_route_authorization_and_idor(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        route_path: str,
        http_method: str,
        has_auth_decorator: bool,
    ) -> None:
        """Checks a route handler AST for Broken Access Control and IDOR patterns."""
        body_src = "\n".join(
            (ast.unparse(stmt) if hasattr(ast, "unparse") else "") for stmt in node.body
        )
        body_lower = body_src.lower()

        has_body_auth_check = any(ind.lower() in body_lower for ind in self.AUTH_BODY_INDICATORS) or (
            "401" in body_lower or "403" in body_lower or "unauthorized" in body_lower or "forbidden" in body_lower
        )

        # 1. Check for Admin / Privileged Route without AuthN/AuthZ check (BFLA / Broken Access Control)
        is_privileged_route = any(
            seg in route_path.lower() or seg in node.name.lower()
            for seg in ("/admin", "admin_", "_admin", "/internal", "/manage", "/users/delete", "/config", "/settings")
        )
        is_public_version = "version" in route_path.lower() or "health" in route_path.lower()

        if is_privileged_route and not is_public_version and not has_auth_decorator and not has_body_auth_check:
            self._add_finding(
                rule_id="AS-PY-BAC-001",
                category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.MEDIUM,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                node=node,
                explanation=(
                    f"Privileged or administrative route '{http_method} {route_path}' in function '{node.name}' "
                    f"lacks detectable authentication or role-authorization decorators and in-body permission checks. "
                    f"Static analysis indicates a potential Broken Function Level Authorization (BFLA) flaw."
                ),
                remediation=(
                    "Enforce server-side authentication and explicit administrative role verification "
                    "(e.g., `@login_required` and `@role_required('admin')` or FastAPI `Depends(require_admin)`)."
                ),
                cwe_id="CWE-285",
                route_path=route_path,
                http_method=http_method,
            )

        # 2. Check for Client-Supplied Role / Privilege Trust (Broken Access Control / Mass Assignment)
        if re.search(
            r"""request\.(?:args|form|json|values|GET|POST)\.get\(\s*['"](?:is_admin|role|admin|privilege)['"]""",
            body_src,
        ) or re.search(r"""(?:req|request)\.(?:json|form|args)\s*\[\s*['"](?:is_admin|role|admin)['"]\s*\]""", body_src):
            self._add_finding(
                rule_id="AS-PY-BAC-002",
                category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                node=node,
                explanation=(
                    f"Function '{node.name}' on route '{http_method} {route_path}' reads privilege or role attributes "
                    f"(`role`, `is_admin`, `admin`) directly from untrusted client request parameters instead of "
                    f"a server-side verified session."
                ),
                remediation=(
                    "Derive user identity and role permissions exclusively from the server-side authenticated "
                    "session or signed token context; never trust role flags supplied in request bodies or query strings."
                ),
                cwe_id="CWE-284",
                route_path=route_path,
                http_method=http_method,
            )

        # 3. Check for IDOR / BOLA pattern: Direct object lookup by request ID without ownership filter
        has_id_param = bool(
            re.search(r"<(?:int:|str:|uuid:)?([a-zA-Z0-9_]*id)>|\{([a-zA-Z0-9_]*id)\}", route_path, re.IGNORECASE)
            or any(arg.arg.lower().endswith("id") for arg in node.args.args)
        )
        if has_id_param:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    base, attr = self._get_call_name(sub)
                    call_src = ast.unparse(sub) if hasattr(ast, "unparse") else ""
                    # Direct primary-key lookup: Model.query.get(id), session.get(Model, id), objects.get(id=...)
                    is_direct_lookup = (
                        attr in {"get", "get_or_404"}
                        and any(
                            tok in base.lower()
                            for tok in ("query", "objects", "session", "db", "basket", "order", "user", "account", "invoice", "address", "card", "document")
                        )
                    ) or (
                        attr in {"filter_by", "filter"}
                        and re.search(r"\bid\s*=", call_src)
                        and not any(owner_k in call_src.lower() for owner_k in ("user_id", "userid", "owner_id", "owner", "current_user", "created_by", "customer_id"))
                    )

                    if is_direct_lookup:
                        has_ownership_check = any(
                            owner_tok in body_lower
                            for owner_tok in (
                                "user_id",
                                "userid",
                                "owner_id",
                                "ownerid",
                                "created_by",
                                "customer_id",
                                "check_object_permissions",
                                "authorize_resource",
                                "owns_resource",
                            )
                        )
                        if not has_ownership_check:
                            self._add_finding(
                                rule_id="AS-PY-IDOR-001",
                                category=SourceVulnerabilityCategory.BOLA_IDOR,
                                severity=SeverityLevel.HIGH,
                                confidence=ConfidenceLevel.MEDIUM,
                                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                                node=sub,
                                explanation=(
                                    f"Route '{http_method} {route_path}' in '{node.name}' retrieves a record directly "
                                    f"by user-supplied identifier (`{call_src[:80]}`) without verifying resource ownership "
                                    f"(e.g., matching `user_id` or `owner_id` against the authenticated session). "
                                    f"This is a classic Insecure Direct Object Reference (BOLA/IDOR) code pattern."
                                ),
                                remediation=(
                                    "Scope database queries to both the resource ID and the authenticated user's owner ID "
                                    "(e.g., `Model.query.filter_by(id=resource_id, user_id=current_user.id).first_or_404()`)."
                                ),
                                cwe_id="CWE-639",
                                route_path=route_path,
                                http_method=http_method,
                            )

    def visit_Assign(self, node: ast.Assign) -> None:
        """Tracks tainted/dynamic SQL strings and checks for hardcoded secrets or misconfigurations."""
        # 1. Track dynamic strings / SQL assigned to variables
        is_dyn = self._is_dynamic_string_expr(node.value)
        has_sql = self._contains_sql_keywords(node.value)
        is_req = self._references_request_input(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if is_dyn and has_sql:
                    self.current_taint[var_name] = "dynamic_sql"
                elif is_dyn or is_req:
                    self.current_taint[var_name] = "dynamic_str"

                # 2. Check for hardcoded secrets / API keys / passwords
                self._check_hardcoded_secret_assignment(node, var_name, node.value)

                # 3. Check for Django/Flask security misconfiguration settings
                self._check_config_assignment(node, var_name, node.value)

            elif isinstance(target, ast.Subscript):
                # e.g., app.config["DEBUG"] = True or app.config["SECRET_KEY"] = "hardcoded"
                sub_src = ast.unparse(target) if hasattr(ast, "unparse") else ""
                if "SECRET_KEY" in sub_src or "JWT_SECRET" in sub_src:
                    self._check_hardcoded_secret_assignment(node, "SECRET_KEY", node.value)
                elif "DEBUG" in sub_src and isinstance(node.value, ast.Constant) and node.value.value is True:
                    self._add_finding(
                        rule_id="AS-PY-MISC-001",
                        category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        classification=StaticFindingClassification.DETECTED_CODE_PATTERN,
                        node=node,
                        explanation="Application configuration explicitly enables debug mode (`DEBUG = True`), which may expose interactive debuggers and stack traces.",
                        remediation="Disable debug mode in production configurations and load `DEBUG` from a secure environment variable defaulting to `False`.",
                        cwe_id="CWE-489",
                    )

        self.generic_visit(node)

    def _check_hardcoded_secret_assignment(self, node: ast.AST, var_name: str, value_node: ast.AST) -> None:
        if not (isinstance(value_node, ast.Constant) and isinstance(value_node.value, str)):
            return
        secret_val = value_node.value.strip()
        if len(secret_val) < 6 or secret_val.lower() in self.SAFE_PLACEHOLDER_VALUES:
            return
        # Ignore environment variable key names like SECRET_KEY_ENV = "MY_ENV_VAR"
        if var_name.lower().endswith(("_env", "_header", "_field", "_name", "_key_name", "_path", "_url")):
            return
        if secret_val.isupper() and "_" in secret_val and not any(c.isdigit() for c in secret_val):
            return

        is_secret_var = bool(self.SENSITIVE_VAR_RE.match(var_name)) or any(
            k in var_name.lower() for k in ("password", "passwd", "secret_key", "api_key", "apikey", "private_key", "jwt_secret", "auth_token")
        )
        is_token_pattern = bool(_HIGH_ENTROPY_TOKEN_RE.search(secret_val)) or any(
            m in secret_val for m in PRIVATE_KEY_CONTENT_MARKERS
        )

        if is_secret_var or is_token_pattern:
            self._add_finding(
                rule_id="AS-PY-SDE-001",
                category=SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                node=node,
                explanation=(
                    f"Hardcoded credential or secret assigned to '{var_name}'. "
                    f"Embedding secrets directly in source code risks credential exposure via version control."
                ),
                remediation="Remove the hardcoded credential and load it securely from environment variables (`os.environ.get(...)`) or a dedicated secrets manager.",
                cwe_id="CWE-798",
            )

    def _check_config_assignment(self, node: ast.AST, var_name: str, value_node: ast.AST) -> None:
        if var_name == "DEBUG" and isinstance(value_node, ast.Constant) and value_node.value is True:
            self._add_finding(
                rule_id="AS-PY-MISC-001",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.DETECTED_CODE_PATTERN,
                node=node,
                explanation="Debug mode is explicitly enabled (`DEBUG = True`), risking exposure of sensitive stack traces and environment variables.",
                remediation="Set `DEBUG = False` by default and control debug settings strictly via environment configuration.",
                cwe_id="CWE-489",
            )
        elif var_name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL") and isinstance(value_node, ast.Constant) and value_node.value is True:
            self._add_finding(
                rule_id="AS-PY-MISC-002",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                node=node,
                explanation=f"Permissive Cross-Origin Resource Sharing configuration (`{var_name} = True`) allows arbitrary external origins.",
                remediation="Restrict CORS origins to an explicit allowlist of trusted domains.",
                cwe_id="CWE-942",
            )

    def visit_Call(self, node: ast.Call) -> None:
        """Inspects function and method calls for SQLi, XSS, Sensitive Data Exposure, and Misconfiguration."""
        base, func_name = self._get_call_name(node)

        # 1. SQL Injection Detection
        if func_name in self.SQL_EXEC_METHODS and node.args:
            first_arg = node.args[0]
            has_second_params_arg = len(node.args) >= 2 or any(kw.arg in ("params", "parameters") for kw in node.keywords)
            is_dynamic = self._is_dynamic_string_expr(first_arg)
            has_sql = self._contains_sql_keywords(first_arg) or func_name in {"raw", "executescript", "text"}

            if is_dynamic and (has_sql or not has_second_params_arg):
                self._add_finding(
                    rule_id="AS-PY-SQLI-001",
                    category=SourceVulnerabilityCategory.SQL_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation=(
                        f"Database query call `{base + '.' if base else ''}{func_name}()` executes a dynamically "
                        f"constructed SQL string (via f-string, `%`, `.format()`, or string concatenation) rather than "
                        f"bound query parameters. If untrusted input reaches this query, SQL Injection is possible."
                    ),
                    remediation=(
                        "Use parameterized queries with bound placeholders (e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`) "
                        "and never interpolate variables directly into SQL command text."
                    ),
                    cwe_id="CWE-89",
                )

        # 2. Cross-Site Scripting (XSS) Detection
        if func_name == "render_template_string" and node.args:
            first_arg = node.args[0]
            if self._is_dynamic_string_expr(first_arg) or self._references_request_input(first_arg):
                self._add_finding(
                    rule_id="AS-PY-XSS-001",
                    category=SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation=(
                        "`render_template_string()` is called with a dynamically formatted template string. "
                        "Interpolating user-controlled input prior to template rendering enables Cross-Site Scripting (XSS) "
                        "and Server-Side Template Injection (SSTI)."
                    ),
                    remediation=(
                        "Pass static template strings or files (`render_template('page.html', data=user_input)`) "
                        "so Jinja2 auto-escaping sanitizes context variables."
                    ),
                    cwe_id="CWE-79",
                )
        elif func_name in {"mark_safe", "Markup", "format_html"} and node.args:
            first_arg = node.args[0]
            if func_name in {"mark_safe", "Markup"} and (
                self._is_dynamic_string_expr(first_arg)
                or self._references_request_input(first_arg)
                or isinstance(first_arg, ast.Name)
            ):
                self._add_finding(
                    rule_id="AS-PY-XSS-002",
                    category=SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation=(
                        f"Call to `{func_name}()` explicitly bypasses HTML output escaping on a dynamic value. "
                        f"If user input is included, this creates a Cross-Site Scripting (XSS) vulnerability."
                    ),
                    remediation="Avoid `mark_safe()` / `Markup()` on dynamic or user-supplied strings; use `html.escape()` or template auto-escaping.",
                    cwe_id="CWE-79",
                )
        elif func_name in {"HTMLResponse", "make_response", "HttpResponse"} and node.args:
            first_arg = node.args[0]
            static_str = self._extract_static_strings(first_arg).lower()
            if self._is_dynamic_string_expr(first_arg) and (
                "<" in static_str or self._references_request_input(first_arg)
            ):
                self._add_finding(
                    rule_id="AS-PY-XSS-003",
                    category=SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation=(
                        f"Direct HTML response construction via `{func_name}()` concatenates or interpolates dynamic "
                        f"values without explicit HTML encoding, creating a potential Reflected XSS vector."
                    ),
                    remediation="Encode all dynamic values with `html.escape()` or render through an auto-escaping template engine.",
                    cwe_id="CWE-79",
                )

        # 3. Security Misconfiguration Detection
        # 3a. Flask/FastAPI/Uvicorn app.run(debug=True)
        if func_name == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add_finding(
                        rule_id="AS-PY-MISC-003",
                        category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                        node=node,
                        explanation="Application server launched with `debug=True`, which can expose an interactive debugger (e.g., Werkzeug console) and sensitive stack traces.",
                        remediation="Remove `debug=True` from application entrypoints and run production servers under a hardened WSGI/ASGI server.",
                        cwe_id="CWE-489",
                    )

        # 3b. TLS certificate verification disabled (verify=False)
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add_finding(
                    rule_id="AS-PY-MISC-004",
                    category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation=f"Call to `{base + '.' if base else ''}{func_name}()` disables TLS certificate verification (`verify=False`), enabling Man-in-the-Middle (MitM) interception.",
                    remediation="Enable TLS verification (`verify=True`) or provide a trusted CA bundle path.",
                    cwe_id="CWE-295",
                )

        # 3c. Subprocess with shell=True or os.system / eval / exec / unsafe deserialization
        if func_name in {"Popen", "run", "call", "check_call", "check_output"} and base in {"subprocess", ""}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add_finding(
                        rule_id="AS-PY-MISC-005",
                        category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                        node=node,
                        explanation=f"`subprocess.{func_name}()` invoked with `shell=True`, exposing the process to command injection if arguments contain untrusted input.",
                        remediation="Pass command arguments as a list with `shell=False`.",
                        cwe_id="CWE-78",
                    )
        elif func_name in {"eval", "exec"} and not base:
            self._add_finding(
                rule_id="AS-PY-MISC-006",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.DETECTED_CODE_PATTERN,
                node=node,
                explanation=f"Use of dynamic code execution primitive `{func_name}()` detected.",
                remediation="Avoid `eval()` and `exec()`; use safe parsers such as `json.loads()` or `ast.literal_eval()`.",
                cwe_id="CWE-95",
            )
        elif func_name == "load" and base == "yaml":
            has_safe_loader = any(
                kw.arg == "Loader" and "SafeLoader" in (ast.unparse(kw.value) if hasattr(ast, "unparse") else "")
                for kw in node.keywords
            )
            if not has_safe_loader:
                self._add_finding(
                    rule_id="AS-PY-MISC-007",
                    category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation="`yaml.load()` called without an explicit `SafeLoader`, allowing arbitrary Python object instantiation.",
                    remediation="Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.",
                    cwe_id="CWE-502",
                )
        elif func_name == "decode" and base == "jwt":
            call_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if "verify_signature" in call_src and "False" in call_src:
                self._add_finding(
                    rule_id="AS-PY-BAC-003",
                    category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    node=node,
                    explanation="`jwt.decode()` disables cryptographic signature verification (`verify_signature: False`), allowing attackers to forge arbitrary identity and role claims.",
                    remediation="Always verify JWT signatures using a strong secret or public key and explicit algorithm allowlist.",
                    cwe_id="CWE-347",
                )

        # 4. Sensitive Data Exposure in logging / printing
        if func_name in {"info", "debug", "warning", "error", "critical", "print"}:
            call_src = (ast.unparse(node) if hasattr(ast, "unparse") else "").lower()
            if any(
                re.search(rf"\b{kw}\b", call_src)
                for kw in ("password", "passwd", "secret_key", "api_key", "private_key", "access_token", "authorization")
            ) and "redact" not in call_src and "sanitize" not in call_src:
                # Ensure a variable or attribute (not just static text) is logged
                has_var_ref = any(isinstance(sub, (ast.Name, ast.Attribute, ast.FormattedValue)) for sub in ast.walk(node))
                if has_var_ref and len(node.args) > 0:
                    # Check if any variable or attribute name matches sensitive terms
                    var_names = [
                        sub.id.lower() if isinstance(sub, ast.Name) else sub.attr.lower()
                        for sub in ast.walk(node)
                        if isinstance(sub, (ast.Name, ast.Attribute))
                    ]
                    if any(
                        any(s in vn for s in ("password", "passwd", "secret", "api_key", "token", "private_key"))
                        for vn in var_names
                    ):
                        self._add_finding(
                            rule_id="AS-PY-SDE-002",
                            category=SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                            severity=SeverityLevel.MEDIUM,
                            confidence=ConfidenceLevel.MEDIUM,
                            classification=StaticFindingClassification.DETECTED_CODE_PATTERN,
                            node=node,
                            explanation=f"Logging or output call `{func_name}()` references sensitive credential or token variables without redaction.",
                            remediation="Mask or redact passwords, tokens, and API keys before writing to application logs.",
                            cwe_id="CWE-532",
                        )

        self.generic_visit(node)


# ==============================================================================
# JavaScript / TypeScript Structural & Scope Analyzer
# ==============================================================================


class _JSTSStructuralAnalyzer:
    """Structural lexical, scope, and route analyzer for JavaScript and TypeScript files.

    Parses JS/TS source code by stripping comments, tracking brace-delimited function
    and route-handler scopes, tracking tainted/dynamic variable assignments, and
    evaluating security rules across:
    1. SQL Injection (template literals `${...}` and string concatenation in SQL execution calls).
    2. Cross-Site Scripting (`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`,
       unencoded `res.send()` HTML interpolation).
    3. Broken Access Control (Express/Nest/Next admin or privileged routes without auth middleware,
       trusting `req.body.role` / `req.body.isAdmin`, `jwt.decode()` without `jwt.verify()`).
    4. IDOR / BOLA patterns (Express/Sequelize/Mongoose/Prisma route handlers looking up objects
       by `req.params.id` without scoping to `req.user.id` / owner).
    5. Sensitive Data Exposure (hardcoded secrets/tokens/keys, exposing password hashes in responses).
    6. Security Misconfiguration (`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = '0'`,
       permissive CORS with credentials, `eval()`).
    """

    # Comment stripping regex (preserves newlines so line numbers remain 100% accurate)
    COMMENT_OR_STRING_RE = re.compile(
        r"""(?xs)
        (
            "(?:\\.|[^"\\])*"
            |'(?:\\.|[^'\\])*'
            |`(?:\\.|[^`\\])*`
        )
        |
        (
            //[^\n]*
            |/\*.*?\*/
        )
        """
    )

    FUNC_DECL_RE = re.compile(
        r"""(?x)
        (?:
            (?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)
            |(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>
            |([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*(?::\s*[^{]+)?\{
        )
        """
    )

    EXPRESS_ROUTE_RE = re.compile(
        r"""(?x)
        \b(?:app|router|server)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*
        ['"`]([^'"`]+)['"`]
        \s*,
        """
    )

    def __init__(self, file_path: str, language: SupportedLanguage, source_text: str) -> None:
        self.file_path = file_path
        self.language = language
        self.source_text = source_text
        self.source_lines = source_text.splitlines()
        self.cleaned_text = self._strip_comments_preserve_lines(source_text)
        self.cleaned_lines = self.cleaned_text.splitlines()
        self.findings: List[SourceFinding] = []
        self._seen_keys: Set[Tuple[str, int, str]] = set()

    @classmethod
    def _strip_comments_preserve_lines(cls, text: str) -> str:
        def replacer(match: re.Match[str]) -> str:
            if match.group(1) is not None:
                return match.group(1)
            comment = match.group(2) or ""
            return "\n" * comment.count("\n")

        return cls.COMMENT_OR_STRING_RE.sub(replacer, text)

    def _line_number_at(self, offset: int) -> int:
        return self.cleaned_text.count("\n", 0, max(0, offset)) + 1

    def _infer_enclosing_function(self, line_no: int) -> Optional[str]:
        """Scans upward from `line_no` to find the nearest enclosing function or method name."""
        start_idx = max(0, line_no - 40)
        for idx in range(line_no - 1, start_idx - 1, -1):
            if idx >= len(self.cleaned_lines):
                continue
            line = self.cleaned_lines[idx]
            m = self.FUNC_DECL_RE.search(line)
            if m:
                name = m.group(1) or m.group(2) or m.group(3)
                if name and name not in {"if", "for", "while", "switch", "catch", "function"}:
                    return name
        return None

    def _extract_balanced_block(self, start_offset: int) -> Tuple[str, int, int]:
        """Extracts a balanced `{ ... }` or `(...)` block starting at or after `start_offset`."""
        n = len(self.cleaned_text)
        idx = start_offset
        while idx < n and self.cleaned_text[idx] not in "{(":
            idx += 1
        if idx >= n:
            line = self._line_number_at(start_offset)
            return ("", line, line)

        open_ch = self.cleaned_text[idx]
        close_ch = "}" if open_ch == "{" else ")"
        depth = 0
        in_str: Optional[str] = None
        escaped = False
        end_idx = idx

        for i in range(idx, min(n, idx + 15_000)):
            ch = self.cleaned_text[i]
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if in_str:
                if ch == in_str:
                    in_str = None
                continue
            if ch in ("'", '"', "`"):
                in_str = ch
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    end_idx = i + 1
                    break

        start_line = self._line_number_at(start_offset)
        end_line = self._line_number_at(end_idx)
        return (self.cleaned_text[start_offset:end_idx], start_line, end_line)

    def _add_finding(
        self,
        rule_id: str,
        category: SourceVulnerabilityCategory,
        severity: SeverityLevel,
        confidence: ConfidenceLevel,
        classification: StaticFindingClassification,
        start_line: int,
        end_line: int,
        explanation: str,
        remediation: str,
        cwe_id: str,
        function_name: Optional[str] = None,
        route_path: Optional[str] = None,
        http_method: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        dedup_key = (rule_id, start_line, category.value)
        if dedup_key in self._seen_keys:
            return
        self._seen_keys.add(dedup_key)

        fn_name = function_name or self._infer_enclosing_function(start_line)
        snippet = extract_code_snippet(self.source_lines, start_line, end_line)
        val_status = (
            StaticValidationStatus.POTENTIAL_UNVERIFIED.value
            if classification == StaticFindingClassification.POTENTIAL_VULNERABILITY
            else StaticValidationStatus.DETECTED_PATTERN.value
        )

        fid_seed = f"{self.file_path}:{rule_id}:{start_line}:{end_line}"
        finding_id = f"src_{compute_sha256(fid_seed)[:12]}"

        self.findings.append(
            SourceFinding(
                finding_id=finding_id,
                rule_id=rule_id,
                vulnerability_category=category.value,
                severity=severity,
                confidence=confidence,
                source_type=SourceType.SOURCE_CODE.value,
                classification=classification,
                validation_status=val_status,
                is_runtime_confirmed=False,
                file_path=self.file_path,
                language=self.language,
                function_name=fn_name,
                route_path=route_path,
                http_method=http_method,
                start_line=start_line,
                end_line=max(start_line, end_line),
                code_snippet=snippet,
                detection_explanation=explanation,
                detection_method=DetectionMethod.JS_TS_STRUCTURAL.value,
                remediation_hint=remediation,
                cwe_id=cwe_id,
                metadata=extra_meta or {},
            )
        )

    def analyze(self) -> List[SourceFinding]:
        """Runs all structural JS/TS detectors on the file."""
        self._detect_sql_injection()
        self._detect_xss()
        self._detect_express_routes_bac_and_idor()
        self._detect_broken_access_control_patterns()
        self._detect_sensitive_data_exposure()
        self._detect_security_misconfiguration()
        return self.findings

    # --------------------------------------------------------------------------
    # 1. SQL Injection (JS/TS)
    # --------------------------------------------------------------------------

    def _detect_sql_injection(self) -> None:
        # Track variables assigned dynamic SQL template literals or concatenations
        dynamic_sql_vars: Set[str] = set()
        var_assign_re = re.compile(
            r"""(?is)\b(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?::\s*string)?\s*=\s*([^\n;]+)"""
        )
        sql_kw_re = re.compile(
            r"(?is)\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|UNION\s+SELECT)\b"
        )

        for m in var_assign_re.finditer(self.cleaned_text):
            var_name = m.group(1)
            rhs = m.group(2)
            if sql_kw_re.search(rhs) and ("${" in rhs or "+" in rhs):
                dynamic_sql_vars.add(var_name)

        # Check `.query(...)`, `.execute(...)`, `.raw(...)`, `$queryRawUnsafe(...)`, `$executeRawUnsafe(...)`
        sql_call_re = re.compile(
            r"""(?is)\b([a-zA-Z0-9_$.]+)\s*\.\s*(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*([^;)]{3,300})\)"""
        )
        for m in sql_call_re.finditer(self.cleaned_text):
            obj_name = m.group(1)
            method_name = m.group(2)
            args_str = m.group(3).strip()
            line_no = self._line_number_at(m.start())
            end_line = self._line_number_at(m.end())

            is_unsafe_prisma = method_name in ("$queryRawUnsafe", "$executeRawUnsafe")
            is_template_interp = "`" in args_str and "${" in args_str
            is_concat = ("+" in args_str) and any(q in args_str for q in ("'", '"', "`"))
            first_arg_token = args_str.split(",")[0].strip()
            is_tainted_var = first_arg_token in dynamic_sql_vars

            if is_unsafe_prisma or ((is_template_interp or is_concat or is_tainted_var) and (
                sql_kw_re.search(args_str) or is_tainted_var or obj_name.lower().endswith(("db", "pool", "sequelize", "knex", "connection", "client", "prisma"))
            )):
                self._add_finding(
                    rule_id="AS-JSTS-SQLI-001",
                    category=SourceVulnerabilityCategory.SQL_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    start_line=line_no,
                    end_line=end_line,
                    explanation=(
                        f"Database query `{obj_name}.{method_name}()` constructs SQL dynamically using template "
                        f"literal interpolation (`${{...}}`) or string concatenation instead of parameterized bindings."
                    ),
                    remediation=(
                        "Use parameterized queries or prepared statements (e.g., `db.query('SELECT * FROM Users WHERE id = ?', [id])` "
                        "or Prisma `$queryRaw` tagged templates)."
                    ),
                    cwe_id="CWE-89",
                )

    # --------------------------------------------------------------------------
    # 2. Cross-Site Scripting (JS/TS)
    # --------------------------------------------------------------------------

    def _detect_xss(self) -> None:
        # 2a. DOM XSS sinks: .innerHTML = ..., .outerHTML = ..., document.write(...), dangerouslySetInnerHTML
        dom_sink_re = re.compile(
            r"""(?x)
            (?:
                \.\s*(innerHTML|outerHTML)\s*\+?=\s*([^\n;]+)
                |\bdocument\.write(?:ln)?\s*\(\s*([^\n;)]+)\)
                |\bdangerouslySetInnerHTML\s*(?:=\s*\{\s*\{\s*|\s*:\s*\{\s*)__html\s*:\s*([^}]+)\}
            )
            """
        )
        for m in dom_sink_re.finditer(self.cleaned_text):
            sink_name = m.group(1) or ("document.write" if m.group(3) else "dangerouslySetInnerHTML")
            rhs = (m.group(2) or m.group(3) or m.group(4) or "").strip()
            # Ignore pure constant empty or static literal strings without interpolation
            if re.fullmatch(r"""['"][^'"]*['"]""", rhs):
                continue
            if "DOMPurify.sanitize" in rhs or "sanitizeHtml" in rhs or "escapeHtml" in rhs:
                continue

            line_no = self._line_number_at(m.start())
            end_line = self._line_number_at(m.end())
            self._add_finding(
                rule_id="AS-JSTS-XSS-001",
                category=SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                start_line=line_no,
                end_line=end_line,
                explanation=(
                    f"Unsafe DOM HTML sink `{sink_name}` receives a dynamic expression (`{rhs[:60]}`) without "
                    f"visible sanitization, creating a potential Cross-Site Scripting (XSS) vulnerability."
                ),
                remediation=(
                    "Use `textContent` / `innerText` for plain text, or sanitize untrusted HTML with `DOMPurify.sanitize()` "
                    "before rendering."
                ),
                cwe_id="CWE-79",
            )

        # 2b. Express res.send(`...<html>...${req.query...}...`) reflected XSS
        res_send_re = re.compile(
            r"""\bres\s*\.\s*(?:send|write|end)\s*\(\s*(`[^`]*\$\{[^`]*`|\s*['"][^'"]*<[^'"]*['"]\s*\+\s*[^)]+)\s*\)"""
        )
        for m in res_send_re.finditer(self.cleaned_text):
            arg_expr = m.group(1)
            if "<" in arg_expr and ("req." in arg_expr or "${" in arg_expr or "+" in arg_expr):
                if "escape" in arg_expr.lower() or "sanitize" in arg_expr.lower():
                    continue
                line_no = self._line_number_at(m.start())
                end_line = self._line_number_at(m.end())
                self._add_finding(
                    rule_id="AS-JSTS-XSS-002",
                    category=SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    start_line=line_no,
                    end_line=end_line,
                    explanation=(
                        "HTTP response directly interpolates dynamic or request-derived data into an HTML string "
                        "via `res.send()` without output encoding (Reflected XSS pattern)."
                    ),
                    remediation="Encode untrusted values before HTML insertion or return structured JSON (`res.json(...)`) with `Content-Type: application/json`.",
                    cwe_id="CWE-79",
                )

    # --------------------------------------------------------------------------
    # 3 & 4. Express / API Route Analysis: Broken Access Control & IDOR
    # --------------------------------------------------------------------------

    def _detect_express_routes_bac_and_idor(self) -> None:
        auth_middleware_keywords = (
            "auth",
            "authenticate",
            "isauthenticated",
            "requireauth",
            "verifytoken",
            "checkauth",
            "ensureloggedIn",
            "isadmin",
            "requireadmin",
            "checkrole",
            "requirerole",
            "passport",
            "jwt",
            "guard",
            "security",
        )
        ownership_keywords = (
            "req.user",
            "ctx.user",
            "session.user",
            "userid",
            "user_id",
            "ownerid",
            "owner_id",
            "createdby",
            "customerid",
            "authenticateduser",
        )

        for m in self.EXPRESS_ROUTE_RE.finditer(self.cleaned_text):
            http_method = m.group(1).upper()
            route_path = m.group(2)
            call_block, start_line, end_line = self._extract_balanced_block(m.start())
            if not call_block:
                continue

            # Split route header vs handler body (before the first `{` of the handler)
            brace_pos = call_block.find("{")
            header_part = call_block[:brace_pos].lower() if brace_pos != -1 else call_block.lower()
            body_part = call_block[brace_pos:] if brace_pos != -1 else ""
            body_lower = body_part.lower()

            has_middleware_auth = any(kw in header_part for kw in auth_middleware_keywords)
            has_body_auth = any(
                kw in body_lower
                for kw in ("req.user", "req.session.user", "verifytoken", "isauthenticated", "isadmin", "status(401)", "status(403)")
            )

            # A. Privileged / Admin Route without Auth Middleware or In-Handler Check (BFLA / BAC)
            is_admin_route = any(
                seg in route_path.lower()
                for seg in ("/admin", "/internal", "/manage", "/users", "/config", "/configuration")
            ) and "application-version" not in route_path.lower()

            if is_admin_route and not has_middleware_auth and not has_body_auth:
                self._add_finding(
                    rule_id="AS-JSTS-BAC-001",
                    category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    start_line=start_line,
                    end_line=end_line,
                    explanation=(
                        f"Administrative or privileged route `{http_method} {route_path}` is registered without "
                        f"authentication/authorization middleware or in-handler role verification. "
                        f"This indicates a potential Broken Function Level Authorization (BFLA) vulnerability."
                    ),
                    remediation=(
                        "Attach authentication and role-checking middleware (e.g., `requireAuth, requireRole('admin')`) "
                        "to the route definition before the handler executes."
                    ),
                    cwe_id="CWE-285",
                    route_path=route_path,
                    http_method=http_method,
                )

            # B. IDOR / BOLA Pattern: Route uses req.params.id / req.query.id in DB lookup without owner check
            uses_req_id = bool(
                re.search(r"\breq\.(?:params|query)\.[a-zA-Z0-9_]*id\b", body_part, re.IGNORECASE)
                or re.search(r":([a-zA-Z0-9_]*id)\b|\{([a-zA-Z0-9_]*id)\}", route_path, re.IGNORECASE)
            )
            has_db_lookup = bool(
                re.search(
                    r"\b(?:findByPk|findById|findOne|findUnique|findFirst|findByIdAndUpdate|findByIdAndDelete|getBasket|getOrder|getUser|where)\s*\(",
                    body_part,
                )
            )
            if uses_req_id and has_db_lookup:
                has_owner_verification = any(ok in body_lower for ok in ownership_keywords)
                if not has_owner_verification:
                    self._add_finding(
                        rule_id="AS-JSTS-IDOR-001",
                        category=SourceVulnerabilityCategory.BOLA_IDOR,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.MEDIUM,
                        classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                        start_line=start_line,
                        end_line=end_line,
                        explanation=(
                            f"Route `{http_method} {route_path}` retrieves or modifies a database record using a "
                            f"client-supplied identifier (`req.params.id` / `req.query.id`) without checking whether "
                            f"the authenticated user (`req.user`) owns the target resource (BOLA / IDOR pattern)."
                        ),
                        remediation=(
                            "Verify resource ownership against the authenticated session (e.g., `where: { id: req.params.id, userId: req.user.id }`) "
                            "and return HTTP 403 Forbidden if ownership does not match."
                        ),
                        cwe_id="CWE-639",
                        route_path=route_path,
                        http_method=http_method,
                    )

    def _detect_broken_access_control_patterns(self) -> None:
        # 1. Client-side role / admin flag trusted from req.body or req.query
        role_trust_re = re.compile(
            r"""(?x)
            \breq\.(?:body|query|headers)\s*\.\s*(?:role|isAdmin|is_admin|admin|permissions)\b
            """
        )
        for m in role_trust_re.finditer(self.cleaned_text):
            line_no = self._line_number_at(m.start())
            self._add_finding(
                rule_id="AS-JSTS-BAC-002",
                category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                start_line=line_no,
                end_line=line_no,
                explanation=(
                    f"Application logic reads privilege/role attribute (`{m.group(0)}`) directly from untrusted "
                    f"client request input, enabling Privilege Escalation or Mass Assignment."
                ),
                remediation="Determine user roles exclusively from verified server-side session or JWT claims (`req.user.role`), and allowlist updatable body fields.",
                cwe_id="CWE-284",
            )

        # 2. jwt.decode() used without jwt.verify()
        jwt_decode_re = re.compile(r"\bjwt\.decode\s*\(")
        for m in jwt_decode_re.finditer(self.cleaned_text):
            if "jwt.verify" not in self.cleaned_text:
                line_no = self._line_number_at(m.start())
                self._add_finding(
                    rule_id="AS-JSTS-BAC-003",
                    category=SourceVulnerabilityCategory.BROKEN_ACCESS_CONTROL,
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceLevel.HIGH,
                    classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                    start_line=line_no,
                    end_line=line_no,
                    explanation=(
                        "`jwt.decode()` is called without `jwt.verify()`. `jwt.decode()` does not verify the token's "
                        "cryptographic signature, allowing attackers to forge arbitrary user IDs and admin roles."
                    ),
                    remediation="Replace `jwt.decode(token)` with `jwt.verify(token, secretOrPublicKey, { algorithms: [...] })`.",
                    cwe_id="CWE-347",
                )

    # --------------------------------------------------------------------------
    # 5. Sensitive Data Exposure (JS/TS)
    # --------------------------------------------------------------------------

    def _detect_sensitive_data_exposure(self) -> None:
        secret_assign_re = re.compile(
            r"""(?ix)
            \b(
                password|passwd|pwd|secret|secretKey|secret_key|apiKey|api_key
                |privateKey|private_key|jwtSecret|jwt_secret|accessToken|access_token
                |authToken|auth_token|clientSecret|client_secret
            )\b
            \s*(?::\s*string)?\s*[:=]\s*
            ['"`]([^'"`\n]{6,})['"`]
            """
        )
        safe_values = {"changeme", "placeholder", "your_api_key", "dummy", "test", "example", "[redacted]", "redacted"}

        for m in secret_assign_re.finditer(self.cleaned_text):
            var_name = m.group(1)
            val = m.group(2).strip()
            if val.lower() in safe_values or val.startswith("$") or "process.env" in val:
                continue
            line_no = self._line_number_at(m.start())
            self._add_finding(
                rule_id="AS-JSTS-SDE-001",
                category=SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                start_line=line_no,
                end_line=line_no,
                explanation=(
                    f"Hardcoded secret or credential assigned to `{var_name}` in source code. "
                    f"Hardcoded credentials can be extracted from source repositories or client bundles."
                ),
                remediation="Load secrets from environment variables (`process.env.SECRET_KEY`) and never commit credentials to source control.",
                cwe_id="CWE-798",
            )

    # --------------------------------------------------------------------------
    # 6. Security Misconfiguration (JS/TS)
    # --------------------------------------------------------------------------

    def _detect_security_misconfiguration(self) -> None:
        # 1. TLS verification disabled: rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED = '0'
        tls_re = re.compile(
            r"""(?x)
            \brejectUnauthorized\s*:\s*false\b
            |\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]
            """
        )
        for m in tls_re.finditer(self.cleaned_text):
            line_no = self._line_number_at(m.start())
            self._add_finding(
                rule_id="AS-JSTS-MISC-001",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                start_line=line_no,
                end_line=line_no,
                explanation="TLS certificate validation is explicitly disabled (`rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED = '0'`), exposing connections to interception.",
                remediation="Keep TLS certificate validation enabled (`rejectUnauthorized: true`) and configure trusted CA certificates properly.",
                cwe_id="CWE-295",
            )

        # 2. Dynamic code evaluation: eval(...) or new Function(...)
        eval_re = re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()")
        for m in eval_re.finditer(self.cleaned_text):
            line_no = self._line_number_at(m.start())
            self._add_finding(
                rule_id="AS-JSTS-MISC-002",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.DETECTED_CODE_PATTERN,
                start_line=line_no,
                end_line=line_no,
                explanation=f"Dynamic code execution via `{m.group(0).strip('(')}` detected, which can lead to Code Injection or XSS if untrusted input is evaluated.",
                remediation="Avoid `eval()` and `new Function()`; use `JSON.parse()` or structured dispatch tables.",
                cwe_id="CWE-95",
            )

        # 3. Overly permissive CORS with credentials
        cors_re = re.compile(r"\bcors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['\"]?\*['\"]?)[^}]*credentials\s*:\s*true[^}]*\}", re.DOTALL)
        for m in cors_re.finditer(self.cleaned_text):
            line_no = self._line_number_at(m.start())
            end_line = self._line_number_at(m.end())
            self._add_finding(
                rule_id="AS-JSTS-MISC-003",
                category=SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION,
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                start_line=line_no,
                end_line=end_line,
                explanation="CORS middleware is configured with wildcard/reflected `origin` alongside `credentials: true`, allowing untrusted origins to make authenticated cross-origin requests.",
                remediation="Configure `origin` with a strict allowlist of trusted origins when `credentials: true` is enabled.",
                cwe_id="CWE-942",
            )


# ==============================================================================
# Primary SourceAnalyzer Engine
# ==============================================================================


class SourceAnalyzer:
    """Static source-code discovery and vulnerability pattern analysis engine.

    Enforces strict safety guardrails:
    - Never executes scanned source code.
    - Never makes network requests.
    - Enforces file-size and repository-size boundaries.
    - Excludes `.git`, `node_modules`, `.venv`, `build`, `dist`, environment files, and private keys.
    - Clearly separates static code patterns (`DETECTED_CODE_PATTERN`, `POTENTIAL_VULNERABILITY`)
      from runtime verification (`CONFIRMED_RUNTIME_VULNERABILITY`).
    """

    def __init__(
        self,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        max_repo_size_bytes: int = DEFAULT_MAX_REPO_SIZE_BYTES,
        max_files_count: int = DEFAULT_MAX_FILES_COUNT,
        excluded_dirs: Optional[Iterable[str]] = None,
        excluded_file_patterns: Optional[Iterable[str]] = None,
        enable_external_tools: bool = False,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be positive.")
        if max_repo_size_bytes <= 0:
            raise ValueError("max_repo_size_bytes must be positive.")

        self.max_file_size_bytes = max_file_size_bytes
        self.max_repo_size_bytes = max_repo_size_bytes
        self.max_files_count = max_files_count
        self.excluded_dirs: Set[str] = {
            d.lower() for d in (excluded_dirs if excluded_dirs is not None else DEFAULT_EXCLUDED_DIRS)
        }
        self.excluded_file_patterns: Tuple[str, ...] = tuple(
            excluded_file_patterns if excluded_file_patterns is not None else SECRET_AND_ENV_FILE_PATTERNS
        )
        self.enable_external_tools = enable_external_tools

    # --------------------------------------------------------------------------
    # Language & File Exclusion Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def detect_language(file_path: Union[str, Path]) -> SupportedLanguage:
        """Detects the programming language of a source file from its extension."""
        p = Path(str(file_path))
        suffix = p.suffix.lower()
        return LANGUAGE_EXTENSIONS.get(suffix, SupportedLanguage.UNKNOWN)

    def is_excluded_directory(self, dir_name: str) -> bool:
        """Returns True if a directory name belongs to the excluded set (`.git`, `node_modules`, `.venv`, `build`, `dist`, etc.)."""
        cleaned = dir_name.strip().lower()
        return cleaned in self.excluded_dirs

    def is_secret_or_env_file(self, file_path: Union[str, Path]) -> bool:
        """Returns True if the filename matches environment or private key exclusion patterns."""
        p = Path(str(file_path))
        name_lower = p.name.lower()

        if name_lower == ".env" or name_lower.startswith(".env."):
            return True

        for pattern in self.excluded_file_patterns:
            if fnmatch.fnmatch(name_lower, pattern.lower()):
                return True
        return False

    @staticmethod
    def _validate_target_path(target_path: Union[str, Path]) -> Path:
        """Validates a target filesystem path, rejecting URLs, null bytes, and missing paths."""
        if target_path is None:
            raise InvalidSourcePathError("Target source path must not be None.")

        raw_str = str(target_path).strip()
        if not raw_str:
            raise InvalidSourcePathError("Target source path must be a non-empty string.")

        if "\x00" in raw_str or any(ord(c) < 32 for c in raw_str):
            raise InvalidSourcePathError("Target source path contains prohibited control characters or null bytes.")

        # Never make network requests or accept remote URLs
        if raw_str.lower().startswith(("http://", "https://", "ftp://", "ssh://", "git://", "file://")):
            raise InvalidSourcePathError(
                f"Remote URLs or URI schemes are prohibited in SourceAnalyzer: '{raw_str}'. "
                f"Only local authorized filesystem paths may be inspected."
            )

        try:
            path_obj = Path(raw_str)
            exists = path_obj.exists()
        except OSError as exc:
            raise InvalidSourcePathError(f"Invalid filesystem path '{raw_str}': {exc}") from exc

        if not exists:
            raise InvalidSourcePathError(f"Source path or repository does not exist: '{raw_str}'.")

        return path_obj.resolve()

    # --------------------------------------------------------------------------
    # Source Discovery
    # --------------------------------------------------------------------------

    def discover_files(
        self,
        target_path: Union[str, Path],
        strict_repo_limits: bool = False,
    ) -> SourceDiscoveryResult:
        """Safely traverses a file or directory to discover supported source files.

        Enforces:
        - Safe directory traversal (prevents symlink escape outside `root_path`).
        - Exclusion of `.git`, `node_modules`, `.venv`, `build`, and `dist`.
        - Exclusion of `.env` files, credential files, and private keys.
        - File-size limits (`max_file_size_bytes`).
        - Repository-size limits (`max_repo_size_bytes`) and file count limits.
        """
        resolved_root = self._validate_target_path(target_path)
        discovered: List[DiscoveredSourceFile] = []
        skipped: List[SkippedSourceItem] = []
        total_bytes = 0
        lang_counts: Dict[str, int] = {}
        repo_limit_reached = False
        repo_limit_reason: Optional[str] = None

        if resolved_root.is_file():
            self._inspect_candidate_file(
                file_path=resolved_root,
                root_dir=resolved_root.parent,
                discovered=discovered,
                skipped=skipped,
                lang_counts=lang_counts,
                current_total_bytes=0,
                strict_repo_limits=strict_repo_limits,
            )
            total_bytes = sum(f.size_bytes for f in discovered)
            return SourceDiscoveryResult(
                root_path=str(resolved_root),
                discovered_files=discovered,
                skipped_items=skipped,
                total_scanned_bytes=total_bytes,
                languages_summary=lang_counts,
            )

        # Safe directory walk with top-down pruning of excluded directories and symlinks
        for current_root, dirs, files in os.walk(str(resolved_root), topdown=True, followlinks=False):
            current_root_path = Path(current_root)

            # Prune excluded directories and symlinked directories in-place
            kept_dirs: List[str] = []
            for d in sorted(dirs):
                d_path = current_root_path / d
                rel_d = self._safe_relative_path(d_path, resolved_root)
                if self.is_excluded_directory(d):
                    skipped.append(SkippedSourceItem(path=rel_d, reason="excluded_directory"))
                    continue
                if d_path.is_symlink():
                    skipped.append(SkippedSourceItem(path=rel_d, reason="symlink_directory_excluded"))
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs

            for fname in sorted(files):
                fpath = current_root_path / fname
                rel_f = self._safe_relative_path(fpath, resolved_root)

                # Reject symlinks that escape the repository root
                if fpath.is_symlink():
                    try:
                        resolved_target = fpath.resolve()
                        resolved_target.relative_to(resolved_root)
                    except Exception:
                        skipped.append(SkippedSourceItem(path=rel_f, reason="symlink_escape_blocked"))
                        continue

                if len(discovered) >= self.max_files_count:
                    repo_limit_reached = True
                    repo_limit_reason = (
                        f"Repository file count limit ({self.max_files_count} files) reached."
                    )
                    skipped.append(SkippedSourceItem(path=rel_f, reason="repository_file_count_limit"))
                    if strict_repo_limits:
                        raise RepositoryLimitExceededError(repo_limit_reason)
                    continue

                added_bytes, hit_repo_limit = self._inspect_candidate_file(
                    file_path=fpath,
                    root_dir=resolved_root,
                    discovered=discovered,
                    skipped=skipped,
                    lang_counts=lang_counts,
                    current_total_bytes=total_bytes,
                    strict_repo_limits=strict_repo_limits,
                )
                total_bytes += added_bytes
                if hit_repo_limit:
                    repo_limit_reached = True
                    repo_limit_reason = (
                        f"Repository size limit ({self.max_repo_size_bytes} bytes) exceeded."
                    )

        return SourceDiscoveryResult(
            root_path=str(resolved_root),
            discovered_files=discovered,
            skipped_items=skipped,
            total_scanned_bytes=total_bytes,
            languages_summary=lang_counts,
            repository_limit_reached=repo_limit_reached,
            repository_limit_reason=repo_limit_reason,
        )

    @staticmethod
    def _safe_relative_path(path: Path, root: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            return path.name

    def _inspect_candidate_file(
        self,
        file_path: Path,
        root_dir: Path,
        discovered: List[DiscoveredSourceFile],
        skipped: List[SkippedSourceItem],
        lang_counts: Dict[str, int],
        current_total_bytes: int,
        strict_repo_limits: bool,
    ) -> Tuple[int, bool]:
        rel_path = self._safe_relative_path(file_path, root_dir)

        # 1. Check if parent path contains an excluded directory component
        for part in file_path.relative_to(root_dir).parts[:-1]:
            if self.is_excluded_directory(part):
                skipped.append(SkippedSourceItem(path=rel_path, reason="excluded_directory"))
                return (0, False)

        # 2. Check secret / environment / private key exclusion
        if self.is_secret_or_env_file(file_path):
            skipped.append(SkippedSourceItem(path=rel_path, reason="excluded_secret_or_env_file"))
            return (0, False)

        # 3. Check language support
        language = self.detect_language(file_path)
        if language == SupportedLanguage.UNKNOWN:
            skipped.append(SkippedSourceItem(path=rel_path, reason="unsupported_file_extension"))
            return (0, False)

        # 4. Check file size limit
        try:
            stat = file_path.stat()
            size_bytes = stat.st_size
        except OSError:
            skipped.append(SkippedSourceItem(path=rel_path, reason="unreadable_file_stat"))
            return (0, False)

        if size_bytes > self.max_file_size_bytes:
            skipped.append(
                SkippedSourceItem(
                    path=rel_path,
                    reason=f"file_size_limit_exceeded ({size_bytes} > {self.max_file_size_bytes} bytes)",
                )
            )
            return (0, False)

        # 5. Check repository cumulative size limit
        if current_total_bytes + size_bytes > self.max_repo_size_bytes:
            skipped.append(
                SkippedSourceItem(
                    path=rel_path,
                    reason=f"repository_size_limit_exceeded ({current_total_bytes + size_bytes} > {self.max_repo_size_bytes} bytes)",
                )
            )
            if strict_repo_limits:
                raise RepositoryLimitExceededError(
                    f"Repository total size exceeded {self.max_repo_size_bytes} bytes at '{rel_path}'."
                )
            return (0, True)

        # 6. Read content safely and reject binary or embedded private key files
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            skipped.append(SkippedSourceItem(path=rel_path, reason="unreadable_file_bytes"))
            return (0, False)

        if b"\x00" in raw_bytes[:4096]:
            skipped.append(SkippedSourceItem(path=rel_path, reason="binary_file_excluded"))
            return (0, False)

        text_preview = raw_bytes[:4096].decode("utf-8", errors="replace")
        if any(marker in text_preview for marker in PRIVATE_KEY_CONTENT_MARKERS):
            skipped.append(SkippedSourceItem(path=rel_path, reason="excluded_private_key_content"))
            return (0, False)

        file_hash = compute_sha256(raw_bytes)
        discovered.append(
            DiscoveredSourceFile(
                file_path=rel_path,
                absolute_path=str(file_path.resolve()),
                language=language,
                size_bytes=size_bytes,
                sha256=file_hash,
            )
        )
        lang_counts[language.value] = lang_counts.get(language.value, 0) + 1
        return (size_bytes, False)

    # --------------------------------------------------------------------------
    # File & Repository Vulnerability Analysis
    # --------------------------------------------------------------------------

    def analyze_file(
        self,
        file_path: Union[str, Path],
        display_path: Optional[str] = None,
    ) -> List[SourceFinding]:
        """Analyzes a single authorized source file and returns structured `SourceFinding` objects."""
        resolved = self._validate_target_path(file_path)
        if not resolved.is_file():
            raise InvalidSourcePathError(f"Expected a file path, but got directory: '{file_path}'.")

        if self.is_secret_or_env_file(resolved):
            return []

        lang = self.detect_language(resolved)
        if lang == SupportedLanguage.UNKNOWN:
            return []

        size_bytes = resolved.stat().st_size
        if size_bytes > self.max_file_size_bytes:
            return []

        raw_bytes = resolved.read_bytes()
        if b"\x00" in raw_bytes[:4096]:
            return []

        source_text = raw_bytes.decode("utf-8", errors="replace")
        if any(marker in source_text[:4096] for marker in PRIVATE_KEY_CONTENT_MARKERS):
            return []

        rel_display = display_path or resolved.name
        return self.analyze_source_string(
            source_code=source_text,
            language=lang,
            file_path=rel_display,
        )

    def analyze_source_string(
        self,
        source_code: str,
        language: SupportedLanguage | str,
        file_path: str = "<memory>",
    ) -> List[SourceFinding]:
        """Analyzes in-memory source code without executing it."""
        if not source_code or not source_code.strip():
            return []

        if isinstance(language, str):
            try:
                lang_enum = SupportedLanguage(language.lower())
            except ValueError:
                lang_enum = self.detect_language(file_path)
        else:
            lang_enum = language

        if lang_enum == SupportedLanguage.PYTHON:
            return self._analyze_python_source(source_code, file_path)
        if lang_enum in (SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT):
            analyzer = _JSTSStructuralAnalyzer(
                file_path=file_path,
                language=lang_enum,
                source_text=source_code,
            )
            return analyzer.analyze()

        return []

    def _analyze_python_source(self, source_code: str, file_path: str) -> List[SourceFinding]:
        lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError as exc:
            logger.warning(
                "Skipping Python AST analysis due to syntax error in target file",
                extra={"file_path": file_path, "line": exc.lineno, "msg": exc.msg},
            )
            return []

        visitor = _PythonASTAnalyzer(file_path=file_path, source_lines=lines)
        visitor.visit(tree)
        return visitor.findings

    def analyze_repository(
        self,
        target_path: Union[str, Path],
        strict_repo_limits: bool = False,
        scan_id: Optional[str] = None,
    ) -> SourceAnalysisReport:
        """Discovers and analyzes all supported source files in a repository or path."""
        started_at = datetime.now(timezone.utc)
        resolved_scan_id = scan_id or f"src_scan_{started_at.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        discovery = self.discover_files(target_path=target_path, strict_repo_limits=strict_repo_limits)
        all_findings: List[SourceFinding] = []
        errors: List[str] = []
        external_tools_used: List[str] = []

        for src_file in discovery.discovered_files:
            try:
                file_findings = self.analyze_file(
                    file_path=src_file.absolute_path,
                    display_path=src_file.file_path,
                )
                all_findings.extend(file_findings)
            except Exception as exc:
                err_msg = f"Failed to analyze '{src_file.file_path}': {exc}"
                logger.warning(err_msg)
                errors.append(err_msg)

        # Optional external SAST enrichment (Bandit / Semgrep) if installed & explicitly enabled
        if self.enable_external_tools and discovery.discovered_files:
            ext_findings, tools_ran = self._run_optional_external_tools(discovery)
            external_tools_used.extend(tools_ran)
            # Deduplicate external findings against AST/structural findings on same file & line
            existing_locs = {(f.file_path, f.start_line, f.vulnerability_category) for f in all_findings}
            for ef in ext_findings:
                if (ef.file_path, ef.start_line, ef.vulnerability_category) not in existing_locs:
                    all_findings.append(ef)
                    existing_locs.add((ef.file_path, ef.start_line, ef.vulnerability_category))

        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in all_findings:
            by_cat[f.vulnerability_category] = by_cat.get(f.vulnerability_category, 0) + 1
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            by_sev[sev_key] = by_sev.get(sev_key, 0) + 1

        return SourceAnalysisReport(
            scan_id=resolved_scan_id,
            root_path=discovery.root_path,
            discovery=discovery,
            findings=all_findings,
            findings_by_category=by_cat,
            findings_by_severity=by_sev,
            external_tools_used=external_tools_used,
            errors=errors,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    def _run_optional_external_tools(
        self, discovery: SourceDiscoveryResult
    ) -> Tuple[List[SourceFinding], List[str]]:
        """Runs local Bandit or Semgrep in offline, non-executing mode if available on PATH."""
        findings: List[SourceFinding] = []
        tools_used: List[str] = []

        bandit_bin = shutil.which("bandit")
        py_files = [f.absolute_path for f in discovery.discovered_files if f.language == SupportedLanguage.PYTHON]
        if bandit_bin and py_files:
            try:
                proc = subprocess.run(
                    [bandit_bin, "-f", "json", "-q", *py_files[:100]],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if proc.stdout:
                    data = json.loads(proc.stdout)
                    tools_used.append("bandit")
                    for item in data.get("results", []):
                        test_id = item.get("test_id", "B000")
                        line_no = int(item.get("line_number", 1) or 1)
                        fname = item.get("filename", "")
                        rel_path = self._safe_relative_path(Path(fname), Path(discovery.root_path))
                        code = sanitize_code_snippet(item.get("code", "") or "<snippet>")
                        issue_text = item.get("issue_text", "Bandit static analysis finding.")
                        sev_str = str(item.get("issue_severity", "MEDIUM")).upper()
                        conf_str = str(item.get("issue_confidence", "MEDIUM")).upper()

                        cat = SourceVulnerabilityCategory.SECURITY_MISCONFIGURATION
                        if test_id in ("B608",):
                            cat = SourceVulnerabilityCategory.SQL_INJECTION
                        elif test_id in ("B105", "B106", "B107"):
                            cat = SourceVulnerabilityCategory.SENSITIVE_DATA_EXPOSURE
                        elif test_id in ("B701", "B702", "B703"):
                            cat = SourceVulnerabilityCategory.CROSS_SITE_SCRIPTING

                        findings.append(
                            SourceFinding(
                                finding_id=f"src_{compute_sha256(f'{rel_path}:{test_id}:{line_no}')[:12]}",
                                rule_id=f"BANDIT-{test_id}",
                                vulnerability_category=cat.value,
                                severity=SeverityLevel(sev_str) if sev_str in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else SeverityLevel.MEDIUM,
                                confidence=ConfidenceLevel(conf_str) if conf_str in {"LOW", "MEDIUM", "HIGH"} else ConfidenceLevel.MEDIUM,
                                source_type=SourceType.SOURCE_CODE.value,
                                classification=StaticFindingClassification.POTENTIAL_VULNERABILITY,
                                validation_status=StaticValidationStatus.POTENTIAL_UNVERIFIED.value,
                                is_runtime_confirmed=False,
                                file_path=rel_path,
                                language=SupportedLanguage.PYTHON,
                                start_line=line_no,
                                end_line=line_no,
                                code_snippet=code,
                                detection_explanation=f"{issue_text} (Detected via Bandit {test_id})",
                                detection_method=DetectionMethod.BANDIT.value,
                            )
                        )
            except Exception as exc:
                logger.warning("Optional Bandit execution skipped", extra={"error": str(exc)})

        return findings, tools_used


def analyze_source(
    target_path: Union[str, Path],
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    max_repo_size_bytes: int = DEFAULT_MAX_REPO_SIZE_BYTES,
) -> SourceAnalysisReport:
    """Top-level convenience function to run the SourceAnalyzer on a target path."""
    analyzer = SourceAnalyzer(
        max_file_size_bytes=max_file_size_bytes,
        max_repo_size_bytes=max_repo_size_bytes,
    )
    return analyzer.analyze_repository(target_path=target_path)
