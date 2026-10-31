"""Vulnerability-to-Code Mapping Engine (AuthScope Phase 5.2).

Identifies and verifies the source-code location in the target application repository
associated with security findings discovered via static analysis or runtime differential testing.

Capabilities:
1. Static Analysis Mapping:
   - Validates reported source file existence on disk (with path traversal protection).
   - Validates line number boundaries against actual file length.
   - Verifies code snippet authenticity against actual file content (never invents lines/snippets).
   - Verifies enclosing function / method names via AST / syntax parsing.
2. Runtime Differential Finding Mapping:
   - Correlates runtime HTTP endpoints (e.g. /rest/basket/1) with backend route declarations
     (e.g. Express / FastAPI / Flask route handlers).
   - Distinguishes backend route handlers from client-side callers (never maps frontend fetch).
   - Detects database operations and presence/absence of authorization checks.
   - Handles multi-candidate route ambiguity cleanly without guessing (returns CANDIDATE status).
   - Reports clear UNAVAILABLE status when source repository or file is inaccessible.
"""

from __future__ import annotations

import ast
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field

from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Mapping Status & Confidence Enums
# ==============================================================================


class MappingStatus(str, Enum):
    """Status classification for vulnerability code mapping."""
    EXACT = "EXACT"              # Single, fully verified source location backed by actual source code
    CANDIDATE = "CANDIDATE"      # Multiple plausible candidate locations; requires review (no guessing)
    UNAVAILABLE = "UNAVAILABLE"  # Source code unavailable on disk or endpoint unmapped
    INVALID = "INVALID"          # Location provided fails verification (nonexistent file, bad line numbers, mismatch)


class MappingConfidence(str, Enum):
    """Confidence level of code mapping."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# ==============================================================================
# Source Location & Result Schemas
# ==============================================================================


class SourceLocation(BaseModel):
    """Detailed source-code location and context associated with a security finding."""
    repository_name: Optional[str] = Field(None, description="Repository identifier or directory name")
    file_path: str = Field(..., description="Relative or normalized file path")
    function_name: Optional[str] = Field(None, description="Function, method, or handler name")
    start_line: int = Field(..., ge=1, description="1-indexed starting line number")
    end_line: int = Field(..., ge=1, description="1-indexed ending line number")
    code_snippet: str = Field(..., description="Actual source code snippet extracted from disk")
    related_endpoint: Optional[str] = Field(None, description="Correlated HTTP endpoint path")
    route_handler: Optional[str] = Field(None, description="Name or identifier of the route handler")
    database_operation: Optional[str] = Field(None, description="Detected database query or ORM call")
    authorization_check: Optional[str] = Field(None, description="Detected authorization logic or guard")
    confidence: MappingConfidence = Field(default=MappingConfidence.HIGH, description="Mapping confidence")


class CodeMappingResult(BaseModel):
    """Output contract for CodeMapper evaluations."""
    status: MappingStatus = Field(..., description="Overall mapping outcome status")
    finding_id: str = Field(..., description="Associated finding unique identifier")
    location: Optional[SourceLocation] = Field(None, description="Verified exact source location if status is EXACT")
    candidates: List[SourceLocation] = Field(default_factory=list, description="Candidate locations if status is CANDIDATE")
    message: Optional[str] = Field(None, description="Explanatory context or failure reason")
    verified: bool = Field(default=False, description="Whether location was verified against actual disk content")


# ==============================================================================
# Regex Patterns for Route & Query Detection
# ==============================================================================

# Directories to ignore when scanning for backend route handlers
IGNORED_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".pytest_cache", "test", "tests", "__tests__", "coverage",
    "docs", "public", "static", "frontend", "client", "ui"
}

# Frontend file patterns that should NOT be considered backend handlers
FRONTEND_FILE_PATTERNS = [
    r"[\\/]frontend[\\/]",
    r"[\\/]client[\\/]",
    r"[\\/]ui[\\/]",
    r"\.component\.[jt]sx?$",
    r"\.view\.[jt]sx?$",
]

# Express / Node route definition regex:
# Matches: app.get('/path', ...), router.post('/path', ...), etc.
EXPRESS_ROUTE_REGEX = re.compile(
    r"""(?:app|router|server)\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(.*)""",
    re.IGNORECASE
)

# Express router mount regex:
# Matches: app.use('/prefix', router)
EXPRESS_USE_REGEX = re.compile(
    r"""(?:app|server)\.use\s*\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z0-9_$]+)""",
    re.IGNORECASE
)

# Database query patterns in source code
DB_OPERATION_PATTERNS = [
    re.compile(r"""(?:models\.[a-zA-Z0-9_]+\.(findOne|findByPk|findAll|create|update|destroy|count))""", re.IGNORECASE),
    re.compile(r"""(?:db\.(query|run|all|get|exec|execute))""", re.IGNORECASE),
    re.compile(r"""\b(SELECT\s+[\s\S]+?\s+FROM|INSERT\s+INTO|UPDATE\s+[a-zA-Z0-9_]+\s+SET|DELETE\s+FROM)\b""", re.IGNORECASE),
    re.compile(r"""(?:\.filter\(|\.get\(|\.create\(|\.all\(|\.save\(\))"""),
]

# Authorization check patterns in source code
AUTH_CHECK_PATTERNS = [
    re.compile(r"""(?:req\.user|req\.auth|req\.session\.user|authenticatedUser)""", re.IGNORECASE),
    re.compile(r"""(?:isAuthorized|checkRole|verifyToken|hasRole|hasPermission|checkOwnership)""", re.IGNORECASE),
    re.compile(r"""(?:jwt\.verify|passport\.authenticate|security\.isAuthorized)""", re.IGNORECASE),
    re.compile(r"""(?:Depends\([a-zA-Z0-9_]*auth|current_user|is_authenticated|has_perm)""", re.IGNORECASE),
]


# ==============================================================================
# Helper Functions
# ==============================================================================


def normalize_path_segments(path_str: str) -> List[str]:
    """Splits a URL path into lowercase, trimmed segments."""
    cleaned = path_str.split("?")[0].strip().strip("/")
    return [seg.lower() for seg in cleaned.split("/") if seg]


def route_matches_endpoint(
    route_path: str,
    endpoint_path: str,
    file_path: Optional[Path] = None
) -> bool:
    """Checks if a route template matches an endpoint.

    Handles:
    1. Full exact path segment match:
       e.g. /api/Users == /api/Users
       e.g. /api/v1/orders/{order_id} == /api/v1/orders/42
    2. Sub-router relative path match (Express mounted routes):
       e.g. route /:id in routes/basket.js matches /rest/basket/1
       e.g. route /:id/items in routes/basket.js matches /rest/basket/1/items
    """
    route_segs = normalize_path_segments(route_path)
    endpoint_segs = normalize_path_segments(endpoint_path)

    if not route_segs or not endpoint_segs:
        return False

    # 1. Direct segment-by-segment match
    if len(route_segs) == len(endpoint_segs):
        match = True
        for r_seg, e_seg in zip(route_segs, endpoint_segs):
            if r_seg.startswith(":") or (r_seg.startswith("{") and r_seg.endswith("}")) or r_seg.startswith("<"):
                continue
            if e_seg.startswith(":") or (e_seg.startswith("{") and e_seg.endswith("}")) or e_seg.startswith("<"):
                continue
            if r_seg != e_seg:
                match = False
                break
        if match:
            return True

    # 2. Sub-route relative match (e.g. route /:id mounted on /rest/basket)
    if len(route_segs) < len(endpoint_segs):
        tail_endpoint = endpoint_segs[-len(route_segs):]
        tail_match = True
        for r_seg, e_seg in zip(route_segs, tail_endpoint):
            if r_seg.startswith(":") or (r_seg.startswith("{") and r_seg.endswith("}")) or r_seg.startswith("<"):
                continue
            if e_seg.startswith(":") or (e_seg.startswith("{") and e_seg.endswith("}")) or e_seg.startswith("<"):
                continue
            if r_seg != e_seg:
                tail_match = False
                break

        if tail_match and file_path:
            remaining_prefix = endpoint_segs[:-len(route_segs)]
            file_stem = file_path.stem.lower()
            file_parts = [p.lower() for p in file_path.parts]
            # Match if file stem or parent directories correlate with prefix segments
            if file_stem in remaining_prefix or any(p in remaining_prefix for p in file_parts):
                return True

    return False


def detect_database_operation(code_block: str) -> Optional[str]:
    """Inspects a code snippet for database queries or ORM operations."""
    for pattern in DB_OPERATION_PATTERNS:
        match = pattern.search(code_block)
        if match:
            return match.group(0).strip()
    return None


def detect_authorization_check(code_block: str) -> Optional[str]:
    """Inspects a code snippet for authorization logic or guards."""
    for pattern in AUTH_CHECK_PATTERNS:
        match = pattern.search(code_block)
        if match:
            return match.group(0).strip()
    return None


# ==============================================================================
# CodeMapper Core Engine
# ==============================================================================


class CodeMapper:
    """Maps security findings to verified source-code locations."""

    def __init__(
        self,
        repo_root: Optional[Union[str, Path]] = None,
        repository_name: Optional[str] = None
    ) -> None:
        """Initializes the CodeMapper.

        Args:
            repo_root: Absolute or relative path to the target repository root directory.
            repository_name: Logical repository name (defaults to directory basename if provided).
        """
        self.repo_root: Optional[Path] = Path(repo_root).resolve() if repo_root else None
        if self.repo_root and not self.repo_root.exists():
            logger.warning("Configured repo_root does not exist on disk", extra={"repo_root": str(self.repo_root)})

        self.repository_name: Optional[str] = repository_name or (self.repo_root.name if self.repo_root else None)

    # -------------------------------------------------------------------------
    # Public Entry Point
    # -------------------------------------------------------------------------

    def map_finding(
        self,
        finding: Any,
        static_hint: Optional[Dict[str, Any]] = None,
        route_hint: Optional[Dict[str, Any]] = None
    ) -> CodeMappingResult:
        """Maps a finding to source code, automatically selecting static or runtime strategy.

        Args:
            finding: FindingRecord, dictionary, or finding object.
            static_hint: Optional dictionary with static analysis location data (from SourceAnalyzer).
            route_hint: Optional route correlation metadata.

        Returns:
            CodeMappingResult with EXACT, CANDIDATE, UNAVAILABLE, or INVALID status.
        """
        finding_id = self._extract_finding_id(finding)

        # Check for static location hints
        hint = static_hint or self._extract_static_hint(finding)
        if hint and (hint.get("file_path") or hint.get("file")):
            return self.map_static_finding(finding, static_hint=hint)

        # Fallback to runtime endpoint correlation
        return self.map_runtime_finding(finding, route_hint=route_hint)

    # -------------------------------------------------------------------------
    # Static Analysis Mapping
    # -------------------------------------------------------------------------

    def map_static_finding(
        self,
        finding: Any,
        static_hint: Optional[Dict[str, Any]] = None
    ) -> CodeMappingResult:
        """Verifies and maps a static analysis finding location provided by SourceAnalyzer.

        Enforces:
        - File exists on disk.
        - Line numbers are within valid boundaries.
        - Code snippet matches the actual file content (never invents lines/snippets).
        - Function name matches if provided.

        Args:
            finding: FindingRecord or dictionary.
            static_hint: Optional dictionary with location data.

        Returns:
            CodeMappingResult with EXACT or INVALID status.
        """
        finding_id = self._extract_finding_id(finding)
        hint = static_hint or self._extract_static_hint(finding) or {}

        raw_file_path = hint.get("file_path") or hint.get("file")
        if not raw_file_path:
            return CodeMappingResult(
                status=MappingStatus.UNAVAILABLE,
                finding_id=finding_id,
                message="Source code location unavailable. No file path specified in finding."
            )

        # Resolve path and verify safety (path traversal prevention)
        resolved_file, error_msg = self._resolve_safe_path(str(raw_file_path))
        if error_msg:
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message=error_msg
            )
        assert resolved_file is not None

        if not resolved_file.is_file():
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message=f"Source file '{raw_file_path}' does not exist on disk."
            )

        # Read file contents
        try:
            with open(resolved_file, "r", encoding="utf-8", errors="replace") as f:
                file_lines = f.readlines()
        except Exception as e:
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message=f"Failed to read source file '{raw_file_path}': {e}"
            )

        total_lines = len(file_lines)

        # Extract and validate line numbers (safely handle 0 as non-None)
        start_line = hint.get("start_line")
        if start_line is None:
            start_line = hint.get("line_start")
        if start_line is None:
            start_line = hint.get("line")

        end_line = hint.get("end_line")
        if end_line is None:
            end_line = hint.get("line_end")
        if end_line is None:
            end_line = start_line

        if start_line is None:
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message="Missing starting line number in static location data."
            )

        try:
            start_line_int = int(start_line)
            end_line_int = int(end_line)
        except (ValueError, TypeError):
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message=f"Line numbers must be integers, got start_line={start_line}, end_line={end_line}."
            )

        if start_line_int < 1 or end_line_int < start_line_int or end_line_int > total_lines:
            return CodeMappingResult(
                status=MappingStatus.INVALID,
                finding_id=finding_id,
                message=(
                    f"Invalid line range [{start_line_int}, {end_line_int}] for file '{raw_file_path}' "
                    f"with {total_lines} total lines."
                )
            )

        # Extract actual lines from the file
        actual_lines = file_lines[start_line_int - 1 : end_line_int]
        actual_snippet = "".join(actual_lines)

        # Verify provided snippet against actual lines
        provided_snippet = hint.get("code_snippet") or hint.get("snippet")
        if provided_snippet:
            clean_provided = self._normalize_whitespace(str(provided_snippet))
            clean_actual = self._normalize_whitespace(actual_snippet)

            if clean_provided not in clean_actual and clean_actual not in clean_provided:
                return CodeMappingResult(
                    status=MappingStatus.INVALID,
                    finding_id=finding_id,
                    message=(
                        f"Code snippet mismatch at {raw_file_path}:{start_line_int}-{end_line_int}. "
                        "The provided snippet does not match actual file contents."
                    )
                )

        # Verify function name if provided
        function_name = hint.get("function_name") or hint.get("function") or hint.get("method_name")
        if function_name and resolved_file.suffix == ".py":
            func_ok = self._verify_python_function(resolved_file, function_name, start_line_int, end_line_int)
            if not func_ok:
                return CodeMappingResult(
                    status=MappingStatus.INVALID,
                    finding_id=finding_id,
                    message=f"Function '{function_name}' was not found at specified lines in '{raw_file_path}'."
                )

        # Context detection (database operations & authorization checks)
        db_op = hint.get("database_operation") or detect_database_operation(actual_snippet)
        auth_check = hint.get("authorization_check") or detect_authorization_check(actual_snippet)

        location = SourceLocation(
            repository_name=hint.get("repository_name") or self.repository_name,
            file_path=self._relativize_path(resolved_file),
            function_name=function_name,
            start_line=start_line_int,
            end_line=end_line_int,
            code_snippet=actual_snippet.rstrip(),
            related_endpoint=hint.get("related_endpoint") or hint.get("endpoint"),
            route_handler=hint.get("route_handler") or function_name,
            database_operation=db_op,
            authorization_check=auth_check,
            confidence=MappingConfidence.HIGH
        )

        return CodeMappingResult(
            status=MappingStatus.EXACT,
            finding_id=finding_id,
            location=location,
            verified=True,
            message=f"Verified exact source location at {location.file_path}:{start_line_int}-{end_line_int}."
        )

    # -------------------------------------------------------------------------
    # Runtime Finding Mapping
    # -------------------------------------------------------------------------

    def map_runtime_finding(
        self,
        finding: Any,
        route_hint: Optional[Dict[str, Any]] = None
    ) -> CodeMappingResult:
        """Correlates a runtime differential finding with its backend route handler.

        Enforces:
        - Returns UNAVAILABLE if repository is not configured or missing.
        - Excludes frontend / client-side files (never attributes vulnerability to UI caller).
        - Returns CANDIDATE when multiple route handler candidates match (no guessing).
        - Returns EXACT when a unique backend route handler is identified and verified on disk.

        Args:
            finding: FindingRecord or dictionary.
            route_hint: Optional dictionary with route hints.

        Returns:
            CodeMappingResult.
        """
        finding_id = self._extract_finding_id(finding)
        endpoint = self._extract_endpoint(finding)
        method = self._extract_http_method(finding)

        # Unavailable source code handling
        if not self.repo_root or not self.repo_root.is_dir():
            return CodeMappingResult(
                status=MappingStatus.UNAVAILABLE,
                finding_id=finding_id,
                message="Source code location unavailable. Runtime evidence is available."
            )

        if not endpoint:
            return CodeMappingResult(
                status=MappingStatus.UNAVAILABLE,
                finding_id=finding_id,
                message="Source code location unavailable. Runtime evidence is available."
            )

        # Scan repository for candidate backend handlers
        candidates = self._scan_repo_for_route_handlers(endpoint=endpoint, method=method)

        if not candidates:
            return CodeMappingResult(
                status=MappingStatus.UNAVAILABLE,
                finding_id=finding_id,
                message="Source code location unavailable. Runtime evidence is available."
            )

        if len(candidates) == 1:
            # Unique exact match found
            exact_location = candidates[0]
            exact_location.confidence = MappingConfidence.HIGH
            return CodeMappingResult(
                status=MappingStatus.EXACT,
                finding_id=finding_id,
                location=exact_location,
                verified=True,
                message=f"Correlated unique route handler at {exact_location.file_path}:{exact_location.start_line}."
            )

        # Multiple candidates found -> DO NOT GUESS
        return CodeMappingResult(
            status=MappingStatus.CANDIDATE,
            finding_id=finding_id,
            candidates=candidates,
            verified=False,
            message=(
                f"Found {len(candidates)} candidate route handlers for endpoint '{endpoint}'. "
                "Manual review required to confirm specific handler."
            )
        )

    # -------------------------------------------------------------------------
    # Route Scanner & Parser Internals
    # -------------------------------------------------------------------------

    def _scan_repo_for_route_handlers(self, endpoint: str, method: str) -> List[SourceLocation]:
        """Scans the repository for backend route declarations matching endpoint & method."""
        if not self.repo_root or not self.repo_root.is_dir():
            return []

        candidates: List[SourceLocation] = []

        for root, dirs, files in os.walk(self.repo_root):
            # Prune ignored and frontend directories in-place
            dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]

            # Skip frontend directory trees entirely
            rel_root = os.path.relpath(root, self.repo_root)
            if any(re.search(pat, f"/{rel_root}/", re.IGNORECASE) for pat in FRONTEND_FILE_PATTERNS):
                continue

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in (".js", ".ts", ".py"):
                    continue

                full_path = Path(root) / file
                file_rel_path = self._relativize_path(full_path)

                if ext in (".js", ".ts"):
                    matches = self._find_js_route_handlers(full_path, file_rel_path, endpoint, method)
                    candidates.extend(matches)
                elif ext == ".py":
                    matches = self._find_py_route_handlers(full_path, file_rel_path, endpoint, method)
                    candidates.extend(matches)

        return candidates

    def _find_js_route_handlers(
        self,
        file_path: Path,
        rel_path: str,
        endpoint: str,
        method: str
    ) -> List[SourceLocation]:
        """Finds Express / Node route handlers in a JS/TS file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        results: List[SourceLocation] = []
        method_upper = method.upper()

        for idx, line in enumerate(lines, start=1):
            match = EXPRESS_ROUTE_REGEX.search(line)
            if not match:
                continue

            route_verb, route_pattern, rest_of_line = match.groups()
            route_verb_upper = route_verb.upper()

            # Check method match (ALL matches any method)
            if route_verb_upper != "ALL" and route_verb_upper != method_upper:
                continue

            # Check endpoint pattern match
            if not route_matches_endpoint(route_pattern, endpoint, file_path=file_path):
                continue

            # Identify handler function name if referenced
            handler_name = self._extract_js_handler_name(rest_of_line)

            # Determine line range of the handler
            start_line = idx
            end_line = self._find_closing_line(lines, start_line - 1)

            snippet_lines = lines[start_line - 1 : end_line]
            snippet = "".join(snippet_lines).rstrip()

            db_op = detect_database_operation(snippet)
            auth_check = detect_authorization_check(snippet)

            loc = SourceLocation(
                repository_name=self.repository_name,
                file_path=rel_path,
                function_name=handler_name,
                start_line=start_line,
                end_line=end_line,
                code_snippet=snippet,
                related_endpoint=route_pattern,
                route_handler=handler_name or f"{route_verb_upper} {route_pattern}",
                database_operation=db_op,
                authorization_check=auth_check,
                confidence=MappingConfidence.HIGH
            )
            results.append(loc)

        return results

    def _find_py_route_handlers(
        self,
        file_path: Path,
        rel_path: str,
        endpoint: str,
        method: str
    ) -> List[SourceLocation]:
        """Finds FastAPI / Flask route handlers in a Python file via AST."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                lines = content.splitlines(keepends=True)
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return []

        results: List[SourceLocation] = []
        method_upper = method.upper()

        # Check for router prefix (e.g. router = APIRouter(prefix="/api/v1"))
        router_prefix = ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_name = getattr(node.value.func, "id", getattr(node.value.func, "attr", ""))
                if "router" in str(func_name).lower():
                    for kw in node.value.keywords:
                        if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                            router_prefix = str(kw.value.value).rstrip("/")

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                route_info = self._extract_py_decorator_route(decorator)
                if not route_info:
                    continue

                dec_verb, dec_path = route_info
                if dec_verb and dec_verb.upper() != "ALL" and dec_verb.upper() != method_upper:
                    continue

                full_route_path = f"{router_prefix}/{dec_path.lstrip('/')}" if router_prefix else dec_path
                if not route_matches_endpoint(full_route_path, endpoint, file_path=file_path):
                    continue

                start_line = node.decorator_list[0].lineno if node.decorator_list else node.lineno
                end_line = getattr(node, "end_lineno", node.lineno)
                snippet_lines = lines[start_line - 1 : end_line]
                snippet = "".join(snippet_lines).rstrip()

                db_op = detect_database_operation(snippet)
                auth_check = detect_authorization_check(snippet)

                loc = SourceLocation(
                    repository_name=self.repository_name,
                    file_path=rel_path,
                    function_name=node.name,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=snippet,
                    related_endpoint=full_route_path,
                    route_handler=node.name,
                    database_operation=db_op,
                    authorization_check=auth_check,
                    confidence=MappingConfidence.HIGH
                )
                results.append(loc)

        return results

    def _extract_py_decorator_route(self, decorator: ast.AST) -> Optional[Tuple[str, str]]:
        """Extracts (method, path) from a Python route decorator (e.g. @app.get('/path'))."""
        if isinstance(decorator, ast.Call):
            func = decorator.func
            verb = "GET"
            if isinstance(func, ast.Attribute):
                verb = func.attr
            elif isinstance(func, ast.Name):
                verb = func.id

            path = None
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                path = str(decorator.args[0].value)

            if path:
                return (verb, path)

        return None

    def _extract_js_handler_name(self, text_after_route: str) -> Optional[str]:
        """Extracts a named function or identifier from the arguments after the route path."""
        # e.g., router.get('/:id', function retrieveBasket(...) or router.get('/:id', retrieveBasket)
        fn_decl_match = re.search(r"""function\s+([a-zA-Z0-9_$]+)""", text_after_route)
        if fn_decl_match:
            return fn_decl_match.group(1)

        clean = text_after_route.strip().lstrip(",").strip()
        named_fn_match = re.search(r"""^([a-zA-Z0-9_$]+)\b""", clean)
        if named_fn_match:
            candidate = named_fn_match.group(1)
            if candidate not in ("function", "async"):
                return candidate
        return None

    def _find_closing_line(self, lines: List[str], start_idx: int) -> int:
        """Finds the line where the enclosing block or function closes."""
        brace_count = 0
        paren_count = 0
        started = False

        for i in range(start_idx, len(lines)):
            line = lines[i]
            for ch in line:
                if ch == '{':
                    brace_count += 1
                    started = True
                elif ch == '}':
                    brace_count -= 1
                elif ch == '(':
                    paren_count += 1
                elif ch == ')':
                    paren_count -= 1

            if started and brace_count <= 0 and paren_count <= 0:
                return i + 1

        # Fallback: search up to next route definition or end of file
        return min(start_idx + 30, len(lines))

    # -------------------------------------------------------------------------
    # Path & File Utilities
    # -------------------------------------------------------------------------

    def _resolve_safe_path(self, path_str: str) -> Tuple[Optional[Path], Optional[str]]:
        """Resolves path against repo_root while preventing path traversal."""
        p = Path(path_str)

        if p.is_absolute():
            resolved = p.resolve()
            if self.repo_root and not str(resolved).startswith(str(self.repo_root)):
                return None, f"Path traversal: '{path_str}' escapes repository boundary."
            return resolved, None

        if not self.repo_root:
            cwd_resolved = (Path.cwd() / p).resolve()
            return cwd_resolved, None

        # Resolve relative to repo_root
        resolved = (self.repo_root / p).resolve()
        if not str(resolved).startswith(str(self.repo_root)):
            return None, f"Path traversal: '{path_str}' escapes repository boundary."

        return resolved, None

    def _relativize_path(self, path: Path) -> str:
        """Returns relative path string if inside repo_root, else normalized path."""
        if self.repo_root:
            try:
                return str(path.relative_to(self.repo_root)).replace("\\", "/")
            except ValueError:
                pass
        return str(path).replace("\\", "/")

    def _normalize_whitespace(self, text: str) -> str:
        """Normalizes newlines and whitespace for comparison."""
        return re.sub(r"\s+", " ", text).strip()

    def _verify_python_function(
        self,
        file_path: Path,
        func_name: str,
        start_line: int,
        end_line: int
    ) -> bool:
        """Verifies if func_name exists and encloses/starts near the specified lines in Python file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                tree = ast.parse(f.read(), filename=str(file_path))
        except Exception:
            return False

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == func_name:
                    fn_start = node.lineno
                    fn_end = getattr(node, "end_lineno", node.lineno)
                    if not (end_line < fn_start or start_line > fn_end):
                        return True
        return False

    # -------------------------------------------------------------------------
    # Finding Extraction Helpers
    # -------------------------------------------------------------------------

    def _extract_finding_id(self, finding: Any) -> str:
        """Extracts finding ID from finding object or dictionary."""
        if isinstance(finding, dict):
            return str(finding.get("id") or finding.get("finding_id") or "fnd_unknown")
        return str(getattr(finding, "id", getattr(finding, "finding_id", "fnd_unknown")))

    def _extract_endpoint(self, finding: Any) -> Optional[str]:
        """Extracts target endpoint path from finding object or dictionary."""
        if isinstance(finding, dict):
            return finding.get("endpoint") or finding.get("target_endpoint")
        return getattr(finding, "endpoint", getattr(finding, "target_endpoint", None))

    def _extract_http_method(self, finding: Any) -> str:
        """Extracts HTTP method from finding object or dictionary."""
        if isinstance(finding, dict):
            return str(finding.get("http_method") or finding.get("method") or "GET")
        return str(getattr(finding, "http_method", getattr(finding, "method", "GET")))

    def _extract_static_hint(self, finding: Any) -> Optional[Dict[str, Any]]:
        """Extracts static location hint dictionary from finding or technical_details."""
        if isinstance(finding, dict):
            if "source_location" in finding and isinstance(finding["source_location"], dict):
                return finding["source_location"]
            if "file_path" in finding:
                return finding
            tech = finding.get("technical_details")
            if isinstance(tech, dict) and "source_location" in tech and isinstance(tech["source_location"], dict):
                return tech["source_location"]

        tech_details = getattr(finding, "technical_details", None)
        if isinstance(tech_details, dict):
            if "source_location" in tech_details and isinstance(tech_details["source_location"], dict):
                return tech_details["source_location"]

        return None
