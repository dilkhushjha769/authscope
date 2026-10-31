"""Security Inspector: Authentication, Session, Security Headers, CORS & Transport Detection Engine.

Extends AuthScope's real vulnerability detection capabilities with 5 defensive
security assessment categories:
1. Authentication Weaknesses (unauthenticated access to protected routes, verbose auth error leaks,
   inconsistent authentication enforcement).
2. Session Security (HttpOnly, Secure, SameSite, excessive cookie lifetime, session tokens in URLs/bodies).
3. Security Headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Frame Protection).
4. CORS Misconfiguration (ACA-Origin, ACA-Credentials, ACA-Methods, ACA-Headers, preflight inspection).
5. HTTPS & Transport Security (HTTPS availability, HTTP-to-HTTPS redirect, HSTS, insecure cookie transmission,
   mixed content references, preserving strict TLS certificate validation).

Core Guardrails:
- Enforces ScopeGuard and RequestExecutor on every network call.
- Never treats HTTP 200 alone, missing headers alone, or reflected CORS origins alone as high-severity
  exploitable vulnerabilities without verifying response content and deployment context.
- Redacts all JWTs, Bearer tokens, cookie values, passwords, and PII via EvidenceValidator.
- Deduplicates findings for the same underlying issue across assessments.
"""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit
import uuid

from pydantic import BaseModel, Field

from backend.analysis.evidence_validator import (
    BEARER_REGEX,
    EvidenceArtifact,
    EvidenceValidationStatus,
    EvidenceValidator,
    JSON_SECRET_FIELD_REGEX,
    JWT_REGEX,
)
from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.core.session_manager import Role, SessionManager
from backend.scanner.endpoint_discovery import (
    DiscoveredEndpoint,
    EndpointCategory,
    EndpointDiscovery,
    TEMPLATE_PARAM_REGEX,
)
from backend.scanner.request_executor import HttpResponseModel, RequestExecutor
from backend.scanner.response_analyzer import ResponseAnalyzer
from backend.utils.helpers import (
    ScopeViolationError,
    TargetUnreachableError,
    UnsupportedMethodError,
    compute_sha256,
    sanitize_headers_for_logging,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# Enums & Constants
# ==============================================================================


class DetectionCategory(str, Enum):
    """Canonical detection categories for Sprint 2 security checks."""
    AUTHENTICATION_WEAKNESS = "AUTHENTICATION_WEAKNESS"
    SESSION_SECURITY = "SESSION_SECURITY"
    SECURITY_HEADERS = "SECURITY_HEADERS"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    TRANSPORT_SECURITY = "TRANSPORT_SECURITY"
    BOLA_IDOR = "BOLA_IDOR"
    BFLA = "BFLA"


class FindingSeverity(str, Enum):
    """Consistent 5-tier severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingValidationStatus(str, Enum):
    """Standardized validation statuses."""
    CONFIRMED = "CONFIRMED"
    SUSPICIOUS = "SUSPICIOUS"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"


SESSION_COOKIE_PATTERNS = re.compile(
    r"(?i)(session|sess|sid|connect\.sid|jwt|token|auth|jsessionid|phpsessid|asp\.net_sessionid|access_token|refresh_token)"
)

VERBOSE_IMPLEMENTATION_LEAK_PATTERNS = [
    (re.compile(r"(?i)(SQLITE_ERROR|SequelizeDatabaseError|PostgresError|MySQLSyntaxError|ORA-\d{5}|syntax error at or near)"), "SQL / Database Driver Error Disclosure"),
    (re.compile(r"(?i)(Traceback \(most recent call last\)|at Object\.<anonymous>|at Function\.Module\._load|node_modules[\\/])"), "Server Stack Trace Disclosure"),
    (re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"), "Bcrypt Password Hash Exposure"),
    (re.compile(r"(?i)\$argon2(i|d|id)\$"), "Argon2 Password Hash Exposure"),
]

MIXED_CONTENT_REGEX = re.compile(
    r'(?i)<(?:script|iframe|form|img|link|object|embed)\b[^>]*(?:src|href|action)\s*=\s*["\'](http://[^"\']+)["\']'
)

EXCESSIVE_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 3600  # 30 days
RECOMMENDED_HSTS_MIN_AGE = 31536000  # 1 year in seconds


# ==============================================================================
# Structured Pydantic Models
# ==============================================================================


class ParsedCookie(BaseModel):
    """Structured representation of a parsed Set-Cookie header with redacted value."""
    name: str
    sanitized_header: str
    is_session_cookie: bool = False
    httponly: bool = False
    secure: bool = False
    samesite: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None


class SecurityFindingRecord(BaseModel):
    """Comprehensive, evidence-backed security finding satisfying Section E and Section G."""
    finding_id: str
    assessment_id: str = "default_assessment"
    target_url: str
    endpoint: str
    method: str = "GET"
    http_method: str = "GET"
    testing_role: str = "anonymous"
    detection_category: str
    issue_code: str
    title: str

    # Evidence & Metadata
    actual_response_evidence: str
    sanitized_evidence: str
    sanitized_request_metadata: Dict[str, Any] = Field(default_factory=dict)
    sanitized_response_metadata: Dict[str, Any] = Field(default_factory=dict)
    baseline_response: Dict[str, Any] = Field(default_factory=dict)
    comparison_response: Dict[str, Any] = Field(default_factory=dict)
    relevant_headers_or_cookies: Dict[str, Any] = Field(default_factory=dict)
    response_hash: Optional[str] = None
    response_hashes: Dict[str, Optional[str]] = Field(default_factory=dict)

    # Severity & Validation
    severity: str
    severity_rationale: str
    validation_status: str
    confirmation_reason: str

    # 6-Part Developer & Security Explanation (Section G)
    what_is_wrong: str
    attacker_impact: str
    evidence_summary: str
    exploitation_conditions: str
    remediation_guidance: str
    verification_steps: str

    # Context & Deduplication
    is_security_recommendation: bool = False
    applicability_note: Optional[str] = None
    dedup_key: str = ""
    evidence_artifact: Optional[EvidenceArtifact] = None


class CategoryInspectionResult(BaseModel):
    """Structured result returned by any category inspection."""
    category: str
    target_url: str
    endpoint: str
    method: str = "GET"
    status: str
    findings: List[SecurityFindingRecord] = Field(default_factory=list)
    inspected_items: Dict[str, Any] = Field(default_factory=dict)
    suppressed_duplicates_count: int = 0
    summary: str


# ==============================================================================
# Main Security Inspector Engine
# ==============================================================================


class SecurityInspector:
    """Executes safe, scope-enforced inspections for Auth, Session, Headers, CORS, and Transport."""

    def __init__(
        self,
        executor: Optional[RequestExecutor] = None,
        session_manager: Optional[SessionManager] = None,
        scope_guard: Optional[ScopeGuard] = None,
        base_url: str = settings.target_base_url,
        min_request_interval_ms: float = 0.0,
        cancel_token: Optional[Any] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.session_manager = session_manager or SessionManager()
        self.executor = executor or RequestExecutor(
            scope_guard=self.scope_guard,
            session_manager=self.session_manager,
        )
        self.analyzer = ResponseAnalyzer()
        self.evidence_validator = EvidenceValidator()
        self.discovery = EndpointDiscovery(base_url=base_url, scope_guard=self.scope_guard)
        self.base_url = base_url.rstrip("/")
        self.min_request_interval_ms = min_request_interval_ms
        self.cancel_token = cancel_token
        self._last_request_ts: float = 0.0
        self._seen_dedup_keys: Set[str] = set()

    def reset_deduplication(self) -> None:
        """Clears the duplicate finding suppression registry."""
        self._seen_dedup_keys.clear()

    def _apply_rate_limit(self) -> None:
        """Enforces minimum interval between HTTP requests."""
        if self.min_request_interval_ms <= 0:
            return
        now = time.monotonic()
        elapsed_ms = (now - self._last_request_ts) * 1000.0
        if self._last_request_ts > 0 and elapsed_ms < self.min_request_interval_ms:
            time.sleep((self.min_request_interval_ms - elapsed_ms) / 1000.0)
        self._last_request_ts = time.monotonic()

    def _is_cancelled(
        self,
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> bool:
        eff_token = cancel_token if cancel_token is not None else getattr(self, "cancel_token", None)
        if eff_token is not None and getattr(eff_token, "is_cancelled", False):
            return True
        if should_cancel is not None and should_cancel():
            return True
        return False

    def _resolve_url(self, endpoint_or_url: str, method: str = "GET") -> Tuple[str, str]:
        """Normalizes an endpoint path or full URL and validates scope via ScopeGuard."""
        raw = (endpoint_or_url or "/").strip()
        if raw.startswith(("http://", "https://")):
            full_url = raw
            parsed = urlsplit(full_url)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            path = raw if raw.startswith("/") else f"/{raw}"
            full_url = f"{self.base_url}{path}"

        self.scope_guard.assert_in_scope(full_url, method=method)
        return full_url, path

    def _finalize_and_deduplicate_finding(
        self,
        finding: SecurityFindingRecord,
        dedup_key: str,
    ) -> Tuple[Optional[SecurityFindingRecord], bool]:
        """Validates finding completeness via EvidenceValidator and suppresses duplicates.

        Returns:
            Tuple of (final_finding_or_None, was_duplicate)
        """
        finding.dedup_key = dedup_key
        if dedup_key in self._seen_dedup_keys:
            return None, True

        # Ensure zero raw secrets in evidence fields
        clean_evidence, _ = self.evidence_validator.sanitize_body(finding.actual_response_evidence)
        clean_evidence, _ = self.evidence_validator.sanitize_url(clean_evidence)
        finding.actual_response_evidence = clean_evidence
        finding.sanitized_evidence = clean_evidence

        clean_target_url, _ = self.evidence_validator.sanitize_url(finding.target_url)
        finding.target_url = clean_target_url
        clean_endpoint, _ = self.evidence_validator.sanitize_url(finding.endpoint)
        finding.endpoint = clean_endpoint

        # Validate completeness before allowing CONFIRMED status
        is_valid, val_errors = self.evidence_validator.validate_finding_evidence_dict(finding.model_dump())
        if not is_valid and finding.validation_status == FindingValidationStatus.CONFIRMED.value:
            finding.validation_status = FindingValidationStatus.INCONCLUSIVE.value
            finding.confirmation_reason = (
                f"Downgraded to INCONCLUSIVE due to incomplete or unverified evidence: {'; '.join(val_errors)}"
            )

        self._seen_dedup_keys.add(dedup_key)
        return finding, False

    def _build_request_response_meta(
        self,
        url: str,
        method: str,
        role: Role,
        response: HttpResponseModel,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """Constructs sanitized request/response metadata and deterministic SHA-256 response hash."""
        clean_url, _ = self.evidence_validator.sanitize_url(url)
        req_headers = response.request_metadata.sanitized_headers if response.request_metadata else {}
        san_req_headers, _ = self.evidence_validator.sanitize_headers(req_headers)

        san_resp_headers: Dict[str, str] = {}
        for hk, hv in (response.headers or {}).items():
            hk_lower = hk.lower()
            if hk_lower == "set-cookie":
                san_resp_headers[hk] = self.evidence_validator.sanitize_set_cookie_preserve_attributes(str(hv))
            elif hk_lower in ("authorization", "proxy-authorization", "cookie", "x-api-key"):
                san_resp_headers[hk] = "[REDACTED]"
            else:
                clean_hv, _ = self.evidence_validator.sanitize_body(str(hv), max_excerpt_len=500)
                san_resp_headers[hk] = clean_hv

        canonical_payload = f"{method.upper()}|{clean_url}|{response.status_code}|{response.body}"
        resp_hash = compute_sha256(canonical_payload)

        req_meta = {
            "method": method.upper(),
            "url": clean_url,
            "role": role.value,
            "headers": san_req_headers,
        }
        resp_meta = {
            "status_code": response.status_code,
            "content_length": response.content_length,
            "response_time_ms": round(response.response_time_ms, 2),
            "headers": san_resp_headers,
        }
        return req_meta, resp_meta, resp_hash

    # ==========================================================================
    # 1. AUTHENTICATION WEAKNESSES
    # ==========================================================================

    def inspect_authentication_weaknesses(
        self,
        endpoint: str,
        assessment_id: str = "default_assessment",
        response: Optional[HttpResponseModel] = None,
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> CategoryInspectionResult:
        """Safely investigates authentication weaknesses on an endpoint.

        Checks:
        - Protected resources accessible without authentication.
        - Authentication endpoints / failure responses exposing sensitive implementation details.
        - Weak or missing authentication requirements on sensitive functions.
        Never reports a vulnerability merely because an endpoint returns HTTP 200.
        """
        if self._is_cancelled(cancel_token, should_cancel):
            return CategoryInspectionResult(
                category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                target_url=self.base_url,
                endpoint=endpoint,
                status=FindingValidationStatus.NOT_TESTED.value,
                summary="Inspection cancelled before execution.",
            )

        full_url, norm_path = self._resolve_url(endpoint, method="GET")
        path_only = urlsplit(full_url).path or "/"
        disc_ep = self.discovery.register_endpoint(path_only, method="GET")

        if response is None:
            if TEMPLATE_PARAM_REGEX.search(path_only) and not disc_ep.extracted_resource_id:
                return CategoryInspectionResult(
                    category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    summary=f"Endpoint '{norm_path}' requires a concrete resource ID; skipping without guessing arbitrary IDs.",
                )
            self._apply_rate_limit()
            try:
                response = self.executor.send_request(role=Role.ANONYMOUS, method="GET", url=full_url)
            except TargetUnreachableError as exc:
                return CategoryInspectionResult(
                    category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    summary=f"Target endpoint unreachable ({exc}); unavailable endpoints are not treated as vulnerabilities.",
                )

        if response.status_code in (502, 503, 504):
            return CategoryInspectionResult(
                category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                target_url=full_url,
                endpoint=norm_path,
                status=FindingValidationStatus.INCONCLUSIVE.value,
                summary=f"Endpoint returned gateway/service unavailable status HTTP {response.status_code}.",
            )

        req_meta, resp_meta, resp_hash = self._build_request_response_meta(full_url, "GET", Role.ANONYMOUS, response)
        insp = self.analyzer.inspect_response(response)
        findings: List[SecurityFindingRecord] = []
        suppressed = 0

        # Check 1A: Verbose authentication failure or sensitive implementation detail disclosure
        for pattern, leak_label in VERBOSE_IMPLEMENTATION_LEAK_PATTERNS:
            match = pattern.search(response.body or "")
            if match:
                san_body, _ = self.evidence_validator.sanitize_body(response.body, max_excerpt_len=800)
                evi_artifact = self.evidence_validator.create_and_sign_evidence(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    test_role=Role.ANONYMOUS,
                    authorized_role=Role.ADMIN,
                    method="GET",
                    url=full_url,
                    headers={},
                    response=response,
                    endpoint=norm_path,
                    expected_behavior="Authentication and error responses must return generic error messages without internal stack traces, SQL errors, or password hashes.",
                    actual_behavior=f"Response (HTTP {response.status_code}) exposed '{leak_label}' in body.",
                    validation_status=EvidenceValidationStatus.CONFIRMED,
                )
                fnd = SecurityFindingRecord(
                    finding_id=evi_artifact.finding_id,
                    assessment_id=assessment_id,
                    target_url=full_url,
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                    issue_code="AUTH_IMPLEMENTATION_DETAIL_LEAK",
                    title=f"Sensitive Implementation Detail Exposure ({leak_label}) on {norm_path}",
                    actual_response_evidence=san_body,
                    sanitized_evidence=san_body,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    comparison_response={"status_code": response.status_code, "body_preview": san_body[:300]},
                    relevant_headers_or_cookies={"content-type": response.headers.get("content-type", "")},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash, "evidence_sha256": evi_artifact.evidence_sha256},
                    severity=FindingSeverity.HIGH.value if "Hash" in leak_label else FindingSeverity.MEDIUM.value,
                    severity_rationale=f"Response directly exposes internal {leak_label} to unauthenticated callers.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Verified presence of '{leak_label}' pattern in actual HTTP {response.status_code} response body.",
                    what_is_wrong=f"The endpoint '{norm_path}' leaks internal implementation details ({leak_label}) in its HTTP response.",
                    attacker_impact="An attacker can harvest database schema details, internal file paths, framework versions, or password hashes to craft targeted exploits.",
                    evidence_summary=f"HTTP {response.status_code} response contained verified '{leak_label}' indicator.",
                    exploitation_conditions="Unauthenticated network access to the endpoint.",
                    remediation_guidance="Configure centralized production error handling that logs detailed diagnostics server-side while returning generic, standardized error payloads to clients. Never serialize raw password hashes in API models.",
                    verification_steps=f"Send an unauthenticated GET request to '{norm_path}' and verify that stack traces, SQL errors, and password hashes are absent from the response.",
                    evidence_artifact=evi_artifact,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(
                    fnd, f"AUTH_LEAK:{norm_path}:{leak_label}"
                )
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        # Check 1B: Public endpoint false-positive prevention
        is_public_catalog = path_only.lower().startswith("/api/products") or disc_ep.category == EndpointCategory.PUBLIC
        if is_public_catalog and not insp.sensitive_fields_found:
            status = FindingValidationStatus.CONFIRMED.value if findings else FindingValidationStatus.NOT_CONFIRMED.value
            return CategoryInspectionResult(
                category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                target_url=full_url,
                endpoint=norm_path,
                status=status,
                findings=findings,
                inspected_items={
                    "status_code": response.status_code,
                    "is_public_endpoint": True,
                    "is_spa_fallback": insp.is_spa_html_fallback,
                    "is_empty_payload": insp.is_empty_payload,
                },
                suppressed_duplicates_count=suppressed,
                summary=f"Public endpoint '{norm_path}' evaluated; public response is not reported as unauthorized access.",
            )

        # Check 1C: Unauthenticated access to protected resource or sensitive function
        if disc_ep.requires_auth or disc_ep.category in (
            EndpointCategory.ADMIN_FUNCTION,
            EndpointCategory.USER_OBJECT,
            EndpointCategory.USER_COLLECTION,
        ):
            if (
                insp.is_http_success
                and not insp.is_spa_html_fallback
                and not insp.is_empty_payload
                and insp.is_json
            ):
                san_body, _ = self.evidence_validator.sanitize_body(response.body, max_excerpt_len=1000)
                has_sensitive = len(insp.sensitive_fields_found) > 0
                is_admin_route = disc_ep.category == EndpointCategory.ADMIN_FUNCTION or "admin" in path_only.lower()

                # Check if authenticated baseline is available to confirm identical protected data
                baseline_matched = False
                baseline_meta: Dict[str, Any] = {}
                auth_role = Role.ADMIN if is_admin_route else Role.USER_A
                if self.session_manager.is_authenticated(auth_role):
                    self._apply_rate_limit()
                    try:
                        base_resp = self.executor.send_request(role=auth_role, method="GET", url=full_url)
                        sim = self.analyzer.compute_body_similarity(base_resp.body, response.body)
                        baseline_meta = {
                            "status_code": base_resp.status_code,
                            "content_length": base_resp.content_length,
                            "similarity": sim,
                        }
                        if base_resp.status_code == 200 and sim >= 0.80:
                            baseline_matched = True
                    except TargetUnreachableError:
                        pass

                is_confirmed_weakness = has_sensitive or baseline_matched
                val_status = (
                    FindingValidationStatus.CONFIRMED.value
                    if is_confirmed_weakness
                    else FindingValidationStatus.SUSPICIOUS.value
                )
                evi_val_enum = (
                    EvidenceValidationStatus.CONFIRMED
                    if is_confirmed_weakness
                    else EvidenceValidationStatus.SUSPICIOUS
                )

                sev = (
                    FindingSeverity.HIGH.value
                    if (is_confirmed_weakness and (is_admin_route or has_sensitive))
                    else FindingSeverity.MEDIUM.value
                )
                evi_artifact = self.evidence_validator.create_and_sign_evidence(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    test_role=Role.ANONYMOUS,
                    authorized_role=auth_role,
                    method="GET",
                    url=full_url,
                    headers={},
                    response=response,
                    endpoint=norm_path,
                    expected_behavior=f"Protected endpoint '{norm_path}' must require valid authentication and reject anonymous requests with HTTP 401/403.",
                    actual_behavior=(
                        f"Anonymous request received HTTP {response.status_code} with {response.content_length} bytes of JSON data "
                        f"(sensitive_fields={insp.sensitive_fields_found}, baseline_matched={baseline_matched})."
                    ),
                    validation_status=evi_val_enum,
                )

                fnd = SecurityFindingRecord(
                    finding_id=evi_artifact.finding_id,
                    assessment_id=assessment_id,
                    target_url=full_url,
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                    issue_code="MISSING_AUTHENTICATION_ON_PROTECTED_ENDPOINT",
                    title=f"Missing Authentication on Protected Endpoint {norm_path}",
                    actual_response_evidence=san_body,
                    sanitized_evidence=san_body,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    baseline_response=baseline_meta,
                    comparison_response={"status_code": response.status_code, "body_preview": san_body[:300]},
                    relevant_headers_or_cookies={"content-type": response.headers.get("content-type", "")},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash, "evidence_sha256": evi_artifact.evidence_sha256},
                    severity=sev,
                    severity_rationale=(
                        f"Unauthenticated caller retrieved protected JSON data from '{norm_path}' "
                        f"(sensitive fields exposed: {insp.sensitive_fields_found})."
                    ),
                    validation_status=val_status,
                    confirmation_reason=(
                        f"Confirmed missing authentication: anonymous GET returned non-empty JSON with sensitive fields {insp.sensitive_fields_found} or verified baseline match."
                        if is_confirmed_weakness
                        else f"Suspicious unauthenticated JSON response on protected route '{norm_path}'; requires authenticated baseline comparison to confirm private data exposure."
                    ),
                    what_is_wrong=f"Protected endpoint '{norm_path}' does not enforce authentication before returning structured application data.",
                    attacker_impact="An unauthenticated attacker can directly read protected user records, administrative configurations, or internal application state.",
                    evidence_summary=f"Anonymous GET {norm_path} returned HTTP {response.status_code} ({response.content_length} bytes JSON, sensitive_fields={insp.sensitive_fields_found}).",
                    exploitation_conditions="Direct network reachability to the endpoint; no credentials required.",
                    remediation_guidance="Apply authentication middleware (e.g., JWT/session verification) to the route handler and reject unauthenticated requests with HTTP 401 Unauthorized.",
                    verification_steps=f"Execute an unauthenticated GET request to '{norm_path}' and verify the server returns HTTP 401 Unauthorized with no protected payload.",
                    evidence_artifact=evi_artifact,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(
                    fnd, f"MISSING_AUTH:{norm_path}"
                )
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        overall_status = FindingValidationStatus.NOT_CONFIRMED.value
        if any(f.validation_status == FindingValidationStatus.CONFIRMED.value for f in findings):
            overall_status = FindingValidationStatus.CONFIRMED.value
        elif any(f.validation_status == FindingValidationStatus.SUSPICIOUS.value for f in findings):
            overall_status = FindingValidationStatus.SUSPICIOUS.value

        return CategoryInspectionResult(
            category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
            target_url=full_url,
            endpoint=norm_path,
            status=overall_status,
            findings=findings,
            inspected_items={
                "status_code": response.status_code,
                "is_json": insp.is_json,
                "is_spa_fallback": insp.is_spa_html_fallback,
                "is_empty_payload": insp.is_empty_payload,
                "sensitive_fields_found": insp.sensitive_fields_found,
            },
            suppressed_duplicates_count=suppressed,
            summary=f"Authentication inspection on '{norm_path}' completed with status {overall_status} ({len(findings)} finding(s)).",
        )

    def inspect_inconsistent_authentication(
        self,
        endpoints: List[str],
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
    ) -> CategoryInspectionResult:
        """Detects inconsistent authentication enforcement across related protected endpoints."""
        enforced_routes: List[str] = []
        exposed_routes: List[Tuple[str, HttpResponseModel, List[str]]] = []
        findings: List[SecurityFindingRecord] = []
        suppressed = 0

        for ep in endpoints:
            if self._is_cancelled(cancel_token):
                break
            res = self.inspect_authentication_weaknesses(ep, assessment_id=assessment_id, cancel_token=cancel_token)
            findings.extend(res.findings)
            suppressed += res.suppressed_duplicates_count
            code = res.inspected_items.get("status_code", 0)
            if code in (401, 403):
                enforced_routes.append(ep)
            elif res.status in (FindingValidationStatus.CONFIRMED.value, FindingValidationStatus.SUSPICIOUS.value):
                full_url, norm_path = self._resolve_url(ep)
                exposed_routes.append((norm_path, HttpResponseModel(status_code=code, body=str(res.inspected_items)), res.inspected_items.get("sensitive_fields_found", [])))

        if enforced_routes and exposed_routes:
            exp_path, exp_resp, sens_fields = exposed_routes[0]
            full_url, _ = self._resolve_url(exp_path)
            evidence_text = (
                f"Inconsistent authentication enforcement detected: routes {enforced_routes} properly denied anonymous access (HTTP 401/403), "
                f"whereas protected sibling route '{exp_path}' returned HTTP {exp_resp.status_code} (sensitive_fields={sens_fields})."
            )
            fnd = SecurityFindingRecord(
                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                target_url=full_url,
                endpoint=exp_path,
                method="GET",
                http_method="GET",
                testing_role=Role.ANONYMOUS.value,
                detection_category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
                issue_code="INCONSISTENT_AUTH_ENFORCEMENT",
                title=f"Inconsistent Authentication Enforcement Across Protected Routes ({exp_path})",
                actual_response_evidence=evidence_text,
                sanitized_evidence=evidence_text,
                sanitized_request_metadata={"tested_routes": endpoints, "role": "anonymous"},
                sanitized_response_metadata={"enforced_routes": enforced_routes, "exposed_route": exp_path},
                relevant_headers_or_cookies={"enforced_routes": enforced_routes, "exposed_route": exp_path},
                response_hash=compute_sha256(evidence_text),
                response_hashes={"evidence_sha256": compute_sha256(evidence_text)},
                severity=FindingSeverity.MEDIUM.value,
                severity_rationale="Authentication middleware is applied inconsistently across protected API routes, leaving individual endpoints exposed.",
                validation_status=FindingValidationStatus.CONFIRMED.value,
                confirmation_reason=evidence_text,
                what_is_wrong=f"Authentication is enforced on {enforced_routes} but omitted on protected endpoint '{exp_path}'.",
                attacker_impact="Attackers can bypass authentication controls by targeting unprotected routes that expose underlying data models.",
                evidence_summary=evidence_text,
                exploitation_conditions="Direct unauthenticated HTTP access to the unprotected route.",
                remediation_guidance="Enforce authentication globally at the router/gateway level by default (deny-by-default), explicitly allowlisting only intended public routes.",
                verification_steps=f"Verify that all protected endpoints ({', '.join(endpoints)}) consistently return HTTP 401 Unauthorized to anonymous callers.",
            )
            final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"INCONSISTENT_AUTH:{exp_path}")
            if is_dup:
                suppressed += 1
            elif final_fnd:
                findings.append(final_fnd)

        overall_status = (
            FindingValidationStatus.CONFIRMED.value
            if any(f.validation_status == FindingValidationStatus.CONFIRMED.value for f in findings)
            else FindingValidationStatus.NOT_CONFIRMED.value
        )
        return CategoryInspectionResult(
            category=DetectionCategory.AUTHENTICATION_WEAKNESS.value,
            target_url=self.base_url,
            endpoint=",".join(endpoints),
            status=overall_status,
            findings=findings,
            inspected_items={"enforced_routes": enforced_routes, "exposed_routes": [e[0] for e in exposed_routes]},
            suppressed_duplicates_count=suppressed,
            summary=f"Evaluated {len(endpoints)} endpoints for authentication consistency ({len(enforced_routes)} enforced, {len(exposed_routes)} exposed).",
        )

    # ==========================================================================
    # 2. SESSION SECURITY
    # ==========================================================================

    @classmethod
    def parse_set_cookie_headers(cls, raw_cookies: List[str]) -> List[ParsedCookie]:
        """Parses raw Set-Cookie header strings while redacting sensitive token values."""
        parsed_list: List[ParsedCookie] = []
        for raw in raw_cookies:
            if not raw or not raw.strip():
                continue
            sanitized_hdr = EvidenceValidator.sanitize_set_cookie_preserve_attributes(raw)
            segments = [s.strip() for s in raw.split(";") if s.strip()]
            if not segments or "=" not in segments[0]:
                continue
            cookie_name, _ = segments[0].split("=", 1)
            cookie_name = cookie_name.strip()
            is_sess = bool(SESSION_COOKIE_PATTERNS.search(cookie_name))

            httponly = False
            secure = False
            samesite: Optional[str] = None
            max_age: Optional[int] = None
            expires: Optional[str] = None
            domain: Optional[str] = None
            path: Optional[str] = None

            for attr in segments[1:]:
                attr_lower = attr.lower()
                if attr_lower == "httponly":
                    httponly = True
                elif attr_lower == "secure":
                    secure = True
                elif attr_lower.startswith("samesite="):
                    samesite = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("max-age="):
                    try:
                        max_age = int(attr.split("=", 1)[1].strip())
                    except ValueError:
                        pass
                elif attr_lower.startswith("expires="):
                    expires = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("domain="):
                    domain = attr.split("=", 1)[1].strip()
                elif attr_lower.startswith("path="):
                    path = attr.split("=", 1)[1].strip()

            parsed_list.append(
                ParsedCookie(
                    name=cookie_name,
                    sanitized_header=sanitized_hdr,
                    is_session_cookie=is_sess,
                    httponly=httponly,
                    secure=secure,
                    samesite=samesite,
                    max_age=max_age,
                    expires=expires,
                    domain=domain,
                    path=path,
                )
            )
        return parsed_list

    def inspect_session_security(
        self,
        endpoint: str = "/",
        response: Optional[HttpResponseModel] = None,
        set_cookie_headers: Optional[List[str]] = None,
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> CategoryInspectionResult:
        """Inspects HTTP responses, cookies, and URLs for session security weaknesses.

        Checks:
        - Missing HttpOnly attribute.
        - Missing Secure attribute (distinguishing HTTPS vs HTTP deployment context).
        - Missing or inappropriate SameSite attribute (e.g. SameSite=None without Secure).
        - Excessive session cookie lifetime.
        - Sensitive session tokens exposed in URLs.
        - Session tokens exposed in response bodies.
        Never exposes raw session tokens in reports.
        """
        if self._is_cancelled(cancel_token, should_cancel):
            return CategoryInspectionResult(
                category=DetectionCategory.SESSION_SECURITY.value,
                target_url=self.base_url,
                endpoint=endpoint,
                status=FindingValidationStatus.NOT_TESTED.value,
                summary="Session security inspection cancelled.",
            )

        full_url, norm_path = self._resolve_url(endpoint, method="GET")
        is_https = full_url.lower().startswith("https://")

        if response is None:
            self._apply_rate_limit()
            try:
                response = self.executor.send_request(role=Role.ANONYMOUS, method="GET", url=full_url)
            except TargetUnreachableError as exc:
                return CategoryInspectionResult(
                    category=DetectionCategory.SESSION_SECURITY.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    summary=f"Target unreachable ({exc}); session security could not be verified.",
                )

        req_meta, resp_meta, resp_hash = self._build_request_response_meta(full_url, "GET", Role.ANONYMOUS, response)
        findings: List[SecurityFindingRecord] = []
        suppressed = 0

        # 1. Check for sensitive session information exposed in URL or Location redirect header
        location_hdr = response.headers.get("location") or response.headers.get("Location") or ""
        for url_candidate, source_label in [(full_url, "Request URL"), (location_hdr, "Location Redirect Header")]:
            if not url_candidate:
                continue
            san_url, redacted_url_params = self.evidence_validator.sanitize_url(url_candidate)
            if redacted_url_params:
                evidence_str = f"{source_label} exposed session/authentication parameter(s) {redacted_url_params}: {san_url}"
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=san_url if source_label == "Request URL" else req_meta["url"],
                    endpoint=self.evidence_validator.sanitize_url(norm_path)[0],
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="SESSION_TOKEN_IN_URL",
                    title=f"Sensitive Session Token Exposed in {source_label}",
                    actual_response_evidence=evidence_str,
                    sanitized_evidence=evidence_str,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"redacted_url_parameters": redacted_url_params, "sanitized_url": san_url},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.MEDIUM.value,
                    severity_rationale="Session identifiers or authentication tokens in URLs are persisted in browser history, proxy logs, and leaked via Referer headers.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Verified presence of sensitive session parameter(s) {redacted_url_params} in {source_label}.",
                    what_is_wrong=f"Session or authentication token is transmitted in the {source_label} query string rather than a protected HTTP header or HttpOnly cookie.",
                    attacker_impact="An attacker can hijack user sessions via Referer header leakage to third-party assets, shared links, or server/proxy access logs.",
                    evidence_summary=evidence_str,
                    exploitation_conditions="User navigates to external links or loads third-party resources without strict Referrer-Policy, or attacker reads access logs.",
                    remediation_guidance="Transmit session identifiers and authentication tokens exclusively via HTTP Authorization headers or HttpOnly, Secure cookies; never place tokens in URL query parameters.",
                    verification_steps="Inspect application URLs and redirect Location headers to confirm no token, jwt, or session_id parameters appear in query strings.",
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"SESSION_URL_TOKEN:{source_label}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        # 2. Check for session tokens exposed in response body on non-authentication endpoints
        path_lower = urlsplit(full_url).path.lower()
        is_login_endpoint = any(k in path_lower for k in ("/login", "/auth", "/token", "/signin", "/oauth"))
        if not is_login_endpoint and response.body:
            san_body, redacted_body_items = self.evidence_validator.sanitize_body(response.body, max_excerpt_len=800)
            if "body_jwt" in redacted_body_items or "body_bearer_token" in redacted_body_items:
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=self.evidence_validator.sanitize_url(norm_path)[0],
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="SESSION_TOKEN_EXPOSED_IN_RESPONSE",
                    title=f"Session Token / JWT Exposed in Response Body on {norm_path}",
                    actual_response_evidence=san_body,
                    sanitized_evidence=san_body,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"redacted_items": redacted_body_items},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.MEDIUM.value,
                    severity_rationale="Non-login endpoint response body contains raw session/JWT tokens that may be cached or logged.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Detected and redacted raw token indicator ({redacted_body_items}) in response body from non-login endpoint '{norm_path}'.",
                    what_is_wrong=f"Endpoint '{norm_path}' returns session tokens or JWTs in the response body.",
                    attacker_impact="Tokens exposed in standard API responses can be captured via cross-site scripting (XSS), browser caching, or diagnostic logging.",
                    evidence_summary=f"Response body on GET {norm_path} contained token material ({redacted_body_items}); value redacted in report.",
                    exploitation_conditions="Attacker gains read access to cached responses, logs, or client-side script execution.",
                    remediation_guidance="Do not echo session tokens or JWTs in non-authentication API responses. Issue tokens only during explicit authentication handshakes.",
                    verification_steps=f"Request '{norm_path}' and verify that session tokens and JWT strings are omitted from the response payload.",
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"SESSION_BODY_TOKEN:{norm_path}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        # 3. Collect and parse Set-Cookie headers
        raw_cookies: List[str] = list(set_cookie_headers or [])
        if not raw_cookies:
            for k, v in (response.headers or {}).items():
                if k.lower() == "set-cookie":
                    # Support newline-joined or single Set-Cookie header values
                    for line in str(v).split("\n"):
                        if line.strip():
                            raw_cookies.append(line.strip())

        parsed_cookies = self.parse_set_cookie_headers(raw_cookies)

        if not parsed_cookies and not findings:
            return CategoryInspectionResult(
                category=DetectionCategory.SESSION_SECURITY.value,
                target_url=req_meta["url"],
                endpoint=norm_path,
                status=FindingValidationStatus.INCONCLUSIVE.value,
                findings=[],
                inspected_items={
                    "cookies_observed": 0,
                    "applicability_note": (
                        "No Set-Cookie headers were present in the HTTP response. "
                        "Cookie attributes (HttpOnly, Secure, SameSite, Max-Age) cannot be verified when no cookies are issued."
                    ),
                },
                suppressed_duplicates_count=suppressed,
                summary="No Set-Cookie headers observed in response; cookie attribute checks are inconclusive without observable cookies.",
            )

        for cookie in parsed_cookies:
            cookie_meta = cookie.model_dump()

            # 3A: Missing HttpOnly
            if not cookie.httponly:
                sev = FindingSeverity.MEDIUM.value if cookie.is_session_cookie else FindingSeverity.LOW.value
                is_rec = not cookie.is_session_cookie
                app_note = (
                    None
                    if cookie.is_session_cookie
                    else f"Cookie '{cookie.name}' does not match common session identifier names; if intentionally read by frontend scripts, omitting HttpOnly may be by design, though sensitive state must never be stored in it."
                )
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="COOKIE_MISSING_HTTPONLY",
                    title=f"Cookie '{cookie.name}' Missing HttpOnly Attribute",
                    actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"cookie": cookie_meta},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=sev,
                    severity_rationale=(
                        f"Session cookie '{cookie.name}' lacks HttpOnly, allowing JavaScript access via document.cookie."
                        if cookie.is_session_cookie
                        else f"Non-session cookie '{cookie.name}' lacks HttpOnly (hardening recommendation)."
                    ),
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Observed Set-Cookie header for '{cookie.name}' without the 'HttpOnly' flag.",
                    what_is_wrong=f"The cookie '{cookie.name}' is set without the 'HttpOnly' directive.",
                    attacker_impact="If Cross-Site Scripting (XSS) occurs, malicious client-side scripts can read this cookie via document.cookie and exfiltrate it.",
                    evidence_summary=f"Observed header: Set-Cookie: {cookie.sanitized_header}",
                    exploitation_conditions="Requires an XSS vector or malicious script execution within the application origin.",
                    remediation_guidance=f"Set the 'HttpOnly' flag when issuing the '{cookie.name}' cookie (e.g., `Set-Cookie: {cookie.name}=<val>; HttpOnly; Secure; SameSite=Lax`).",
                    verification_steps=f"Inspect the Set-Cookie response header for '{cookie.name}' and confirm the 'HttpOnly' attribute is present.",
                    is_security_recommendation=is_rec,
                    applicability_note=app_note,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"COOKIE_HTTPONLY:{cookie.name}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

            # 3B: Missing Secure attribute
            if not cookie.secure:
                if is_https:
                    sev = FindingSeverity.MEDIUM.value if cookie.is_session_cookie else FindingSeverity.LOW.value
                    is_rec = not cookie.is_session_cookie
                    app_note = None
                    rationale = f"Cookie '{cookie.name}' was issued over HTTPS without the 'Secure' attribute, permitting transmission over unencrypted HTTP."
                else:
                    sev = FindingSeverity.LOW.value if cookie.is_session_cookie else FindingSeverity.INFORMATIONAL.value
                    is_rec = True
                    app_note = (
                        "Target was accessed over plain HTTP (non-HTTPS). Browsers only transmit 'Secure' cookies over HTTPS "
                        "(or localhost in modern browsers). Enable 'Secure' alongside HTTPS in production."
                    )
                    rationale = f"Cookie '{cookie.name}' lacks the 'Secure' attribute on an HTTP endpoint (production HTTPS hardening recommendation)."

                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="COOKIE_MISSING_SECURE",
                    title=f"Cookie '{cookie.name}' Missing Secure Attribute",
                    actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"cookie": cookie_meta, "is_https_target": is_https},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=sev,
                    severity_rationale=rationale,
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Observed Set-Cookie header for '{cookie.name}' without the 'Secure' attribute.",
                    what_is_wrong=f"The cookie '{cookie.name}' does not include the 'Secure' attribute.",
                    attacker_impact="If a user makes an unencrypted HTTP request to the domain, the browser will transmit the cookie in cleartext over the network.",
                    evidence_summary=f"Observed header: Set-Cookie: {cookie.sanitized_header}",
                    exploitation_conditions="User triggers an unencrypted HTTP request on a network observable by an attacker.",
                    remediation_guidance=f"Add the 'Secure' attribute to the '{cookie.name}' cookie in all HTTPS environments.",
                    verification_steps=f"Inspect the Set-Cookie header for '{cookie.name}' over HTTPS and verify the 'Secure' flag is present.",
                    is_security_recommendation=is_rec,
                    applicability_note=app_note,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"COOKIE_SECURE:{cookie.name}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

            # 3C: Missing or inappropriate SameSite attribute
            samesite_lower = (cookie.samesite or "").lower()
            if not samesite_lower:
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="COOKIE_MISSING_SAMESITE",
                    title=f"Cookie '{cookie.name}' Missing SameSite Attribute",
                    actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"cookie": cookie_meta},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.LOW.value,
                    severity_rationale=f"Cookie '{cookie.name}' omits explicit SameSite protection, relying on browser-specific Lax defaults.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Observed Set-Cookie header for '{cookie.name}' without a 'SameSite' directive.",
                    what_is_wrong=f"The cookie '{cookie.name}' is issued without an explicit 'SameSite=Lax' or 'SameSite=Strict' attribute.",
                    attacker_impact="In older browsers or non-standard user agents that do not enforce Lax-by-default, the cookie may be sent on cross-site requests (CSRF risk).",
                    evidence_summary=f"Observed header: Set-Cookie: {cookie.sanitized_header}",
                    exploitation_conditions="Victim uses a browser without SameSite=Lax default and visits a malicious third-party page triggering cross-site requests.",
                    remediation_guidance=f"Explicitly set 'SameSite=Lax' or 'SameSite=Strict' on the '{cookie.name}' cookie.",
                    verification_steps=f"Verify the Set-Cookie header for '{cookie.name}' contains 'SameSite=Lax' or 'SameSite=Strict'.",
                    is_security_recommendation=not cookie.is_session_cookie,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"COOKIE_SAMESITE:{cookie.name}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)
            elif samesite_lower == "none" and not cookie.secure:
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="COOKIE_SAMESITE_NONE_WITHOUT_SECURE",
                    title=f"Cookie '{cookie.name}' Uses SameSite=None Without Secure",
                    actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"cookie": cookie_meta},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.MEDIUM.value,
                    severity_rationale=f"Cookie '{cookie.name}' specifies SameSite=None without the Secure attribute, enabling cross-site transmission over insecure channels.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Observed 'SameSite=None' without 'Secure' on Set-Cookie header for '{cookie.name}'.",
                    what_is_wrong=f"Cookie '{cookie.name}' is configured with 'SameSite=None' but lacks the mandatory 'Secure' attribute.",
                    attacker_impact="Cross-site requests can include this cookie, and modern browsers may reject or inconsistently handle the cookie.",
                    evidence_summary=f"Observed header: Set-Cookie: {cookie.sanitized_header}",
                    exploitation_conditions="Cross-origin requests from third-party sites.",
                    remediation_guidance=f"Prefer 'SameSite=Lax' or 'SameSite=Strict'. If cross-site usage is strictly required, add the 'Secure' attribute alongside 'SameSite=None'.",
                    verification_steps=f"Inspect Set-Cookie for '{cookie.name}' and confirm either 'SameSite=Lax/Strict' or 'SameSite=None; Secure'.",
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"COOKIE_SAMESITE_NONE:{cookie.name}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

            # 3D: Excessive lifetime on session cookies
            lifetime_seconds: Optional[int] = cookie.max_age
            if lifetime_seconds is None and cookie.expires:
                try:
                    exp_dt = parsedate_to_datetime(cookie.expires)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    lifetime_seconds = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
                except Exception:
                    pass

            if cookie.is_session_cookie and lifetime_seconds is not None and lifetime_seconds > EXCESSIVE_COOKIE_MAX_AGE_SECONDS:
                days = round(lifetime_seconds / 86400, 1)
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.SESSION_SECURITY.value,
                    issue_code="COOKIE_EXCESSIVE_LIFETIME",
                    title=f"Session Cookie '{cookie.name}' Has Excessive Lifetime ({days} days)",
                    actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"cookie": cookie_meta, "lifetime_seconds": lifetime_seconds, "lifetime_days": days},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.LOW.value,
                    severity_rationale=f"Session cookie '{cookie.name}' persists for {days} days (> 30 days threshold), expanding the window for session replay if compromised.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Verified Max-Age/Expires lifetime of {lifetime_seconds} seconds ({days} days) on session cookie '{cookie.name}'.",
                    what_is_wrong=f"Session cookie '{cookie.name}' is configured with an excessive validity period of {days} days.",
                    attacker_impact="A stolen session cookie remains valid for an extended period, increasing the impact of device theft or token leakage.",
                    evidence_summary=f"Observed header: Set-Cookie: {cookie.sanitized_header} (lifetime={days} days).",
                    exploitation_conditions="Attacker obtains the persistent session cookie from a shared device or backup.",
                    remediation_guidance="Use ephemeral session cookies (omit Max-Age/Expires) or restrict session cookie Max-Age to a short operational window (e.g., 8-24 hours).",
                    verification_steps=f"Inspect Set-Cookie for '{cookie.name}' and confirm Max-Age is <= 86400 seconds or omitted for browser-session scope.",
                    is_security_recommendation=True,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"COOKIE_LIFETIME:{cookie.name}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        overall_status = (
            FindingValidationStatus.CONFIRMED.value
            if findings
            else FindingValidationStatus.NOT_CONFIRMED.value
        )
        return CategoryInspectionResult(
            category=DetectionCategory.SESSION_SECURITY.value,
            target_url=req_meta["url"],
            endpoint=norm_path,
            status=overall_status,
            findings=findings,
            inspected_items={
                "cookies_observed": len(parsed_cookies),
                "cookies": [c.model_dump() for c in parsed_cookies],
                "is_https_target": is_https,
            },
            suppressed_duplicates_count=suppressed,
            summary=f"Session security inspection on '{norm_path}' evaluated {len(parsed_cookies)} cookie(s) and found {len(findings)} issue(s).",
        )

    # ==========================================================================
    # 3. SECURITY HEADERS
    # ==========================================================================

    def inspect_security_headers(
        self,
        endpoint: str = "/",
        response: Optional[HttpResponseModel] = None,
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> CategoryInspectionResult:
        """Inspects actual HTTP responses for security headers according to endpoint & deployment context.

        Evaluates:
        - Content-Security-Policy
        - Strict-Transport-Security
        - X-Content-Type-Options
        - Referrer-Policy
        - Permissions-Policy
        - Frame protection (CSP frame-ancestors or X-Frame-Options)

        Never inflates missing headers to HIGH severity. Deduplicates host-wide missing headers.
        """
        if self._is_cancelled(cancel_token, should_cancel):
            return CategoryInspectionResult(
                category=DetectionCategory.SECURITY_HEADERS.value,
                target_url=self.base_url,
                endpoint=endpoint,
                status=FindingValidationStatus.NOT_TESTED.value,
                summary="Security headers inspection cancelled.",
            )

        full_url, norm_path = self._resolve_url(endpoint, method="GET")
        parsed_url = urlsplit(full_url)
        host_key = f"{parsed_url.scheme}://{parsed_url.netloc}"
        is_https = parsed_url.scheme.lower() == "https"

        if response is None:
            self._apply_rate_limit()
            try:
                response = self.executor.send_request(role=Role.ANONYMOUS, method="GET", url=full_url)
            except TargetUnreachableError as exc:
                return CategoryInspectionResult(
                    category=DetectionCategory.SECURITY_HEADERS.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    summary=f"Target unreachable ({exc}); response headers could not be inspected.",
                )

        if response.status_code >= 500:
            return CategoryInspectionResult(
                category=DetectionCategory.SECURITY_HEADERS.value,
                target_url=full_url,
                endpoint=norm_path,
                status=FindingValidationStatus.INCONCLUSIVE.value,
                summary=f"Endpoint returned server error HTTP {response.status_code}; skipping header evaluation on error response.",
            )

        req_meta, resp_meta, resp_hash = self._build_request_response_meta(full_url, "GET", Role.ANONYMOUS, response)
        headers_lower = {k.lower(): v for k, v in (response.headers or {}).items()}
        content_type = headers_lower.get("content-type", "").lower()
        is_html = "text/html" in content_type or (not content_type and "<html" in (response.body or "")[:500].lower())
        is_json = "application/json" in content_type

        csp = headers_lower.get("content-security-policy", "").strip()
        hsts = headers_lower.get("strict-transport-security", "").strip()
        xcto = headers_lower.get("x-content-type-options", "").strip()
        ref_pol = headers_lower.get("referrer-policy", "").strip()
        perm_pol = headers_lower.get("permissions-policy", "").strip()
        xfo = headers_lower.get("x-frame-options", "").strip()

        observed_security_headers = {
            "content-security-policy": csp or None,
            "strict-transport-security": hsts or None,
            "x-content-type-options": xcto or None,
            "referrer-policy": ref_pol or None,
            "permissions-policy": perm_pol or None,
            "x-frame-options": xfo or None,
            "content-type": content_type or "unknown",
        }
        evidence_header_dump = "\n".join(f"{k}: {v}" for k, v in resp_meta["headers"].items()) or f"HTTP {response.status_code} (no headers)"

        findings: List[SecurityFindingRecord] = []
        suppressed = 0

        def add_header_finding(
            issue_code: str,
            title: str,
            severity: FindingSeverity,
            rationale: str,
            what_wrong: str,
            impact: str,
            conditions: str,
            remediation: str,
            verification: str,
            applicability: Optional[str] = None,
        ) -> None:
            nonlocal suppressed
            fnd = SecurityFindingRecord(
                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                target_url=req_meta["url"],
                endpoint=norm_path,
                method="GET",
                http_method="GET",
                testing_role=Role.ANONYMOUS.value,
                detection_category=DetectionCategory.SECURITY_HEADERS.value,
                issue_code=issue_code,
                title=title,
                actual_response_evidence=evidence_header_dump,
                sanitized_evidence=evidence_header_dump,
                sanitized_request_metadata=req_meta,
                sanitized_response_metadata=resp_meta,
                relevant_headers_or_cookies=observed_security_headers,
                response_hash=resp_hash,
                response_hashes={"comparison_sha256": resp_hash},
                severity=severity.value,
                severity_rationale=rationale,
                validation_status=FindingValidationStatus.CONFIRMED.value,
                confirmation_reason=f"Verified HTTP {response.status_code} response headers from '{norm_path}'.",
                what_is_wrong=what_wrong,
                attacker_impact=impact,
                evidence_summary=f"HTTP {response.status_code} response headers on {norm_path}: {observed_security_headers}",
                exploitation_conditions=conditions,
                remediation_guidance=remediation,
                verification_steps=verification,
                is_security_recommendation=True,
                applicability_note=applicability,
            )
            final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"HEADER:{host_key}:{issue_code}")
            if is_dup:
                suppressed += 1
            elif final_fnd:
                findings.append(final_fnd)

        # 1. Content-Security-Policy (CSP)
        if not csp:
            sev = FindingSeverity.LOW if is_html else FindingSeverity.INFORMATIONAL
            app_note = (
                "Evaluated on HTML document response where CSP mitigates XSS and data injection."
                if is_html
                else "Evaluated on non-HTML API response; CSP primarily protects document/HTML rendering contexts."
            )
            add_header_finding(
                issue_code="MISSING_CSP_HEADER",
                title="Missing Content-Security-Policy (CSP) Header",
                severity=sev,
                rationale=f"Response from '{norm_path}' ({content_type or 'unknown'}) omits Content-Security-Policy.",
                what_wrong="The HTTP response does not include a Content-Security-Policy (CSP) header.",
                impact="Without CSP, the browser does not restrict script sources or outbound connections, increasing the impact of Cross-Site Scripting (XSS) if an injection flaw exists.",
                conditions="Requires an HTML injection or XSS vulnerability in the application.",
                remediation="Configure a restrictive Content-Security-Policy header (e.g., `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`).",
                verification=f"Send a GET request to '{norm_path}' and confirm a valid Content-Security-Policy header is present.",
                applicability=app_note,
            )
        elif "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower():
            add_header_finding(
                issue_code="WEAK_CSP_POLICY",
                title="Permissive Content-Security-Policy Contains unsafe-inline / unsafe-eval",
                severity=FindingSeverity.LOW,
                rationale=f"CSP header ({csp}) permits 'unsafe-inline' or 'unsafe-eval', weakening XSS protection.",
                what_wrong=f"The Content-Security-Policy header includes unsafe directives: `{csp}`.",
                impact="Inline script execution or dynamic eval() calls remain permitted, reducing CSP effectiveness against XSS.",
                conditions="Requires an HTML/script injection flaw in the application.",
                remediation="Remove 'unsafe-inline' and 'unsafe-eval' from script-src/default-src and use cryptographic nonces or hashes for legitimate inline scripts.",
                verification="Inspect the Content-Security-Policy header and verify 'unsafe-inline' and 'unsafe-eval' are absent.",
            )

        # 2. Strict-Transport-Security (HSTS)
        if not hsts:
            sev = FindingSeverity.LOW if is_https else FindingSeverity.INFORMATIONAL
            app_note = (
                None
                if is_https
                else "Target was accessed over plain HTTP. Per RFC 6797, browsers ignore HSTS headers received over unencrypted HTTP; configure HSTS on the HTTPS listener in production."
            )
            add_header_finding(
                issue_code="MISSING_HSTS_HEADER",
                title="Missing Strict-Transport-Security (HSTS) Header",
                severity=sev,
                rationale=(
                    "HTTPS response omits Strict-Transport-Security."
                    if is_https
                    else "HTTP response omits Strict-Transport-Security (informational note for HTTPS deployment)."
                ),
                what_wrong="The response does not include a Strict-Transport-Security (HSTS) header.",
                impact="Browsers are not instructed to pin HTTPS connections for the domain, leaving initial HTTP requests susceptible to SSL stripping on untrusted networks.",
                conditions="User connects over an untrusted network via an initial cleartext HTTP link.",
                remediation="Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
                verification="Request the application over HTTPS and confirm `Strict-Transport-Security` is returned with `max-age>=31536000`.",
                applicability=app_note,
            )
        else:
            m = re.search(r"(?i)max-age\s*=\s*(\d+)", hsts)
            if m and int(m.group(1)) < RECOMMENDED_HSTS_MIN_AGE:
                add_header_finding(
                    issue_code="WEAK_HSTS_MAX_AGE",
                    title=f"Short Strict-Transport-Security max-age ({m.group(1)}s)",
                    severity=FindingSeverity.LOW,
                    rationale=f"HSTS max-age is {m.group(1)} seconds (< recommended 31,536,000 seconds / 1 year).",
                    what_wrong=f"The Strict-Transport-Security header specifies a short max-age: `{hsts}`.",
                    impact="The HSTS policy expires quickly, exposing infrequent visitors to cleartext HTTP downgrade risks.",
                    conditions="User visits the site after the short HSTS max-age expires.",
                    remediation="Increase HSTS `max-age` to at least `31536000` (1 year).",
                    verification="Verify `Strict-Transport-Security` contains `max-age=31536000` or greater.",
                )

        # 3. X-Content-Type-Options
        if xcto.lower() != "nosniff":
            add_header_finding(
                issue_code="MISSING_X_CONTENT_TYPE_OPTIONS",
                title="Missing or Invalid X-Content-Type-Options Header",
                severity=FindingSeverity.LOW,
                rationale=f"X-Content-Type-Options is '{xcto or 'missing'}' instead of 'nosniff'.",
                what_wrong="The response does not set `X-Content-Type-Options: nosniff`.",
                impact="Browsers may MIME-sniff response payloads and execute uploaded or reflected content as active scripts or stylesheets.",
                conditions="Attacker can influence response content on an endpoint with an ambiguous or permissive Content-Type.",
                remediation="Add `X-Content-Type-Options: nosniff` to all HTTP responses.",
                verification=f"Request '{norm_path}' and confirm `X-Content-Type-Options: nosniff` is present.",
            )

        # 4. Referrer-Policy
        unsafe_referrers = {"unsafe-url", "no-referrer-when-downgrade"}
        if not ref_pol or ref_pol.lower() in unsafe_referrers:
            sev = FindingSeverity.LOW if ref_pol.lower() == "unsafe-url" else FindingSeverity.INFORMATIONAL
            add_header_finding(
                issue_code="MISSING_OR_WEAK_REFERRER_POLICY",
                title="Missing or Permissive Referrer-Policy Header",
                severity=sev,
                rationale=f"Referrer-Policy is '{ref_pol or 'missing'}'.",
                what_wrong=f"The response does not define a strict Referrer-Policy (observed: '{ref_pol or 'missing'}').",
                impact="Full URLs or origin metadata may be leaked in Referer headers when users navigate to external links or load third-party assets.",
                conditions="Application pages contain external links or third-party subresources and sensitive paths/query parameters.",
                remediation="Set `Referrer-Policy: strict-origin-when-cross-origin` or `Referrer-Policy: no-referrer`.",
                verification=f"Request '{norm_path}' and verify `Referrer-Policy` is set to `strict-origin-when-cross-origin` or stricter.",
            )

        # 5. Permissions-Policy
        if not perm_pol:
            add_header_finding(
                issue_code="MISSING_PERMISSIONS_POLICY",
                title="Missing Permissions-Policy Header",
                severity=FindingSeverity.INFORMATIONAL,
                rationale="Response omits Permissions-Policy header for restricting powerful browser features.",
                what_wrong="The response does not include a `Permissions-Policy` header.",
                impact="Embedded frames or scripts are not explicitly restricted from requesting browser APIs such as camera, microphone, or geolocation.",
                conditions="Relevant primarily to HTML document responses embedding third-party content.",
                remediation="Add a restrictive `Permissions-Policy` header (e.g., `Permissions-Policy: geolocation=(), microphone=(), camera=()`).",
                verification=f"Request '{norm_path}' and verify the `Permissions-Policy` header is returned.",
                applicability="Primarily applicable to HTML documents; informational on JSON API endpoints." if is_json else None,
            )

        # 6. Frame Protection (CSP frame-ancestors OR X-Frame-Options)
        has_csp_frame_ancestors = "frame-ancestors" in csp.lower()
        has_valid_xfo = xfo.upper() in ("DENY", "SAMEORIGIN")
        if not (has_csp_frame_ancestors or has_valid_xfo):
            sev = FindingSeverity.LOW if is_html else FindingSeverity.INFORMATIONAL
            add_header_finding(
                issue_code="MISSING_FRAME_PROTECTION",
                title="Missing Frame Protection (X-Frame-Options / CSP frame-ancestors)",
                severity=sev,
                rationale="Neither `X-Frame-Options: DENY/SAMEORIGIN` nor `Content-Security-Policy: frame-ancestors` is present.",
                what_wrong="The response lacks anti-framing controls (`X-Frame-Options` and CSP `frame-ancestors`).",
                impact="Interactive HTML pages can be embedded inside an attacker-controlled `<iframe>` to perform Clickjacking / UI redressing attacks.",
                conditions="Target endpoint renders interactive UI elements (buttons, forms) in a browser.",
                remediation="Add `X-Frame-Options: DENY` (or `SAMEORIGIN`) and `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`).",
                verification=f"Request '{norm_path}' and confirm `X-Frame-Options: DENY` or `CSP frame-ancestors` is present.",
                applicability="Clickjacking affects interactive HTML pages; informational on pure JSON API responses." if is_json else None,
            )

        overall_status = (
            FindingValidationStatus.CONFIRMED.value
            if findings
            else FindingValidationStatus.NOT_CONFIRMED.value
        )
        return CategoryInspectionResult(
            category=DetectionCategory.SECURITY_HEADERS.value,
            target_url=req_meta["url"],
            endpoint=norm_path,
            status=overall_status,
            findings=findings,
            inspected_items=observed_security_headers,
            suppressed_duplicates_count=suppressed,
            summary=f"Security headers inspection on '{norm_path}' completed ({len(findings)} finding(s), {suppressed} duplicate(s) suppressed).",
        )

    # ==========================================================================
    # 4. CORS MISCONFIGURATION
    # ==========================================================================

    def inspect_cors_configuration(
        self,
        endpoint: str = "/",
        probe_origin: str = "https://untrusted-origin.example",
        response: Optional[HttpResponseModel] = None,
        preflight_response: Optional[HttpResponseModel] = None,
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> CategoryInspectionResult:
        """Safely inspects CORS headers and preflight behavior without sending requests to external origins.

        Inspects:
        - Access-Control-Allow-Origin
        - Access-Control-Allow-Credentials
        - Access-Control-Allow-Methods
        - Access-Control-Allow-Headers
        - Preflight responses (when OPTIONS is permitted or provided)

        Never claims CORS is exploitable based on wildcard or reflected origin alone without
        evaluating credentials and actual response sensitivity.
        """
        if self._is_cancelled(cancel_token, should_cancel):
            return CategoryInspectionResult(
                category=DetectionCategory.CORS_MISCONFIGURATION.value,
                target_url=self.base_url,
                endpoint=endpoint,
                status=FindingValidationStatus.NOT_TESTED.value,
                summary="CORS inspection cancelled.",
            )

        full_url, norm_path = self._resolve_url(endpoint, method="GET")
        path_only = urlsplit(full_url).path or "/"
        disc_ep = self.discovery.register_endpoint(path_only, method="GET")

        if response is None:
            self._apply_rate_limit()
            try:
                response = self.executor.send_request(
                    role=Role.ANONYMOUS,
                    method="GET",
                    url=full_url,
                    custom_headers={"Origin": probe_origin},
                )
            except TargetUnreachableError as exc:
                return CategoryInspectionResult(
                    category=DetectionCategory.CORS_MISCONFIGURATION.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    summary=f"Target unreachable ({exc}); CORS behavior could not be verified.",
                )

        # Optional preflight inspection if OPTIONS is in ScopeGuard.allowed_methods
        if preflight_response is None and "OPTIONS" in self.scope_guard.allowed_methods:
            self._apply_rate_limit()
            try:
                preflight_response = self.executor.send_request(
                    role=Role.ANONYMOUS,
                    method="OPTIONS",
                    url=full_url,
                    custom_headers={
                        "Origin": probe_origin,
                        "Access-Control-Request-Method": "GET",
                    },
                )
            except (TargetUnreachableError, ScopeViolationError, UnsupportedMethodError):
                preflight_response = None

        req_meta, resp_meta, resp_hash = self._build_request_response_meta(full_url, "GET", Role.ANONYMOUS, response)
        headers_lower = {k.lower(): v.strip() for k, v in (response.headers or {}).items()}
        preflight_lower = {k.lower(): v.strip() for k, v in (preflight_response.headers if preflight_response else {}).items()}

        acao = headers_lower.get("access-control-allow-origin") or preflight_lower.get("access-control-allow-origin") or ""
        acac = (headers_lower.get("access-control-allow-credentials") or preflight_lower.get("access-control-allow-credentials") or "").lower()
        acam = headers_lower.get("access-control-allow-methods") or preflight_lower.get("access-control-allow-methods") or ""
        acah = headers_lower.get("access-control-allow-headers") or preflight_lower.get("access-control-allow-headers") or ""

        insp = self.analyzer.inspect_response(response)
        is_public = disc_ep.category == EndpointCategory.PUBLIC or path_only.lower().startswith("/api/products")
        has_sensitive_data = len(insp.sensitive_fields_found) > 0 or (disc_ep.requires_auth and not is_public)

        cors_details = {
            "probe_origin": probe_origin,
            "access-control-allow-origin": acao or None,
            "access-control-allow-credentials": acac or None,
            "access-control-allow-methods": acam or None,
            "access-control-allow-headers": acah or None,
            "preflight_tested": preflight_response is not None,
        }

        findings: List[SecurityFindingRecord] = []
        suppressed = 0

        if not acao:
            return CategoryInspectionResult(
                category=DetectionCategory.CORS_MISCONFIGURATION.value,
                target_url=req_meta["url"],
                endpoint=norm_path,
                status=FindingValidationStatus.NOT_CONFIRMED.value,
                findings=[],
                inspected_items=cors_details,
                summary=f"No Access-Control-Allow-Origin header returned on '{norm_path}'; cross-origin reads are restricted by Same-Origin Policy.",
            )

        is_reflected_origin = acao.lower() == probe_origin.lower()
        is_null_origin = acao.lower() == "null"
        is_wildcard = acao == "*"
        allows_credentials = acac == "true"

        evidence_str = (
            f"Request Origin: {probe_origin} -> Response HTTP {response.status_code} "
            f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac or 'absent'}, "
            f"Access-Control-Allow-Methods: {acam or 'absent'}, Access-Control-Allow-Headers: {acah or 'absent'}"
        )

        # Case 1: Reflected arbitrary origin WITH credentials (Dangerous!)
        if is_reflected_origin and allows_credentials:
            val_status = (
                FindingValidationStatus.CONFIRMED.value
                if (has_sensitive_data or (insp.is_http_success and not insp.is_empty_payload))
                else FindingValidationStatus.SUSPICIOUS.value
            )
            sev = FindingSeverity.HIGH.value if has_sensitive_data else FindingSeverity.MEDIUM.value
            fnd = SecurityFindingRecord(
                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                target_url=req_meta["url"],
                endpoint=norm_path,
                method="GET",
                http_method="GET",
                testing_role=Role.ANONYMOUS.value,
                detection_category=DetectionCategory.CORS_MISCONFIGURATION.value,
                issue_code="CORS_CREDENTIALED_ORIGIN_REFLECTION",
                title=f"Dangerous Credentialed CORS Origin Reflection on {norm_path}",
                actual_response_evidence=evidence_str,
                sanitized_evidence=evidence_str,
                sanitized_request_metadata=req_meta,
                sanitized_response_metadata=resp_meta,
                relevant_headers_or_cookies=cors_details,
                response_hash=resp_hash,
                response_hashes={"comparison_sha256": resp_hash},
                severity=sev,
                severity_rationale=(
                    f"Endpoint '{norm_path}' reflects untrusted Origin '{probe_origin}' alongside "
                    f"'Access-Control-Allow-Credentials: true', permitting cross-origin credentialed reads."
                ),
                validation_status=val_status,
                confirmation_reason=f"Verified reflection of '{probe_origin}' in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
                what_is_wrong=f"The server dynamically reflects an arbitrary untrusted Origin ('{probe_origin}') in `Access-Control-Allow-Origin` while setting `Access-Control-Allow-Credentials: true`.",
                attacker_impact="A malicious website visited by an authenticated user can issue cross-origin `fetch(..., {credentials: 'include'})` requests and read private response data.",
                evidence_summary=evidence_str,
                exploitation_conditions="Victim must hold an active cookie/browser session and visit an attacker-controlled website.",
                remediation_guidance="Validate the `Origin` header against a strict, static server-side allowlist of trusted domains before setting `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`.",
                verification_steps=f"Send a request to '{norm_path}' with `Origin: https://untrusted-origin.example` and verify `Access-Control-Allow-Origin` does not reflect the untrusted origin.",
            )
            final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"CORS_CRED_REFLECT:{norm_path}")
            if is_dup:
                suppressed += 1
            elif final_fnd:
                findings.append(final_fnd)

        # Case 2: Null origin WITH credentials
        elif is_null_origin and allows_credentials:
            fnd = SecurityFindingRecord(
                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                target_url=req_meta["url"],
                endpoint=norm_path,
                method="GET",
                http_method="GET",
                testing_role=Role.ANONYMOUS.value,
                detection_category=DetectionCategory.CORS_MISCONFIGURATION.value,
                issue_code="CORS_CREDENTIALED_NULL_ORIGIN",
                title=f"Credentialed CORS Allows 'null' Origin on {norm_path}",
                actual_response_evidence=evidence_str,
                sanitized_evidence=evidence_str,
                sanitized_request_metadata=req_meta,
                sanitized_response_metadata=resp_meta,
                relevant_headers_or_cookies=cors_details,
                response_hash=resp_hash,
                response_hashes={"comparison_sha256": resp_hash},
                severity=FindingSeverity.HIGH.value if has_sensitive_data else FindingSeverity.MEDIUM.value,
                severity_rationale="Allowing 'Origin: null' with 'Access-Control-Allow-Credentials: true' permits sandboxed iframe cross-origin data theft.",
                validation_status=FindingValidationStatus.CONFIRMED.value,
                confirmation_reason="Verified `Access-Control-Allow-Origin: null` combined with `Access-Control-Allow-Credentials: true`.",
                what_is_wrong="The endpoint permits `Access-Control-Allow-Origin: null` together with `Access-Control-Allow-Credentials: true`.",
                attacker_impact="An attacker can use a sandboxed `<iframe>` (which sends `Origin: null`) to perform credentialed cross-origin requests and read the response.",
                evidence_summary=evidence_str,
                exploitation_conditions="Victim holds a valid session cookie and opens a page containing a malicious sandboxed iframe.",
                remediation_guidance="Never allow `null` in `Access-Control-Allow-Origin`. Enforce an explicit allowlist of trusted HTTPS origins.",
                verification_steps=f"Send a request with `Origin: null` to '{norm_path}' and confirm `Access-Control-Allow-Origin: null` is not returned.",
            )
            final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"CORS_NULL_CRED:{norm_path}")
            if is_dup:
                suppressed += 1
            elif final_fnd:
                findings.append(final_fnd)

        # Case 3: Wildcard '*' WITH credentials
        elif is_wildcard and allows_credentials:
            fnd = SecurityFindingRecord(
                finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                assessment_id=assessment_id,
                target_url=req_meta["url"],
                endpoint=norm_path,
                method="GET",
                http_method="GET",
                testing_role=Role.ANONYMOUS.value,
                detection_category=DetectionCategory.CORS_MISCONFIGURATION.value,
                issue_code="CORS_WILDCARD_WITH_CREDENTIALS",
                title=f"Misconfigured CORS Wildcard with Credentials on {norm_path}",
                actual_response_evidence=evidence_str,
                sanitized_evidence=evidence_str,
                sanitized_request_metadata=req_meta,
                sanitized_response_metadata=resp_meta,
                relevant_headers_or_cookies=cors_details,
                response_hash=resp_hash,
                response_hashes={"comparison_sha256": resp_hash},
                severity=FindingSeverity.LOW.value,
                severity_rationale="Server combines `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Browsers block this per Fetch specification, indicating a flawed CORS policy.",
                validation_status=FindingValidationStatus.CONFIRMED.value,
                confirmation_reason="Observed `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`.",
                what_is_wrong="The server sets both `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`.",
                attacker_impact="Standard browsers reject wildcard credentialed CORS responses, but the configuration indicates an unsafe attempt to enable global credentialed access.",
                evidence_summary=evidence_str,
                exploitation_conditions="Non-compliant user agents; blocked by standard WHATWG Fetch specification in modern browsers.",
                remediation_guidance="Replace wildcard `*` with an explicit allowlist of trusted origins if credentials are required, or remove `Access-Control-Allow-Credentials: true` for public endpoints.",
                verification_steps="Verify `Access-Control-Allow-Origin: *` is never paired with `Access-Control-Allow-Credentials: true`.",
                is_security_recommendation=True,
            )
            final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"CORS_WILDCARD_CRED:{norm_path}")
            if is_dup:
                suppressed += 1
            elif final_fnd:
                findings.append(final_fnd)

        # Case 4: Reflected origin WITHOUT credentials (Do not falsely claim exploitable!)
        elif is_reflected_origin and not allows_credentials:
            if has_sensitive_data:
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.CORS_MISCONFIGURATION.value,
                    issue_code="CORS_UNCREDENTIALED_ORIGIN_REFLECTION",
                    title=f"Permissive Uncredentialed CORS Origin Reflection on {norm_path}",
                    actual_response_evidence=evidence_str,
                    sanitized_evidence=evidence_str,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies=cors_details,
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.LOW.value,
                    severity_rationale=(
                        f"Endpoint reflects arbitrary Origin '{probe_origin}' without Access-Control-Allow-Credentials. "
                        f"Browsers will not send cookies automatically, so this is a hardening issue rather than direct credentialed exploitation."
                    ),
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason="Observed reflected Origin without Access-Control-Allow-Credentials.",
                    what_is_wrong=f"The endpoint reflects arbitrary `Origin` headers in `Access-Control-Allow-Origin` (`{acao}`), though `Access-Control-Allow-Credentials` is not enabled.",
                    attacker_impact="Cross-origin scripts can read unauthenticated responses from this endpoint, or if an application relies on IP/intranet-based trust.",
                    evidence_summary=evidence_str,
                    exploitation_conditions="Only exploitable if the endpoint exposes sensitive data without requiring cookies/Authorization headers.",
                    remediation_guidance="Restrict `Access-Control-Allow-Origin` to an explicit list of trusted origins.",
                    verification_steps=f"Send `Origin: {probe_origin}` to '{norm_path}' and verify the untrusted origin is not reflected.",
                    is_security_recommendation=True,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"CORS_UNCRED_REFLECT:{norm_path}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        overall_status = FindingValidationStatus.NOT_CONFIRMED.value
        if any(f.validation_status == FindingValidationStatus.CONFIRMED.value for f in findings):
            overall_status = FindingValidationStatus.CONFIRMED.value
        elif any(f.validation_status == FindingValidationStatus.SUSPICIOUS.value for f in findings):
            overall_status = FindingValidationStatus.SUSPICIOUS.value

        return CategoryInspectionResult(
            category=DetectionCategory.CORS_MISCONFIGURATION.value,
            target_url=req_meta["url"],
            endpoint=norm_path,
            status=overall_status,
            findings=findings,
            inspected_items=cors_details,
            suppressed_duplicates_count=suppressed,
            summary=f"CORS inspection on '{norm_path}' completed with status {overall_status} (ACAO={acao or 'none'}, ACAC={acac or 'none'}).",
        )

    # ==========================================================================
    # 5. HTTPS & TRANSPORT SECURITY
    # ==========================================================================

    def inspect_transport_security(
        self,
        target_url: Optional[str] = None,
        response: Optional[HttpResponseModel] = None,
        http_redirect_response: Optional[HttpResponseModel] = None,
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> CategoryInspectionResult:
        """Inspects HTTPS availability, HTTP-to-HTTPS redirection, HSTS, insecure cookies, and mixed content.

        Preserves normal TLS certificate validation (never disables certificate verification).
        Never performs MITM or downgrade attacks.
        """
        if self._is_cancelled(cancel_token, should_cancel):
            return CategoryInspectionResult(
                category=DetectionCategory.TRANSPORT_SECURITY.value,
                target_url=target_url or self.base_url,
                endpoint="/",
                status=FindingValidationStatus.NOT_TESTED.value,
                summary="Transport security inspection cancelled.",
            )

        effective_target = (target_url or self.base_url).strip()
        full_url, norm_path = self._resolve_url(effective_target, method="GET")
        parsed = urlsplit(full_url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        is_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        host_key = f"{scheme}://{parsed.netloc}"

        if response is None:
            self._apply_rate_limit()
            try:
                response = self.executor.send_request(role=Role.ANONYMOUS, method="GET", url=full_url)
            except TargetUnreachableError as exc:
                return CategoryInspectionResult(
                    category=DetectionCategory.TRANSPORT_SECURITY.value,
                    target_url=full_url,
                    endpoint=norm_path,
                    status=FindingValidationStatus.INCONCLUSIVE.value,
                    inspected_items={"tls_verified": False, "error": str(exc)},
                    summary=f"Transport connection or TLS certificate validation failed ({exc}). Certificate verification was preserved.",
                )

        req_meta, resp_meta, resp_hash = self._build_request_response_meta(full_url, "GET", Role.ANONYMOUS, response)
        headers_lower = {k.lower(): v.strip() for k, v in (response.headers or {}).items()}
        hsts = headers_lower.get("strict-transport-security", "")
        location = headers_lower.get("location", "")

        findings: List[SecurityFindingRecord] = []
        suppressed = 0
        transport_info: Dict[str, Any] = {
            "scheme": scheme,
            "hostname": hostname,
            "is_loopback": is_loopback,
            "status_code": response.status_code,
            "hsts_present": bool(hsts),
            "hsts_value": hsts or None,
            "tls_certificate_verification_preserved": True,
        }

        if scheme == "https":
            transport_info["https_available"] = True

            # 5A: Check HSTS on HTTPS target
            if not hsts:
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.TRANSPORT_SECURITY.value,
                    issue_code="TRANSPORT_MISSING_HSTS",
                    title=f"HTTPS Target Missing Strict-Transport-Security (HSTS) on {host_key}",
                    actual_response_evidence=f"HTTPS {response.status_code} response headers omitted Strict-Transport-Security.",
                    sanitized_evidence=f"HTTPS {response.status_code} response headers omitted Strict-Transport-Security.",
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"strict-transport-security": None, "scheme": "https"},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.LOW.value,
                    severity_rationale="HTTPS endpoint does not send Strict-Transport-Security, allowing initial cleartext HTTP connections to be intercepted.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason="Verified absence of Strict-Transport-Security header on HTTPS response.",
                    what_is_wrong="The HTTPS server does not return a `Strict-Transport-Security` header.",
                    attacker_impact="Users typing the domain without `https://` can be intercepted via SSL stripping before being redirected to HTTPS.",
                    evidence_summary=f"GET {req_meta['url']} returned HTTP {response.status_code} over HTTPS with no Strict-Transport-Security header.",
                    exploitation_conditions="Victim connects from an untrusted network and initiates an unencrypted HTTP navigation.",
                    remediation_guidance="Configure `Strict-Transport-Security: max-age=31536000; includeSubDomains` on the HTTPS server.",
                    verification_steps=f"Request '{req_meta['url']}' over HTTPS and verify `Strict-Transport-Security` is present with `max-age>=31536000`.",
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"TRANSPORT_HSTS:{host_key}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

            # 5B: Check insecure cookie transmission over HTTPS
            raw_cookies = [v for k, v in (response.headers or {}).items() if k.lower() == "set-cookie"]
            for cookie in self.parse_set_cookie_headers(raw_cookies):
                if not cookie.secure:
                    fnd = SecurityFindingRecord(
                        finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                        assessment_id=assessment_id,
                        target_url=req_meta["url"],
                        endpoint=norm_path,
                        method="GET",
                        http_method="GET",
                        testing_role=Role.ANONYMOUS.value,
                        detection_category=DetectionCategory.TRANSPORT_SECURITY.value,
                        issue_code="TRANSPORT_INSECURE_COOKIE_TRANSMISSION",
                        title=f"Cookie '{cookie.name}' Transmitted Over HTTPS Without Secure Flag",
                        actual_response_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                        sanitized_evidence=f"Set-Cookie: {cookie.sanitized_header}",
                        sanitized_request_metadata=req_meta,
                        sanitized_response_metadata=resp_meta,
                        relevant_headers_or_cookies={"cookie": cookie.model_dump()},
                        response_hash=resp_hash,
                        response_hashes={"comparison_sha256": resp_hash},
                        severity=FindingSeverity.MEDIUM.value if cookie.is_session_cookie else FindingSeverity.LOW.value,
                        severity_rationale=f"Cookie '{cookie.name}' is set over HTTPS without the 'Secure' attribute, permitting cleartext HTTP leakage.",
                        validation_status=FindingValidationStatus.CONFIRMED.value,
                        confirmation_reason=f"Verified Set-Cookie header for '{cookie.name}' on HTTPS response lacks 'Secure'.",
                        what_is_wrong=f"Cookie '{cookie.name}' on an HTTPS response does not specify the `Secure` attribute.",
                        attacker_impact="The browser will attach this cookie to unencrypted HTTP requests to the same domain, exposing it in transit.",
                        evidence_summary=f"Set-Cookie: {cookie.sanitized_header}",
                        exploitation_conditions="Victim triggers an unencrypted HTTP request to the domain.",
                        remediation_guidance=f"Append `; Secure` to the `Set-Cookie` directive for '{cookie.name}'.",
                        verification_steps=f"Confirm `Set-Cookie` for '{cookie.name}' includes `Secure`.",
                    )
                    final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"TRANSPORT_COOKIE:{host_key}:{cookie.name}")
                    if is_dup:
                        suppressed += 1
                    elif final_fnd:
                        findings.append(final_fnd)

            # 5C: Check observable mixed content references in HTTPS HTML body
            mixed_matches = MIXED_CONTENT_REGEX.findall(response.body or "")
            if mixed_matches:
                sample_refs = sorted(set(mixed_matches))[:5]
                transport_info["mixed_content_references"] = sample_refs
                evidence_str = f"HTTPS page '{norm_path}' contains insecure http:// subresource/form reference(s): {sample_refs}"
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.TRANSPORT_SECURITY.value,
                    issue_code="TRANSPORT_MIXED_CONTENT",
                    title=f"Mixed Content (Insecure HTTP References) on HTTPS Page {norm_path}",
                    actual_response_evidence=evidence_str,
                    sanitized_evidence=evidence_str,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies={"mixed_content_urls": sample_refs},
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=FindingSeverity.MEDIUM.value,
                    severity_rationale="HTTPS document references cleartext http:// resources or form targets, weakening transport confidentiality/integrity.",
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=f"Verified presence of insecure http:// resource attributes {sample_refs} inside HTTPS response body.",
                    what_is_wrong=f"The HTTPS page '{norm_path}' embeds insecure `http://` references: {sample_refs}.",
                    attacker_impact="Active mixed content (scripts/iframes) or insecure form actions can be intercepted or modified over the network.",
                    evidence_summary=evidence_str,
                    exploitation_conditions="Victim loads the page over a network where cleartext HTTP subrequests can be observed or tampered with.",
                    remediation_guidance="Update all subresource URLs and form actions to use `https://` and add `Content-Security-Policy: upgrade-insecure-requests`.",
                    verification_steps=f"Inspect the HTML source of '{norm_path}' and confirm zero `http://` script, iframe, form, or stylesheet references remain.",
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"TRANSPORT_MIXED:{norm_path}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

            # 5D: Check HTTP-to-HTTPS redirection if http_redirect_response provided or in scope
            if http_redirect_response is not None:
                redir_loc = (http_redirect_response.headers.get("location") or http_redirect_response.headers.get("Location") or "")
                is_https_redir = http_redirect_response.status_code in (301, 302, 307, 308) and redir_loc.lower().startswith("https://")
                transport_info["http_to_https_redirect"] = is_https_redir
                if not is_https_redir:
                    evidence_str = f"Plain HTTP request returned status {http_redirect_response.status_code} (Location: '{redir_loc or 'none'}') instead of redirecting to HTTPS."
                    fnd = SecurityFindingRecord(
                        finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                        assessment_id=assessment_id,
                        target_url=req_meta["url"],
                        endpoint=norm_path,
                        method="GET",
                        http_method="GET",
                        testing_role=Role.ANONYMOUS.value,
                        detection_category=DetectionCategory.TRANSPORT_SECURITY.value,
                        issue_code="TRANSPORT_MISSING_HTTPS_REDIRECT",
                        title=f"HTTP Listener Does Not Redirect to HTTPS on {hostname}",
                        actual_response_evidence=evidence_str,
                        sanitized_evidence=evidence_str,
                        sanitized_request_metadata=req_meta,
                        sanitized_response_metadata=resp_meta,
                        relevant_headers_or_cookies={"http_status": http_redirect_response.status_code, "location": redir_loc},
                        response_hash=resp_hash,
                        response_hashes={"comparison_sha256": resp_hash},
                        severity=FindingSeverity.LOW.value if is_loopback else FindingSeverity.MEDIUM.value,
                        severity_rationale="Plain HTTP requests are served directly instead of issuing a 301/308 redirect to HTTPS.",
                        validation_status=FindingValidationStatus.CONFIRMED.value,
                        confirmation_reason=evidence_str,
                        what_is_wrong="The HTTP endpoint serves content directly over cleartext HTTP rather than redirecting to `https://`.",
                        attacker_impact="Initial user requests over HTTP remain unencrypted, exposing traffic on untrusted networks.",
                        evidence_summary=evidence_str,
                        exploitation_conditions="User accesses the service via an `http://` URL.",
                        remediation_guidance="Configure the web server or reverse proxy to return `HTTP 301 Moved Permanently` (or `308`) redirecting all `http://` requests to `https://`.",
                        verification_steps="Send a GET request over `http://` with redirects disabled and verify an HTTP 301/308 response with `Location: https://...`.",
                    )
                    final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"TRANSPORT_NO_REDIR:{hostname}")
                    if is_dup:
                        suppressed += 1
                    elif final_fnd:
                        findings.append(final_fnd)

        else:
            # Target URL is plain http://
            is_redirecting_to_https = response.status_code in (301, 302, 307, 308) and location.lower().startswith("https://")
            transport_info["http_to_https_redirect"] = is_redirecting_to_https
            transport_info["https_probe_status"] = (
                "AVAILABLE_VIA_REDIRECT"
                if is_redirecting_to_https
                else ("NOT_TESTED" if "https" not in self.scope_guard.allowed_schemes else "UNCONFIGURED")
            )

            if not is_redirecting_to_https:
                sev = FindingSeverity.INFORMATIONAL.value if is_loopback else FindingSeverity.MEDIUM.value
                app_note = (
                    "Target is running on local loopback (localhost/127.0.0.1) over plain HTTP, which is common in local test environments. "
                    "In production deployments, enforce HTTPS TLS encryption and HTTP-to-HTTPS redirection."
                    if is_loopback
                    else None
                )
                evidence_str = f"GET {req_meta['url']} served HTTP {response.status_code} directly over unencrypted HTTP without redirecting to HTTPS."
                fnd = SecurityFindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    assessment_id=assessment_id,
                    target_url=req_meta["url"],
                    endpoint=norm_path,
                    method="GET",
                    http_method="GET",
                    testing_role=Role.ANONYMOUS.value,
                    detection_category=DetectionCategory.TRANSPORT_SECURITY.value,
                    issue_code="TRANSPORT_CLEARTEXT_HTTP",
                    title=f"Application Served Over Unencrypted HTTP ({host_key})",
                    actual_response_evidence=evidence_str,
                    sanitized_evidence=evidence_str,
                    sanitized_request_metadata=req_meta,
                    sanitized_response_metadata=resp_meta,
                    relevant_headers_or_cookies=transport_info,
                    response_hash=resp_hash,
                    response_hashes={"comparison_sha256": resp_hash},
                    severity=sev,
                    severity_rationale=(
                        "Local development target is served over plain HTTP (informational production readiness note)."
                        if is_loopback
                        else "Remote target serves application responses over unencrypted HTTP without HTTPS redirection."
                    ),
                    validation_status=FindingValidationStatus.CONFIRMED.value,
                    confirmation_reason=evidence_str,
                    what_is_wrong=f"The application at '{host_key}' serves HTTP {response.status_code} responses over unencrypted HTTP.",
                    attacker_impact="Traffic transmitted over non-loopback HTTP networks can be passively eavesdropped or modified in transit.",
                    evidence_summary=evidence_str,
                    exploitation_conditions="Network traffic traverses an untrusted network segment (not applicable to isolated localhost loopback).",
                    remediation_guidance="Terminate TLS (HTTPS) at the reverse proxy or application server, redirect all HTTP traffic to HTTPS (301/308), and enable HSTS.",
                    verification_steps="Verify that `http://` requests return HTTP 301/308 to `https://` and that `https://` presents a valid TLS certificate.",
                    is_security_recommendation=is_loopback,
                    applicability_note=app_note,
                )
                final_fnd, is_dup = self._finalize_and_deduplicate_finding(fnd, f"TRANSPORT_CLEARTEXT:{host_key}")
                if is_dup:
                    suppressed += 1
                elif final_fnd:
                    findings.append(final_fnd)

        overall_status = (
            FindingValidationStatus.CONFIRMED.value
            if findings
            else FindingValidationStatus.NOT_CONFIRMED.value
        )
        return CategoryInspectionResult(
            category=DetectionCategory.TRANSPORT_SECURITY.value,
            target_url=req_meta["url"],
            endpoint=norm_path,
            status=overall_status,
            findings=findings,
            inspected_items=transport_info,
            suppressed_duplicates_count=suppressed,
            summary=f"Transport security inspection on '{req_meta['url']}' completed with status {overall_status} ({len(findings)} finding(s)).",
        )

    # ==========================================================================
    # Comprehensive Multi-Category Scan
    # ==========================================================================

    def run_comprehensive_inspection(
        self,
        endpoint: str = "/",
        assessment_id: str = "default_assessment",
        cancel_token: Optional[Any] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Executes all 5 Sprint 2 detection categories on an endpoint with automatic deduplication."""
        auth_res = self.inspect_authentication_weaknesses(
            endpoint=endpoint,
            assessment_id=assessment_id,
            cancel_token=cancel_token,
            should_cancel=should_cancel,
        )
        sess_res = self.inspect_session_security(
            endpoint=endpoint,
            assessment_id=assessment_id,
            cancel_token=cancel_token,
            should_cancel=should_cancel,
        )
        hdr_res = self.inspect_security_headers(
            endpoint=endpoint,
            assessment_id=assessment_id,
            cancel_token=cancel_token,
            should_cancel=should_cancel,
        )
        cors_res = self.inspect_cors_configuration(
            endpoint=endpoint,
            assessment_id=assessment_id,
            cancel_token=cancel_token,
            should_cancel=should_cancel,
        )
        trans_res = self.inspect_transport_security(
            target_url=endpoint,
            assessment_id=assessment_id,
            cancel_token=cancel_token,
            should_cancel=should_cancel,
        )

        all_findings: List[SecurityFindingRecord] = (
            auth_res.findings
            + sess_res.findings
            + hdr_res.findings
            + cors_res.findings
            + trans_res.findings
        )
        total_suppressed = (
            auth_res.suppressed_duplicates_count
            + sess_res.suppressed_duplicates_count
            + hdr_res.suppressed_duplicates_count
            + cors_res.suppressed_duplicates_count
            + trans_res.suppressed_duplicates_count
        )

        return {
            "assessment_id": assessment_id,
            "endpoint": endpoint,
            "total_findings": len(all_findings),
            "suppressed_duplicates_count": total_suppressed,
            "categories": {
                DetectionCategory.AUTHENTICATION_WEAKNESS.value: auth_res.model_dump(),
                DetectionCategory.SESSION_SECURITY.value: sess_res.model_dump(),
                DetectionCategory.SECURITY_HEADERS.value: hdr_res.model_dump(),
                DetectionCategory.CORS_MISCONFIGURATION.value: cors_res.model_dump(),
                DetectionCategory.TRANSPORT_SECURITY.value: trans_res.model_dump(),
            },
            "findings": [f.model_dump() for f in all_findings],
        }

