"""Website Assessment Tools for AuthScope Tool Registry.

Enforces:
- ScopeGuard allowlist checking on all URLs.
- Safe non-destructive HTTP inspections (GET/HEAD only).
- Endpoint discovery without crawling unauthorized external domains.
- Response structure analysis.
"""

from typing import Dict, Any, Optional
import time

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.scanner.endpoint_discovery import EndpointDiscovery
from backend.scanner.request_executor import RequestExecutor
from backend.scanner.response_analyzer import ResponseAnalyzer, AccessVerdict
from backend.scanner.security_inspector import SecurityInspector
from backend.tools.schemas import (
    AnalyzeResponseInput,
    AnalyzeResponseOutput,
    CheckAuthWeaknessesInput,
    CheckAuthWeaknessesOutput,
    CheckCorsInput,
    CheckCorsOutput,
    CheckHttpMethodsInput,
    CheckHttpMethodsOutput,
    CheckSecurityHeadersInput,
    CheckSecurityHeadersOutput,
    CheckSessionSecurityInput,
    CheckSessionSecurityOutput,
    CheckTransportSecurityInput,
    CheckTransportSecurityOutput,
    DiscoverEndpointsInput,
    DiscoverEndpointsOutput,
    DiscoveredEndpointSummary,
    InspectEndpointInput,
    InspectEndpointOutput,
    RunMisconfigurationScanInput,
    RunMisconfigurationScanOutput,
    ToolExecutionContext,
    ValidateTargetInput,
    ValidateTargetOutput,
)
from backend.utils.helpers import InvalidTargetURLError, ScopeViolationError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class WebsiteTools:
    """Provides website assessment tools backed by ScopeGuard, EndpointDiscovery, and RequestExecutor."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        executor: Optional[RequestExecutor] = None,
        discovery: Optional[EndpointDiscovery] = None,
        analyzer: Optional[ResponseAnalyzer] = None
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.executor = executor or RequestExecutor(scope_guard=self.scope_guard)
        self.discovery = discovery or EndpointDiscovery(scope_guard=self.scope_guard)
        self.analyzer = analyzer or ResponseAnalyzer()
        self.inspector = SecurityInspector(executor=self.executor, scope_guard=self.scope_guard)

    def validate_target(
        self,
        payload: ValidateTargetInput,
        context: Optional[ToolExecutionContext] = None
    ) -> ValidateTargetOutput:
        """Verifies whether a given URL is strictly within the authorized target allowlist."""
        result = self.scope_guard.validate_url(payload.url)
        return ValidateTargetOutput(
            url=payload.url,
            is_allowed=result.is_allowed,
            reason=result.reason,
            host=result.normalized_host,
            port=result.normalized_port,
            normalized_url=result.target_url
        )

    def discover_endpoints(
        self,
        payload: DiscoverEndpointsInput,
        context: Optional[ToolExecutionContext] = None
    ) -> DiscoverEndpointsOutput:
        """Discovers authorized application endpoints and attack surface routes."""
        base_url = payload.base_url or settings.target_base_url
        self.scope_guard.assert_in_scope(base_url, method="GET")

        # Discover endpoints using existing EndpointDiscovery
        endpoints = self.discovery.discover_known_routes()
        summaries = [
            DiscoveredEndpointSummary(
                path=ep.path,
                method=ep.method,
                category=ep.category.value if hasattr(ep.category, "value") else str(ep.category),
                resource_type=ep.resource_type,
                requires_auth=ep.requires_auth,
                parameters=ep.parameters
            )
            for ep in endpoints
            if payload.include_admin or "admin" not in ep.path.lower()
        ]

        return DiscoverEndpointsOutput(
            base_url=base_url,
            endpoint_count=len(summaries),
            endpoints=summaries
        )

    def inspect_endpoint(
        self,
        payload: InspectEndpointInput,
        context: Optional[ToolExecutionContext] = None
    ) -> InspectEndpointOutput:
        """Safely executes a non-destructive GET/HEAD request to inspect status and headers."""
        norm_method = payload.method.strip().upper()
        if norm_method not in ("GET", "HEAD"):
            raise ScopeViolationError(
                f"Method '{norm_method}' is prohibited. Only GET and HEAD inspections are permitted."
            )

        target_url = payload.url
        if target_url.startswith("/"):
            target_url = f"{settings.target_base_url.rstrip('/')}{target_url}"

        # Scope validation is automatically performed by RequestExecutor
        start_time = time.time()
        resp = self.executor.send_request(
            method=norm_method,
            url=target_url,
            custom_headers=payload.headers
        )
        duration_ms = (time.time() - start_time) * 1000.0

        is_json = "application/json" in resp.headers.get("content-type", "").lower()
        body_snippet = resp.body[:1000] if resp.body else ""

        return InspectEndpointOutput(
            url=target_url,
            status_code=resp.status_code,
            headers=resp.headers,
            body_snippet=body_snippet,
            is_json=is_json,
            content_length=len(resp.body),
            duration_ms=round(duration_ms, 2)
        )

    def analyze_response(
        self,
        payload: AnalyzeResponseInput,
        context: Optional[ToolExecutionContext] = None
    ) -> AnalyzeResponseOutput:
        """Analyzes response status and body indicators to evaluate access behavior."""
        is_access_granted = 200 <= payload.status_code < 300
        is_error = payload.status_code >= 400
        reasons = []

        if payload.status_code in (401, 403):
            reasons.append(f"HTTP {payload.status_code} explicitly denies access.")
            verdict = "CORRECTLY_DENIED"
        elif 200 <= payload.status_code < 300:
            reasons.append(f"HTTP {payload.status_code} permits resource retrieval.")
            verdict = "ACCESS_GRANTED"
        else:
            reasons.append(f"HTTP {payload.status_code} unexpected response.")
            verdict = "AMBIGUOUS"

        # Check for error leaks in body
        indicates_leak = False
        lower_body = payload.body.lower()
        if any(leak in lower_body for leak in ("stack trace", "syntax error", "sql", "sqlite")):
            indicates_leak = True
            reasons.append("Response body indicates diagnostic information leak.")

        return AnalyzeResponseOutput(
            verdict=verdict,
            is_access_granted=is_access_granted,
            is_error=is_error,
            indicates_leak=indicates_leak,
            reasons=reasons
        )

    def check_http_methods(
        self,
        payload: CheckHttpMethodsInput,
        context: Optional[ToolExecutionContext] = None
    ) -> CheckHttpMethodsOutput:
        """Determines permitted methods for an endpoint strictly adhering to read-only policy."""
        self.scope_guard.assert_in_scope(payload.url, method="GET")
        # In AuthScope security boundary, GET and HEAD are permitted by default
        return CheckHttpMethodsOutput(
            url=payload.url,
            allowed_methods=["GET", "HEAD"],
            is_safe=True
        )

    def check_authentication_weaknesses(
        self,
        payload: CheckAuthWeaknessesInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> CheckAuthWeaknessesOutput:
        """Inspects endpoints for unauthenticated access, verbose error leaks, or auth inconsistencies."""
        result = self.inspector.inspect_authentication_weaknesses(
            endpoint=payload.endpoint,
            assessment_id=payload.assessment_id,
        )
        return CheckAuthWeaknessesOutput(
            category=result.category,
            target_url=result.target_url,
            endpoint=result.endpoint,
            status=result.status,
            findings=[(f.model_dump() if hasattr(f, 'model_dump') else f) for f in result.findings],
            inspected_items=result.inspected_items,
            suppressed_duplicates_count=result.suppressed_duplicates_count,
            summary=result.summary,
        )

    def check_session_security(
        self,
        payload: CheckSessionSecurityInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> CheckSessionSecurityOutput:
        """Inspects cookie flags (HttpOnly, Secure, SameSite, lifetime) and session token leakage."""
        result = self.inspector.inspect_session_security(
            endpoint=payload.endpoint,
            assessment_id=payload.assessment_id,
        )
        return CheckSessionSecurityOutput(
            category=result.category,
            target_url=result.target_url,
            endpoint=result.endpoint,
            status=result.status,
            findings=[(f.model_dump() if hasattr(f, 'model_dump') else f) for f in result.findings],
            inspected_items=result.inspected_items,
            suppressed_duplicates_count=result.suppressed_duplicates_count,
            summary=result.summary,
        )

    def check_security_headers(
        self,
        payload: CheckSecurityHeadersInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> CheckSecurityHeadersOutput:
        """Evaluates presence and adequacy of key HTTP security headers (CSP, HSTS, frame protection, etc.)."""
        result = self.inspector.inspect_security_headers(
            endpoint=payload.endpoint,
            assessment_id=payload.assessment_id,
        )
        return CheckSecurityHeadersOutput(
            category=result.category,
            target_url=result.target_url,
            endpoint=result.endpoint,
            status=result.status,
            findings=[(f.model_dump() if hasattr(f, 'model_dump') else f) for f in result.findings],
            inspected_items=result.inspected_items,
            suppressed_duplicates_count=result.suppressed_duplicates_count,
            summary=result.summary,
        )

    def check_cors_misconfiguration(
        self,
        payload: CheckCorsInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> CheckCorsOutput:
        """Evaluates Cross-Origin Resource Sharing headers for unsafe credentialed trust combinations."""
        result = self.inspector.inspect_cors_configuration(
            endpoint=payload.endpoint,
            probe_origin=payload.probe_origin,
            assessment_id=payload.assessment_id,
        )
        return CheckCorsOutput(
            category=result.category,
            target_url=result.target_url,
            endpoint=result.endpoint,
            status=result.status,
            findings=[(f.model_dump() if hasattr(f, 'model_dump') else f) for f in result.findings],
            inspected_items=result.inspected_items,
            suppressed_duplicates_count=result.suppressed_duplicates_count,
            summary=result.summary,
        )

    def check_transport_security(
        self,
        payload: CheckTransportSecurityInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> CheckTransportSecurityOutput:
        """Evaluates HTTPS availability, HTTP-to-HTTPS redirect, HSTS, and mixed content references."""
        result = self.inspector.inspect_transport_security(
            target_url=payload.target_url,
            assessment_id=payload.assessment_id,
        )
        return CheckTransportSecurityOutput(
            category=result.category,
            target_url=result.target_url,
            endpoint=result.endpoint,
            status=result.status,
            findings=[(f.model_dump() if hasattr(f, 'model_dump') else f) for f in result.findings],
            inspected_items=result.inspected_items,
            suppressed_duplicates_count=result.suppressed_duplicates_count,
            summary=result.summary,
        )

    def run_security_misconfiguration_scan(
        self,
        payload: RunMisconfigurationScanInput,
        context: Optional[ToolExecutionContext] = None,
    ) -> RunMisconfigurationScanOutput:
        """Runs comprehensive Sprint 2 defensive security checks on an endpoint."""
        data = self.inspector.run_comprehensive_inspection(
            endpoint=payload.endpoint,
            assessment_id=payload.assessment_id,
        )
        return RunMisconfigurationScanOutput(
            assessment_id=data["assessment_id"],
            endpoint=data["endpoint"],
            total_findings=data["total_findings"],
            suppressed_duplicates_count=data["suppressed_duplicates_count"],
            categories=data["categories"],
            findings=data["findings"],
        )
