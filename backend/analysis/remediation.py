"""Remediation Engine: Synthesizes developer-friendly code fixes and mitigation guidance.

Generates practical, technically sound, and framework-specific server-side
remediation guidance, implementation patches, retesting procedures, and
regression test recommendations for confirmed and suspected vulnerabilities.

Design Principles:
1. Defense-in-Depth: Recommends strict server-side controls; never client-side-only mitigations.
2. Evidence Relevance: Customizes recommendations to the specific endpoint, resource, and observed behavior.
3. Safe Non-Destructive Operation: Proposes code fixes without mutating running application code.
4. Dependency Injection: Supports injected AI clients with automatic fallback to deterministic patterns.
"""

from typing import Any, Dict, List, Optional, Protocol
import json
import re

from pydantic import BaseModel, ConfigDict, Field

from backend.agent.prompts import (
    SYSTEM_ANALYSIS_PROMPT,
    build_remediation_prompt,
)
from backend.agent.schemas import (
    AffectedResource,
    FindingAnalysis,
    RemediationRecommendation,
    SecurityEvidence,
    SeverityAssessment,
    VulnerabilityCategory,
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ==============================================================================
# AI Client Protocol for Dependency Injection
# ==============================================================================


class AIClientProtocol(Protocol):
    """Protocol for injected AI client to support unit testing with mock providers."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        ...


# ==============================================================================
# Detailed Remediation Plan Schema
# ==============================================================================


class DetailedRemediationPlan(BaseModel):
    """Comprehensive remediation package addressing an analyzed vulnerability."""

    model_config = ConfigDict(extra="forbid")

    problem_addressed: str = Field(..., min_length=5, description="Security vulnerability or logic flaw being addressed")
    recommended_fix: str = Field(..., min_length=10, description="High-level architectural fix description")
    technical_implementation_guidance: str = Field(..., min_length=15, description="Concrete developer code snippet and implementation steps")
    root_cause_correction: str = Field(..., min_length=10, description="Explanation of how the fix corrects the underlying defect")
    additional_security_controls: List[str] = Field(default_factory=list, description="Defense-in-depth controls (e.g. rate limiting, audit logging)")
    why_fix_works: str = Field(..., min_length=10, description="Technical explanation of the protection mechanism")
    retesting_procedure: str = Field(..., min_length=10, description="Step-by-step retesting instructions for verification")
    expected_secure_behavior: str = Field(..., min_length=5, description="Expected HTTP response status and behavior after fix")
    regression_test_suggestions: List[str] = Field(default_factory=list, description="Unit and integration tests to prevent regression")
    target_framework: str = Field(default="express", description="Target application framework")

    def to_remediation_recommendation(self) -> RemediationRecommendation:
        """Converts to the standard RemediationRecommendation contract."""
        controls = list(self.additional_security_controls)
        if not controls:
            controls = ["ServerSideAuthorizationMiddleware"]

        return RemediationRecommendation(
            recommended_fix=self.recommended_fix,
            technical_implementation_guidance=self.technical_implementation_guidance,
            server_side_controls=controls,
            why_fix_works=self.why_fix_works,
            retesting_procedure=self.retesting_procedure,
            regression_testing_recommendations=self.regression_test_suggestions,
        )


# ==============================================================================
# Remediation Engine Implementation
# ==============================================================================


class RemediationEngine:
    """Generates concrete code patches and security guidance for authorization flaws."""

    def __init__(self, ai_client: Optional[AIClientProtocol] = None):
        """Initializes the remediation engine with optional injected AI client.

        Args:
            ai_client: Optional AI client implementing `complete()`.
        """
        self.ai_client = ai_client

    # --------------------------------------------------------------------------
    # Primary Remediation Entry Point
    # --------------------------------------------------------------------------

    def generate_remediation(
        self,
        analysis: FindingAnalysis,
        severity: Optional[SeverityAssessment] = None,
        evidence: Optional[List[SecurityEvidence]] = None,
        resource: Optional[AffectedResource] = None,
        target_framework: str = "express",
    ) -> DetailedRemediationPlan:
        """Generates a detailed, evidence-grounded remediation plan.

        Args:
            analysis: Validated FindingAnalysis model.
            severity: Optional SeverityAssessment model.
            evidence: Optional list of SecurityEvidence artifacts.
            resource: Optional AffectedResource model.
            target_framework: Framework name (e.g., 'express', 'fastapi', 'spring').

        Returns:
            DetailedRemediationPlan with concrete implementation snippets.
        """
        evidence_list = evidence or analysis.supporting_evidence
        target_res = resource or (analysis.affected_resources[0] if analysis.affected_resources else None)
        endpoint = target_res.endpoint if target_res else "/unknown"
        norm_framework = self._normalize_framework(target_framework)

        logger.info(
            "Generating targeted remediation plan",
            extra={
                "endpoint": endpoint,
                "framework": norm_framework,
                "title": analysis.title,
            },
        )

        # If AI client is injected, attempt structured AI generation
        if self.ai_client is not None:
            ai_plan = self._generate_with_ai(
                analysis=analysis,
                endpoint=endpoint,
                evidence_list=evidence_list,
                target_framework=norm_framework,
            )
            if ai_plan is not None:
                return ai_plan

        # Deterministic generation fallback
        return self._generate_deterministic_plan(
            analysis=analysis,
            endpoint=endpoint,
            target_res=target_res,
            evidence_list=evidence_list,
            framework=norm_framework,
        )

    # --------------------------------------------------------------------------
    # Backward Compatibility Adapter
    # --------------------------------------------------------------------------

    def generate_patch(self, vulnerability_type: str, framework: str = "express") -> str:
        """Legacy helper generating framework-specific authorization check templates."""
        logger.info("Generating remediation patch", extra={"type": vulnerability_type, "framework": framework})
        norm_framework = self._normalize_framework(framework)

        if "BOLA" in vulnerability_type.upper() or "IDOR" in vulnerability_type.upper():
            return self._build_bola_code_snippet(endpoint="/rest/basket/:id", framework=norm_framework)
        if "BFLA" in vulnerability_type.upper():
            return self._build_bfla_code_snippet(endpoint="/rest/admin/*", framework=norm_framework)
        if "AUTH" in vulnerability_type.upper():
            return self._build_auth_code_snippet(endpoint="/api/protected", framework=norm_framework)

        return self._build_generic_rbac_snippet(framework=norm_framework)

    # --------------------------------------------------------------------------
    # Deterministic Remediation Builders
    # --------------------------------------------------------------------------

    def _generate_deterministic_plan(
        self,
        analysis: FindingAnalysis,
        endpoint: str,
        target_res: Optional[AffectedResource],
        evidence_list: List[SecurityEvidence],
        framework: str,
    ) -> DetailedRemediationPlan:
        """Generates a complete remediation plan deterministically based on vulnerability class."""
        title = analysis.title.lower()
        root_cause = analysis.technical_root_cause

        # 1. Broken Object Level Authorization (BOLA / IDOR)
        if "idor" in title or "bola" in title or "object level" in title:
            return self._plan_bola_remediation(endpoint, target_res, root_cause, framework)

        # 2. Broken Function Level Authorization (BFLA) / Administrative Bypass
        if "bfla" in title or "function level" in title or "admin" in endpoint.lower():
            return self._plan_bfla_remediation(endpoint, target_res, root_cause, framework)

        # 3. Missing Authentication / Unauthenticated Access
        if "missing auth" in title or "authentication" in title or "unauthenticated" in root_cause.lower():
            return self._plan_missing_auth_remediation(endpoint, target_res, root_cause, framework)

        # 4. Privilege Escalation / Role Tampering
        if "privilege" in title or "escalation" in title:
            return self._plan_privilege_escalation_remediation(endpoint, target_res, root_cause, framework)

        # 5. Information Disclosure
        if "information disclosure" in title or "leak" in title:
            return self._plan_info_disclosure_remediation(endpoint, target_res, root_cause, framework)

        # 6. Default Fallback: Broken Access Control
        return self._plan_general_access_control_remediation(endpoint, target_res, root_cause, framework)

    def _plan_bola_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        res_id = resource.resource_id if resource else "resource"
        owner = resource.owner_identity if resource else "authorized user"
        code_snippet = self._build_bola_code_snippet(endpoint, framework)

        return DetailedRemediationPlan(
            problem_addressed=f"Broken Object Level Authorization (BOLA/IDOR) on {endpoint}",
            recommended_fix=(
                f"Enforce strict server-side resource ownership verification on {endpoint}. "
                f"Assert that the authenticated session identity matches the entity's owner before retrieving or modifying it."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=(
                f"Resolves the root cause: {root_cause}. Specifically eliminates reliance on client-provided "
                f"path/query identifiers without database ownership checks."
            ),
            additional_security_controls=[
                "ResourceOwnershipMiddleware",
                "AuditLoggingForUnauthorizedAccess",
                "RateLimitingPerAccount",
                "DenyByDefaultAccessPolicy",
            ],
            why_fix_works=(
                f"The server queries the entity from the persistence layer and asserts that the session caller's "
                f"identity matches the record's owner ({owner}). If mismatched, the request is rejected immediately "
                f"with HTTP 403 Forbidden before entity data is leaked."
            ),
            retesting_procedure=(
                f"1. Authenticate as a non-owner test persona (e.g. User B).\n"
                f"2. Issue a request targeting resource '{res_id}' owned by User A on {endpoint}.\n"
                f"3. Verify that the response status code is strictly 403 Forbidden with an Access Denied error payload."
            ),
            expected_secure_behavior="HTTP 403 Forbidden with error JSON: {'error': 'Access Denied: Resource belongs to another user'}.",
            regression_test_suggestions=[
                f"Unit test: Assert non-owner request to {endpoint} returns 403.",
                f"Unit test: Assert legitimate owner request to {endpoint} succeeds with 200.",
                "Integration test: Cross-tenant differential matrix assertion across User A and User B in CI pipeline.",
            ],
            target_framework=framework,
        )

    def _plan_bfla_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        code_snippet = self._build_bfla_code_snippet(endpoint, framework)

        return DetailedRemediationPlan(
            problem_addressed=f"Broken Function Level Authorization (BFLA) on restricted route {endpoint}",
            recommended_fix=(
                f"Implement centralized role-based access control (RBAC) middleware on {endpoint}. "
                f"Enforce that only authenticated sessions possessing verified administrative privileges can access this route."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=(
                f"Corrects: {root_cause}. Restricts administrative function execution exclusively to verified admin role claims."
            ),
            additional_security_controls=[
                "RequireAdminRoleMiddleware",
                "SecurityTelemetryAlerting",
                "AdministrativeSessionRe-authentication",
                "StrictMethodWhitelisting",
            ],
            why_fix_works=(
                "Intercepts requests at the router/controller gateway before executing administrative operations, "
                "evaluating the cryptographically signed JWT role claims and rejecting standard or anonymous users with 403."
            ),
            retesting_procedure=(
                f"1. Authenticate as standard low-privilege User A.\n"
                f"2. Send HTTP request to administrative endpoint {endpoint}.\n"
                f"3. Verify response status is 403 Forbidden.\n"
                f"4. Send unauthenticated request; verify status is 401 Unauthorized."
            ),
            expected_secure_behavior="HTTP 403 Forbidden for non-admin accounts; administrative state unchanged.",
            regression_test_suggestions=[
                f"Automated test: Standard role accessing {endpoint} returns 403.",
                f"Automated test: Anonymous user accessing {endpoint} returns 401.",
                "Security regression test: Role claim tampering verification.",
            ],
            target_framework=framework,
        )

    def _plan_missing_auth_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        code_snippet = self._build_auth_code_snippet(endpoint, framework)

        return DetailedRemediationPlan(
            problem_addressed=f"Missing Authentication on sensitive endpoint {endpoint}",
            recommended_fix=(
                f"Attach authentication guard middleware to {endpoint} requiring a valid, "
                f"unexpired cryptographically signed session token on all incoming requests."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=(
                f"Eliminates unauthenticated access flaw: {root_cause} by placing a mandatory authentication barrier."
            ),
            additional_security_controls=[
                "JWTAuthenticationMiddleware",
                "TokenRevocationFilter",
                "AntiBruteForceRateLimiter",
                "StrictCORSConfiguration",
            ],
            why_fix_works=(
                "Validates Bearer token signature, expiry, and issuer before the handler executes. "
                "Requests lacking valid tokens are halted at the middleware perimeter with HTTP 401."
            ),
            retesting_procedure=(
                f"1. Send HTTP request to {endpoint} with no Authorization header.\n"
                f"2. Assert response status is 401 Unauthorized.\n"
                f"3. Send HTTP request with invalid/expired token; assert 401 Unauthorized."
            ),
            expected_secure_behavior="HTTP 401 Unauthorized with WWW-Authenticate header.",
            regression_test_suggestions=[
                f"Unit test: {endpoint} rejects unauthenticated calls with 401.",
                "Integration test: Token expiration and signature tampering test.",
            ],
            target_framework=framework,
        )

    def _plan_privilege_escalation_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        code_snippet = (
            "// Node.js / Express: Protect role assignment and profile state updates\n"
            "router.put('/api/Users/:id', verifyAuth, async (req, res) => {\n"
            "  const allowedFields = ['email', 'username']; // Whitelist permitted fields\n"
            "  const updates = {};\n"
            "  for (const key of allowedFields) {\n"
            "    if (req.body[key] !== undefined) updates[key] = req.body[key];\n"
            "  }\n"
            "  if (req.body.role || req.body.isAdmin) {\n"
            "    return res.status(403).json({ error: 'Cannot modify role parameters' });\n"
            "  }\n"
            "  await UserModel.update(updates, { where: { id: req.user.id } });\n"
            "  res.json({ status: 'success' });\n"
            "});"
        )

        return DetailedRemediationPlan(
            problem_addressed=f"Privilege Escalation / Mass Assignment vulnerability on {endpoint}",
            recommended_fix=(
                "Implement strict schema-based input whitelisting and enforce server-controlled role assignments. "
                "Prevent mass assignment of privileged attributes (e.g. role, isAdmin)."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=f"Corrects: {root_cause}. Prohibits client-controlled privilege mutations.",
            additional_security_controls=[
                "InputDTOValidationMiddleware",
                "ImmutableRoleEnforcement",
                "PrivilegeMutationAuditLog",
            ],
            why_fix_works="Strips or rejects unauthorized privilege attributes before persistence in the database.",
            retesting_procedure=(
                "1. Authenticate as standard User A.\n"
                f"2. Submit request to {endpoint} containing {{ 'role': 'admin' }}.\n"
                "3. Assert server returns 403 Forbidden or 400 Bad Request, and role remains unchanged."
            ),
            expected_secure_behavior="HTTP 403 Forbidden or 400 Bad Request; privilege attribute rejected.",
            regression_test_suggestions=[
                "Unit test: User cannot promote self to admin via profile update.",
            ],
            target_framework=framework,
        )

    def _plan_info_disclosure_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        code_snippet = (
            "// Data minimization & response DTO sanitization\n"
            "const user = await UserModel.findByPk(req.user.id);\n"
            "// Explicitly project only public attributes\n"
            "const sanitizedUser = {\n"
            "  id: user.id,\n"
            "  username: user.username,\n"
            "  createdAt: user.createdAt\n"
            "};\n"
            "return res.json({ user: sanitizedUser });"
        )

        return DetailedRemediationPlan(
            problem_addressed=f"Sensitive Information Disclosure on {endpoint}",
            recommended_fix=(
                "Implement response data minimization and DTO projection to filter out sensitive internal fields "
                "(passwords, tokens, internal IDs, system metrics)."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=f"Remediates: {root_cause}. Restricts response payloads to safe public schemas.",
            additional_security_controls=[
                "ResponseSanitizationFilter",
                "ProductionStackTraceSuppression",
            ],
            why_fix_works="Prevents raw database entities from being serialized directly to HTTP response bodies.",
            retesting_procedure=(
                f"1. Query {endpoint} with valid session.\n"
                "2. Assert response body does not contain sensitive attributes (passwordHash, secretKey, stack)."
            ),
            expected_secure_behavior="HTTP 200 containing sanitized projection attributes only.",
            regression_test_suggestions=[
                "Unit test: Assert sensitive fields are absent from response JSON.",
            ],
            target_framework=framework,
        )

    def _plan_general_access_control_remediation(
        self,
        endpoint: str,
        resource: Optional[AffectedResource],
        root_cause: str,
        framework: str,
    ) -> DetailedRemediationPlan:
        code_snippet = self._build_generic_rbac_snippet(framework)

        return DetailedRemediationPlan(
            problem_addressed=f"Broken Access Control on {endpoint}",
            recommended_fix=(
                f"Enforce server-side authorization checks and deny-by-default access control on {endpoint}."
            ),
            technical_implementation_guidance=code_snippet,
            root_cause_correction=f"Corrects: {root_cause}. Enforces authorization validation prior to route execution.",
            additional_security_controls=[
                "ServerSideAuthorizationFilter",
                "CentralizedAccessDecisionPoint",
            ],
            why_fix_works="Denies access by default unless explicit permission claims are validated on the server.",
            retesting_procedure=(
                f"1. Issue request to {endpoint} using unauthorized credentials.\n"
                "2. Assert response is 403 Forbidden."
            ),
            expected_secure_behavior="HTTP 403 Forbidden for unauthorized requests.",
            regression_test_suggestions=[
                f"Unit test: Verify access is denied to non-permitted roles on {endpoint}.",
            ],
            target_framework=framework,
        )

    # --------------------------------------------------------------------------
    # Framework-Specific Code Snippet Generators
    # --------------------------------------------------------------------------

    def _build_bola_code_snippet(self, endpoint: str, framework: str) -> str:
        if framework in ("fastapi", "python"):
            return (
                "# FastAPI / Python: Server-side ownership verification\n"
                "from fastapi import APIRouter, Depends, HTTPException, status\n\n"
                f"@router.get('{endpoint}')\n"
                "async def get_basket(basket_id: int, current_user: User = Depends(get_current_active_user)):\n"
                "    basket = await db.baskets.find_one({'id': basket_id})\n"
                "    if not basket:\n"
                "        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Basket not found')\n"
                "    # Ownership check: assert caller owns the resource or is admin\n"
                "    if basket['user_id'] != current_user.id and current_user.role != 'admin':\n"
                "        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Access denied')\n"
                "    return basket"
            )
        elif framework in ("spring", "java"):
            return (
                "// Spring Boot / Java: Ownership check via security service\n"
                f"@GetMapping(\"{endpoint}\")\n"
                "@PreAuthorize(\"@securityService.isBasketOwner(#id, authentication) or hasRole('ADMIN')\")\n"
                "public ResponseEntity<BasketDto> getBasket(@PathVariable Long id) {\n"
                "    BasketDto basket = basketService.findById(id);\n"
                "    return ResponseEntity.ok(basket);\n"
                "}"
            )
        else:
            # Express / Node.js default
            return (
                "// Node.js / Express: Server-side resource ownership verification\n"
                "const verifyBasketOwnership = async (req, res, next) => {\n"
                "  const basketId = req.params.id;\n"
                "  const basket = await BasketModel.findByPk(basketId);\n"
                "  if (!basket) {\n"
                "    return res.status(404).json({ error: 'Basket not found' });\n"
                "  }\n"
                "  // Assert session identity matches resource owner\n"
                "  if (basket.UserId !== req.user.id && req.user.role !== 'admin') {\n"
                "    return res.status(403).json({ error: 'Access Denied: You do not own this basket' });\n"
                "  }\n"
                "  req.basket = basket;\n"
                "  next();\n"
                "};\n\n"
                f"router.get('{endpoint}', verifyAuth, verifyBasketOwnership, (req, res) => {{\n"
                "  res.json({ data: req.basket });\n"
                "});"
            )

    def _build_bfla_code_snippet(self, endpoint: str, framework: str) -> str:
        if framework in ("fastapi", "python"):
            return (
                "# FastAPI / Python: Administrative role enforcement dependency\n"
                "def require_admin(current_user: User = Depends(get_current_user)):\n"
                "    if current_user.role != 'admin':\n"
                "        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Admin role required')\n"
                "    return current_user\n\n"
                f"@router.get('{endpoint}', dependencies=[Depends(require_admin)])\n"
                "async def admin_endpoint():\n"
                "    return {'status': 'success'}"
            )
        else:
            return (
                "// Node.js / Express: Role-based access control middleware\n"
                "const requireRole = (requiredRole) => (req, res, next) => {\n"
                "  if (!req.user || req.user.role !== requiredRole) {\n"
                "    return res.status(403).json({ error: 'Forbidden: Insufficient privileges' });\n"
                "  }\n"
                "  next();\n"
                "};\n\n"
                f"router.use('{endpoint}', verifyAuth, requireRole('admin'));"
            )

    def _build_auth_code_snippet(self, endpoint: str, framework: str) -> str:
        if framework in ("fastapi", "python"):
            return (
                "# FastAPI: Mandatory OAuth2/JWT authentication dependency\n"
                f"@router.get('{endpoint}')\n"
                "async def protected_route(user: User = Depends(get_current_user)):\n"
                "    return {'data': 'protected'}"
            )
        else:
            return (
                "// Node.js / Express: Mandatory JWT verification middleware\n"
                "const verifyJwt = (req, res, next) => {\n"
                "  const authHeader = req.headers.authorization;\n"
                "  if (!authHeader || !authHeader.startsWith('Bearer ')) {\n"
                "    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });\n"
                "  }\n"
                "  const token = authHeader.split(' ')[1];\n"
                "  try {\n"
                "    req.user = jwt.verify(token, process.env.JWT_SECRET);\n"
                "    next();\n"
                "  } catch (err) {\n"
                "    return res.status(401).json({ error: 'Unauthorized: Invalid token signature' });\n"
                "  }\n"
                "};\n\n"
                f"router.use('{endpoint}', verifyJwt);"
            )

    def _build_generic_rbac_snippet(self, framework: str) -> str:
        return (
            "// Server-side access control policy\n"
            "if (!securityContext.isAuthorized(user, resource, action)) {\n"
            "  throw new ForbiddenException('Access denied by policy');\n"
            "}"
        )

    # --------------------------------------------------------------------------
    # AI Synthesis with Fallback
    # --------------------------------------------------------------------------

    def _generate_with_ai(
        self,
        analysis: FindingAnalysis,
        endpoint: str,
        evidence_list: List[SecurityEvidence],
        target_framework: str,
    ) -> Optional[DetailedRemediationPlan]:
        """Synthesizes remediation plan using injected AI client, validating output."""
        try:
            prompt = build_remediation_prompt(
                finding_title=analysis.title,
                vulnerability_category=analysis.title,
                endpoint=endpoint,
                evidence_list=evidence_list,
                target_framework=target_framework,
            )

            raw_response = self.ai_client.complete(
                system_prompt=SYSTEM_ANALYSIS_PROMPT,
                user_prompt=prompt,
            )

            clean_json = raw_response.strip()
            if clean_json.startswith("```"):
                clean_json = re.sub(r"^```(?:json)?\s*", "", clean_json)
                clean_json = re.sub(r"\s*```$", "", clean_json)

            data = json.loads(clean_json)

            return DetailedRemediationPlan(
                problem_addressed=f"Vulnerability on {endpoint}: {analysis.title}",
                recommended_fix=data.get("recommended_fix", "Enforce server-side authorization controls."),
                technical_implementation_guidance=data.get("technical_implementation_guidance", "// Implement access control"),
                root_cause_correction=analysis.technical_root_cause,
                additional_security_controls=data.get("server_side_controls", ["AuthorizationMiddleware"]),
                why_fix_works=data.get("why_fix_works", "Enforces authorization validation prior to execution."),
                retesting_procedure=data.get("retesting_procedure", f"Send request to {endpoint} and assert 403."),
                expected_secure_behavior="HTTP 403 Forbidden with access denied error.",
                regression_test_suggestions=data.get("regression_testing_recommendations", ["Automated regression test."]),
                target_framework=target_framework,
            )
        except Exception as exc:
            logger.warning(
                "AI remediation generation failed or returned invalid JSON; falling back to deterministic synthesis",
                extra={"error": str(exc)},
            )
            return None

    def _normalize_framework(self, framework: str) -> str:
        """Normalizes framework string into standard identifier."""
        norm = (framework or "express").strip().lower()
        if any(f in norm for f in ["fastapi", "python"]):
            return "fastapi"
        if any(f in norm for f in ["spring", "java"]):
            return "spring"
        return "express"
