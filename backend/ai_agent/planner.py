"""Bounded Security Assessment Planner for the AuthScope Gemini AI Brain.

Validates user assessment requests against `ScopeGuard`, interprets the security
objective, incorporates retrieved security knowledge, and generates a bounded,
non-destructive assessment plan restricted strictly to approved tools.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import asyncio
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.ai_agent.config import GeminiAgentConfig
from backend.ai_agent.gemini_client import GeminiClient
from backend.ai_agent.prompts import GEMINI_SYSTEM_INSTRUCTION, build_planning_prompt
from backend.core.scope_guard import ScopeGuard
from backend.utils.helpers import AuthScopeException, ScopeViolationError
from backend.utils.logger import get_logger

logger = get_logger(__name__)


DEFAULT_APPROVED_TOOLS: List[str] = [
    "check_scope",
    "discover_endpoints",
    "inspect_endpoint",
    "compare_access",
    "validate_evidence",
    "retrieve_security_knowledge",
]


class AssessmentRequest(BaseModel):
    """Validated user request for an authorized website security assessment."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    assessment_id: str = Field(
        default_factory=lambda: f"assess_{uuid.uuid4().hex[:10]}",
        min_length=1,
        description="Unique identifier for the assessment run.",
    )
    target_url: str = Field(
        ...,
        min_length=1,
        description="Authorized target website base URL (must pass ScopeGuard).",
    )
    objective: str = Field(
        default="Assess authorization boundaries for BOLA/IDOR, BFLA, and missing access controls.",
        min_length=3,
        description="User-defined security assessment objective.",
    )
    candidate_endpoints: List[str] = Field(
        default_factory=list,
        description="Optional relative endpoints to prioritize during testing.",
    )
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["GET"],
        description="Permitted HTTP methods (strictly GET by default for non-destructive testing).",
    )
    target_framework: str = Field(
        default="express",
        description="Target backend framework hint for tailored remediation suggestions.",
    )
    max_iterations: Optional[int] = Field(
        default=None,
        ge=1,
        le=50,
        description="Optional override for maximum agent iterations.",
    )
    max_tool_calls: Optional[int] = Field(
        default=None,
        ge=1,
        le=100,
        description="Optional override for maximum tool calls.",
    )

    @field_validator("target_url")
    @classmethod
    def normalize_target_url(cls, v: str) -> str:
        cleaned = (v or "").strip().rstrip("/")
        if not cleaned:
            raise ValueError("target_url cannot be empty.")
        return cleaned

    @field_validator("allowed_methods")
    @classmethod
    def validate_methods(cls, v: List[str]) -> List[str]:
        if not v:
            return ["GET"]
        normalized = [m.strip().upper() for m in v if m and m.strip()]
        return normalized or ["GET"]


class AssessmentPlanStep(BaseModel):
    """A single bounded step inside an AssessmentPlan."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    step_number: int = Field(..., ge=1, description="1-based execution order of the step.")
    title: str = Field(..., min_length=3, description="Concise title of the assessment step.")
    description: str = Field(..., min_length=5, description="Description of the test or check.")
    recommended_tool: str = Field(..., min_length=1, description="Approved tool name for this step.")
    expected_artifact: str = Field(
        default="Structured tool execution result",
        description="Expected evidence or output artifact.",
    )


class _LLMGeneratedPlanSchema(BaseModel):
    """Schema used to parse structured planning responses from Gemini."""

    model_config = ConfigDict(extra="ignore")

    objective_summary: str = Field(..., min_length=5)
    target_url: str = Field(..., min_length=1)
    rationale: str = Field(..., min_length=5)
    steps: List[AssessmentPlanStep] = Field(..., min_length=1)


class AssessmentPlan(BaseModel):
    """Complete, bounded, and scope-validated security assessment plan."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    plan_id: str = Field(
        default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}",
        description="Unique plan identifier.",
    )
    assessment_id: str = Field(..., description="Associated assessment request ID.")
    target_url: str = Field(..., description="ScopeGuard-verified target URL.")
    objective: str = Field(..., description="Original assessment objective.")
    objective_summary: str = Field(..., description="Normalized summary of the assessment goal.")
    rationale: str = Field(..., description="Security reasoning behind the planned steps.")
    steps: List[AssessmentPlanStep] = Field(..., min_length=1, description="Ordered, bounded assessment steps.")
    approved_tools: List[str] = Field(..., description="Allowlisted tool names available for this plan.")
    allowed_methods: List[str] = Field(..., description="Permitted HTTP methods for this assessment.")
    max_iterations: int = Field(..., ge=1, description="Hard upper bound on reasoning iterations.")
    max_tool_calls: int = Field(..., ge=1, description="Hard upper bound on total tool calls.")
    requires_evidence_validation: bool = Field(
        default=True,
        description="Mandatory gate requiring evidence validation before confirming findings.",
    )
    generated_by: str = Field(
        default="deterministic_planner",
        description="Indicates whether the plan was synthesized by 'gemini' or 'deterministic_planner'.",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC ISO-8601 creation timestamp.",
    )


class AssessmentPlanner:
    """Builds bounded, scope-validated security assessment plans using Gemini or deterministic rules."""

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        gemini_client: Optional[GeminiClient] = None,
        config: Optional[GeminiAgentConfig] = None,
        approved_tools: Optional[List[str]] = None,
    ) -> None:
        self.scope_guard = scope_guard or ScopeGuard()
        self.config = config or GeminiAgentConfig.from_env()
        self.gemini_client = gemini_client or GeminiClient(config=self.config)
        self.approved_tools = list(approved_tools or DEFAULT_APPROVED_TOOLS)

    def validate_request_scope(self, request: AssessmentRequest) -> None:
        """Validates the target URL and allowed HTTP methods against ScopeGuard.

        Raises:
            ScopeViolationError: If the target URL or any requested HTTP method violates ScopeGuard.
        """
        for method in request.allowed_methods:
            check = self.scope_guard.validate_request(url=request.target_url, method=method)
            if not check.is_allowed:
                logger.warning(
                    "Planner blocked out-of-scope assessment request",
                    extra={"target_url": request.target_url, "method": method, "reason": check.reason},
                )
                raise ScopeViolationError(
                    f"Assessment target or method rejected by ScopeGuard: {check.reason}"
                )

    def _build_deterministic_plan(
        self,
        request: AssessmentRequest,
        max_iterations: int,
        max_tool_calls: int,
    ) -> AssessmentPlan:
        """Constructs a reliable, bounded deterministic plan tailored to the request objective."""
        obj_lower = request.objective.lower()
        focus_areas: List[str] = []
        if "bola" in obj_lower or "idor" in obj_lower or "object" in obj_lower:
            focus_areas.append("BOLA/IDOR object-level ownership boundaries")
        if "bfla" in obj_lower or "admin" in obj_lower or "function" in obj_lower or "privilege" in obj_lower:
            focus_areas.append("BFLA administrative and function-level privileges")
        if not focus_areas:
            focus_areas.append("horizontal (BOLA/IDOR) and vertical (BFLA) authorization boundaries")

        focus_summary = " and ".join(focus_areas)

        raw_steps: List[AssessmentPlanStep] = [
            AssessmentPlanStep(
                step_number=1,
                title="Verify Target Scope Boundary",
                description=f"Validate {request.target_url} against ScopeGuard allowlist rules.",
                recommended_tool="check_scope",
                expected_artifact="ScopeCheckResult confirming target is in-scope.",
            ),
            AssessmentPlanStep(
                step_number=2,
                title="Discover & Enumerate Target Endpoints",
                description=f"Discover candidate API and web endpoints on {request.target_url}.",
                recommended_tool="discover_endpoints",
                expected_artifact="Normalized list of in-scope endpoints for testing.",
            ),
            AssessmentPlanStep(
                step_number=3,
                title="Execute Differential Authorization Probing",
                description=f"Compare responses across roles to evaluate {focus_summary}.",
                recommended_tool="compare_access",
                expected_artifact="Differential role comparison records and candidate evidence.",
            ),
            AssessmentPlanStep(
                step_number=4,
                title="Validate Empirical Security Evidence",
                description="Verify candidate findings with EvidenceValidator before any confirmation.",
                recommended_tool="validate_evidence",
                expected_artifact="Cryptographically hashed, sanitized EvidenceValidation status.",
            ),
        ]

        bounded_steps = raw_steps[: max(1, min(len(raw_steps), max_iterations))]
        for idx, stp in enumerate(bounded_steps, start=1):
            stp.step_number = idx

        return AssessmentPlan(
            assessment_id=request.assessment_id,
            target_url=request.target_url,
            objective=request.objective,
            objective_summary=f"Authorized non-destructive assessment of {request.target_url} focusing on {focus_summary}.",
            rationale=(
                "Executes strict scope verification first, maps exposed endpoints, performs "
                "read-only differential authorization checks across roles, and enforces independent "
                "evidence validation before reporting findings."
            ),
            steps=bounded_steps,
            approved_tools=list(self.approved_tools),
            allowed_methods=list(request.allowed_methods),
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            requires_evidence_validation=True,
            generated_by="deterministic_planner",
        )

    def _sanitize_and_bound_llm_steps(
        self,
        steps: List[AssessmentPlanStep],
        max_iterations: int,
    ) -> List[AssessmentPlanStep]:
        """Ensures all LLM-proposed steps use approved tools, stay within iteration bounds, and validate evidence."""
        valid_steps: List[AssessmentPlanStep] = []
        max_step_budget = max(1, min(max_iterations, 6))

        for step in steps:
            tool_name = step.recommended_tool.strip()
            if tool_name not in self.approved_tools:
                logger.warning(
                    "Planner stripped unapproved tool from LLM plan step; substituting safe default",
                    extra={"proposed_tool": tool_name},
                )
                tool_name = "compare_access" if "compare_access" in self.approved_tools else self.approved_tools[0]

            valid_steps.append(
                AssessmentPlanStep(
                    step_number=len(valid_steps) + 1,
                    title=step.title,
                    description=step.description,
                    recommended_tool=tool_name,
                    expected_artifact=step.expected_artifact,
                )
            )
            if len(valid_steps) >= max_step_budget:
                break

        # Ensure evidence validation step is present if budget permits and validate_evidence is approved
        if "validate_evidence" in self.approved_tools and not any(
            s.recommended_tool == "validate_evidence" for s in valid_steps
        ):
            if len(valid_steps) >= max_step_budget and len(valid_steps) > 1:
                valid_steps[-1] = AssessmentPlanStep(
                    step_number=len(valid_steps),
                    title="Validate Empirical Security Evidence",
                    description="Verify collected HTTP evidence before presenting or confirming any finding.",
                    recommended_tool="validate_evidence",
                    expected_artifact="Validated EvidenceArtifact with SHA-256 signature.",
                )
            elif len(valid_steps) < max_step_budget:
                valid_steps.append(
                    AssessmentPlanStep(
                        step_number=len(valid_steps) + 1,
                        title="Validate Empirical Security Evidence",
                        description="Verify collected HTTP evidence before presenting or confirming any finding.",
                        recommended_tool="validate_evidence",
                        expected_artifact="Validated EvidenceArtifact with SHA-265 signature.",
                    )
                )

        return valid_steps

    def create_plan(
        self,
        request: AssessmentRequest,
        security_knowledge: Optional[List[Dict[str, Any]]] = None,
    ) -> AssessmentPlan:
        """Creates a validated, bounded assessment plan for the authorized request."""
        # 1. Hard ScopeGuard enforcement before any planning
        self.validate_request_scope(request)

        eff_max_iterations = request.max_iterations or self.config.max_iterations
        eff_max_tool_calls = request.max_tool_calls or self.config.max_tool_calls

        # 2. If Gemini is configured, request an objective-tailored plan
        if self.gemini_client.is_configured:
            try:
                prompt = build_planning_prompt(
                    target_url=request.target_url,
                    objective=request.objective,
                    allowed_methods=request.allowed_methods,
                    approved_tools=self.approved_tools,
                    max_iterations=eff_max_iterations,
                    max_tool_calls=eff_max_tool_calls,
                    security_knowledge=security_knowledge,
                )
                llm_plan = self.gemini_client.generate_structured(
                    prompt=prompt,
                    response_schema=_LLMGeneratedPlanSchema,
                    system_instruction=GEMINI_SYSTEM_INSTRUCTION,
                )
                sanitized_steps = self._sanitize_and_bound_llm_steps(
                    steps=llm_plan.steps,
                    max_iterations=eff_max_iterations,
                )
                if sanitized_steps:
                    return AssessmentPlan(
                        assessment_id=request.assessment_id,
                        target_url=request.target_url,
                        objective=request.objective,
                        objective_summary=llm_plan.objective_summary,
                        rationale=llm_plan.rationale,
                        steps=sanitized_steps,
                        approved_tools=list(self.approved_tools),
                        allowed_methods=list(request.allowed_methods),
                        max_iterations=eff_max_iterations,
                        max_tool_calls=eff_max_tool_calls,
                        requires_evidence_validation=True,
                        generated_by="gemini",
                    )
            except Exception as exc:
                logger.warning(
                    "Gemini planning call failed; falling back to deterministic assessment plan",
                    extra={"error": str(exc)},
                )

        # 3. Deterministic fallback plan
        return self._build_deterministic_plan(
            request=request,
            max_iterations=eff_max_iterations,
            max_tool_calls=eff_max_tool_calls,
        )

    async def acreate_plan(
        self,
        request: AssessmentRequest,
        security_knowledge: Optional[List[Dict[str, Any]]] = None,
    ) -> AssessmentPlan:
        """Asynchronous wrapper for `create_plan`."""
        return await asyncio.to_thread(
            self.create_plan,
            request=request,
            security_knowledge=security_knowledge,
        )
