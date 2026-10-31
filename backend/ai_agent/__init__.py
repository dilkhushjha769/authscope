"""AuthScope Gemini AI Brain & Bounded Security Agent Package (`backend.ai_agent`).

Exports the official Google GenAI client wrapper, configuration, planner,
approved tool registry, memory system protocol, bounded orchestrator, and
high-level agent facade.
"""

from backend.ai_agent.agent import GeminiAgent, GeminiAuthScopeAgent
from backend.ai_agent.config import GeminiAgentConfig
from backend.ai_agent.gemini_client import (
    GeminiAPIError,
    GeminiAuthenticationError,
    GeminiClient,
    GeminiClientException,
    GeminiConfigurationError,
    GeminiRateLimitError,
    GeminiTimeoutError,
    GeminiValidationError,
)
from backend.ai_agent.orchestrator import (
    APPROVED_TOOL_SCHEMAS,
    AgentOrchestrator,
    ApprovedToolRegistry,
    AssessmentRunResult,
    DefaultMemoryBridge,
    InvalidToolProposalError,
    MemorySystemInterface,
    OrchestratorException,
    ToolCallProposal,
    ToolExecutionResult,
    ToolValidationResult,
    ValidatedFindingReport,
)
from backend.ai_agent.planner import (
    AssessmentPlan,
    AssessmentPlanStep,
    AssessmentPlanner,
    AssessmentRequest,
    DEFAULT_APPROVED_TOOLS,
)
from backend.ai_agent.prompts import (
    GEMINI_SYSTEM_INSTRUCTION,
    build_assessment_summary_prompt,
    build_planning_prompt,
    build_simple_finding_explanation_prompt,
    build_tool_selection_prompt,
    wrap_untrusted_evidence,
)

__all__ = [
    "GeminiAgent",
    "GeminiAuthScopeAgent",
    "GeminiAgentConfig",
    "GeminiClient",
    "GeminiClientException",
    "GeminiConfigurationError",
    "GeminiAuthenticationError",
    "GeminiRateLimitError",
    "GeminiTimeoutError",
    "GeminiAPIError",
    "GeminiValidationError",
    "AssessmentRequest",
    "AssessmentPlanStep",
    "AssessmentPlan",
    "AssessmentPlanner",
    "DEFAULT_APPROVED_TOOLS",
    "APPROVED_TOOL_SCHEMAS",
    "ToolCallProposal",
    "ToolValidationResult",
    "ToolExecutionResult",
    "ApprovedToolRegistry",
    "InvalidToolProposalError",
    "MemorySystemInterface",
    "DefaultMemoryBridge",
    "ValidatedFindingReport",
    "AssessmentRunResult",
    "AgentOrchestrator",
    "OrchestratorException",
    "GEMINI_SYSTEM_INSTRUCTION",
    "build_planning_prompt",
    "build_tool_selection_prompt",
    "build_simple_finding_explanation_prompt",
    "build_assessment_summary_prompt",
    "wrap_untrusted_evidence",
]

