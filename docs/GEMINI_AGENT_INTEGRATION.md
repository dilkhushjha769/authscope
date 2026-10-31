# AuthScope Gemini AI Brain & Agent Integration Guide (Member 1)

This document defines the architecture, safety boundaries, configuration, and cross-member integration interfaces for the **Gemini AI Brain (`backend/ai_agent/`)**.

---

## 1. Architecture Overview

The `backend/ai_agent/` package provides a Google Gemini-powered cognitive planner, safe tool-call proposer, bounded execution loop, and evidence-grounded vulnerability analyst using the official `google-genai` SDK.

### Package Structure
- [`backend/ai_agent/config.py`](file:///d:/authscope/backend/ai_agent/config.py): `GeminiAgentConfig` (reads `GEMINI_API_KEY`, `GEMINI_MODEL`, `AGENT_MAX_ITERATIONS`, `AGENT_MAX_TOOL_CALLS`, `AGENT_TEMPERATURE` from environment variables; redacts secrets in `__repr__` and `to_safe_dict()`).
- [`backend/ai_agent/gemini_client.py`](file:///d:/authscope/backend/ai_agent/gemini_client.py): `GeminiClient` wrapper around `google.genai.Client` with exponential backoff retries, rate-limit/timeout handling, structured JSON schema validation, and function-calling support.
- [`backend/ai_agent/prompts.py`](file:///d:/authscope/backend/ai_agent/prompts.py): Prompt builders reusing `wrap_untrusted_evidence` (`<untrusted_security_evidence>`) from `backend.agent.prompts`.
- [`backend/ai_agent/planner.py`](file:///d:/authscope/backend/ai_agent/planner.py): `AssessmentPlanner`, `AssessmentRequest`, `AssessmentPlan`, and `AssessmentPlanStep` with pre-planning `ScopeGuard` enforcement.
- [`backend/ai_agent/orchestrator.py`](file:///d:/authscope/backend/ai_agent/orchestrator.py): `AgentOrchestrator`, `ApprovedToolRegistry`, `MemorySystemInterface`, and the 11-step bounded assessment loop.
- [`backend/ai_agent/agent.py`](file:///d:/authscope/backend/ai_agent/agent.py): `GeminiAuthScopeAgent` (`GeminiAgent`) unified facade.

---

## 2. Safety & Security Boundaries

1. **Gemini is NOT the Security Authority**:
   - Every target URL and HTTP method is validated through [`ScopeGuard`](file:///d:/authscope/backend/core/scope_guard.py) before planning and before every tool execution.
   - Any attempt to expand target scope (different host, port, or scheme) or use disallowed HTTP methods is blocked immediately.
2. **Zero Arbitrary Code or Shell Execution**:
   - Tool proposals containing forbidden keys (`cmd`, `command`, `shell`, `eval`, `exec`, `script`, `subprocess`, `raw_sql`) or destructive patterns (`rm -rf`, `drop table`, `eval(`, `exec(`) are rejected by `ApprovedToolRegistry.validate_proposal()`.
3. **Bounded Execution Loop**:
   - Enforces hard limits via `AGENT_MAX_ITERATIONS` (default `8`) and `AGENT_MAX_TOOL_CALLS` (default `15`) to prevent infinite loops or excessive token consumption.
4. **Mandatory Evidence Validation Gate**:
   - Candidate findings must be verified through `EvidenceValidator` (`validate_evidence`).
   - A finding is **never** marked `CONFIRMED` unless `is_evidence_validated=True` and a deterministic SHA-256 signature is present; unvalidated findings are strictly capped at `SUSPECTED`.

---

## 3. Environment Configuration

Add the following variables to `.env` (never commit actual API keys):

```env
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
AGENT_MAX_ITERATIONS=8
AGENT_MAX_TOOL_CALLS=15
AGENT_TEMPERATURE=0.2
GEMINI_MAX_TOKENS=2048
GEMINI_TIMEOUT=30.0
```

---

## 4. Integration Interfaces for Team Members

### A. Integration with Member 2 (Tool Registry & Security Scanner Tools)

Member 2 can register additional deterministic security tools into `ApprovedToolRegistry` without modifying `backend/ai_agent/` files:

```python
from backend.ai_agent import GeminiAgent

agent = GeminiAgent()

agent.tool_registry.register_tool(
    name="custom_idor_probe",
    description="Probes object ownership across User A and User B sessions.",
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {"type": "string"},
            "method": {"type": "string", "enum": ["GET"]},
        },
        "required": ["endpoint", "method"],
    },
    handler=member2_idor_handler,  # Callable[[Dict[str, Any]], Dict[str, Any]]
)
```

- `ApprovedToolRegistry.validate_proposal()` automatically enforces `ScopeGuard.validate_request()`, allowed HTTP methods, and forbidden parameter checks before invoking `handler(arguments)`.
- All handler outputs are automatically scrubbed of tokens/secrets and wrapped in `<untrusted_security_evidence>` tags before being passed back to Gemini.

### B. Integration with Member 3 (Memory & RAG Security Knowledge System)

Member 3's memory system integrates via the `MemorySystemInterface` protocol in [`backend/ai_agent/orchestrator.py`](file:///d:/authscope/backend/ai_agent/orchestrator.py):

```python
from typing import Any, Dict, List, Optional
from backend.ai_agent import GeminiAgent, MemorySystemInterface

class Member3MemoryStore(MemorySystemInterface):
    def read_assessment_context(self, assessment_id: str) -> Dict[str, Any]:
        ...

    def store_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        ...

    def retrieve_security_knowledge(
        self, query: str, category: Optional[str] = None, top_k: int = 3
    ) -> List[Dict[str, Any]]:
        ...

    def get_conversation_context(
        self, assessment_id: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        ...

    def append_conversation_turn(
        self,
        assessment_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        ...

agent = GeminiAgent(memory=Member3MemoryStore())
```

### C. Integration with Member 4 (FastAPI Backend, SSE Streaming & Frontend UI)

Member 4 can stream real-time `AssessmentEvent` progress events and retrieve the final `AssessmentRunResult` in FastAPI routes or background tasks:

```python
from backend.ai_agent import AssessmentRequest, GeminiAgent

agent = GeminiAgent()
request = AssessmentRequest(
    target_url="http://localhost:3000",
    objective="Check BOLA and BFLA authorization boundaries.",
)

# 1. Async SSE Event Streaming (yields existing backend.storage.models.AssessmentEvent objects)
async for event in agent.astream_assessment(request):
    # Compatible with existing FastAPI SSE broadcaster
    pass

# 2. Full Structured Assessment Result
result = await agent.arun_assessment(request)
# result.findings -> List[ValidatedFindingReport] (includes simple_explanation, remediation_suggestion, evidence_sha256)
# result.executive_summary -> str
# agent.get_status() -> Dict[str, Any] (safe for frontend; API key is always redacted)
```

