"""AuthScope Gemini AI Agent Connector (Member 1).

Connects Gemini 2.0 / 1.5 models with Tool Registry and Assessment Memory under
strict evidence-supported guardrails:
1. Zero Arbitrary Execution: Tools must be strictly schema-validated and executed via ToolRegistry.
2. Scope Lockdown: Never contacts URLs outside ScopeGuard allowlist.
3. Secret Redaction: API keys and session tokens are never logged or exposed.
4. Deterministic Fallback: When GEMINI_API_KEY is not configured (or in tests),
   generates structured, evidence-grounded reasoning from verified facts.
5. Event Streaming: Emits structured agent_thinking, agent_plan, and explanation_generated events.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import json
import httpx

from backend.config import settings
from backend.core.scope_guard import ScopeGuard
from backend.agent.memory import AssessmentMemory
from backend.agent.tools import ToolRegistry, ToolExecutionResult
from backend.utils.helpers import compute_sha256, redact_sensitive_text
from backend.utils.logger import get_logger

logger = get_logger(__name__)

GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiAgent:
    """Gemini-powered security reasoning agent with ToolRegistry and Memory integration."""

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        memory: Optional[AssessmentMemory] = None,
        scope_guard: Optional[ScopeGuard] = None,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
    ):
        self.scope_guard = scope_guard or ScopeGuard()
        self.tool_registry = tool_registry or ToolRegistry(scope_guard=self.scope_guard)
        self.memory = memory
        self.api_key = api_key or settings.gemini_api_key
        self.model_name = model_name or settings.gemini_model or "gemini-2.0-flash"

    def plan_assessment(
        self,
        target_url: str,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Generates strategic assessment plan and emits thinking/plan events."""
        # 1. Agent Thinking
        thinking_msg = f"Formulating authorization differential strategy for {target_url}."
        if self.memory:
            self.memory.record_thought(thinking_msg)

        if on_event:
            on_event("agent_thinking", {
                "message": thinking_msg,
                "target_url": target_url,
            })

        # 2. Check previous assessment metadata via RAG memory
        past_scans = []
        if self.memory:
            past_scans = self.memory.get_previous_assessment_metadata()

        past_context = (
            f"Found {len(past_scans)} previous assessment(s) for this host."
            if past_scans
            else "First assessment for this target."
        )

        # 3. Agent Plan
        plan_steps = [
            "1. Validate target scope against strict ScopeGuard allowlist.",
            "2. Establish target connectivity and verify HTTP response.",
            "3. Discover attack surface endpoints and parameterized resources.",
            "4. Validate multi-role testing personas (User A, User B, Admin).",
            "5. Execute cross-account differential tests on identified endpoints.",
            "6. Cryptographically sign and validate evidence artifacts (SHA-256).",
            "7. Compile findings and synthesize remediation code patches.",
        ]
        plan_summary = "7-stage authorization evaluation plan initialized."

        if self.memory:
            self.memory.record_plan(plan_summary, {"steps": plan_steps, "past_context": past_context})

        if on_event:
            on_event("agent_plan", {
                "message": plan_summary,
                "steps": plan_steps,
                "past_context": past_context,
            })

        return {
            "plan_summary": plan_summary,
            "steps": plan_steps,
            "past_scans_count": len(past_scans),
        }

    def generate_explanation(
        self,
        endpoint: str,
        vulnerability_category: str,
        validation_status: str,
        evidence_summary: str,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Generates plain-English root cause explanation and remediation advice.

        Uses Gemini API when configured, otherwise deterministic RAG knowledge lookup.
        """
        # 1. Agent Thinking
        thinking_msg = f"Analyzing vulnerability mechanics for {vulnerability_category} on {endpoint}."
        if self.memory:
            self.memory.record_thought(thinking_msg)

        if on_event:
            on_event("agent_thinking", {
                "message": thinking_msg,
                "endpoint": endpoint,
                "category": vulnerability_category,
            })

        # 2. Query Memory RAG for vulnerability context
        rag_items = []
        if self.memory:
            rag_items = self.memory.retrieve_security_knowledge(
                query=f"{vulnerability_category} {endpoint}",
                category=vulnerability_category,
            )

        rag_knowledge = rag_items[0] if rag_items else None

        # 3. Attempt Gemini generation if key is present
        explanation_text = ""
        remediation_code = ""
        source_location = None

        if self.api_key:
            try:
                explanation_text = self._call_gemini_api(
                    endpoint=endpoint,
                    vulnerability_category=vulnerability_category,
                    evidence_summary=evidence_summary,
                    rag_item=rag_knowledge,
                )
            except Exception as exc:
                logger.warning(f"Gemini API call failed, falling back to deterministic RAG: {exc}")
                explanation_text = ""

        # Deterministic fallback if API was not called or failed
        if not explanation_text:
            if rag_knowledge:
                explanation_text = (
                    f"### {rag_knowledge.title}\n\n"
                    f"**Observed Behavior:** {evidence_summary}\n\n"
                    f"**Root Cause:** {rag_knowledge.root_cause}\n\n"
                    f"**Security Impact:** {rag_knowledge.threat_impact}\n\n"
                    f"**Remediation:** {rag_knowledge.remediation_guidance}"
                )
                remediation_code = rag_knowledge.code_pattern_secure
            else:
                explanation_text = (
                    f"Unauthorized differential access observed on `{endpoint}`. "
                    f"The server failed to enforce strict role-based or ownership assertions."
                )

        if self.memory:
            self.memory.record_explanation(explanation_text, {"endpoint": endpoint})

        if on_event:
            on_event("explanation_generated", {
                "message": f"Generated security analysis for {endpoint}",
                "endpoint": endpoint,
                "category": vulnerability_category,
                "explanation": explanation_text,
            })

        return {
            "endpoint": endpoint,
            "category": vulnerability_category,
            "explanation": explanation_text,
            "remediation_code": remediation_code,
            "source_location": source_location,
        }

    def _call_gemini_api(
        self,
        endpoint: str,
        vulnerability_category: str,
        evidence_summary: str,
        rag_item: Optional[Any] = None,
    ) -> str:
        """Invokes Google Gemini REST API using httpx."""
        url = f"{GEMINI_API_ENDPOINT}/{self.model_name}:generateContent?key={self.api_key}"
        prompt = (
            f"You are an expert Application Security Engineer analyzing an authorization vulnerability.\n"
            f"Vulnerability: {vulnerability_category}\n"
            f"Endpoint: {endpoint}\n"
            f"Evidence: {evidence_summary}\n"
        )
        if rag_item:
            prompt += f"\nReference Knowledge: {rag_item.root_cause}\n"

        prompt += (
            "\nProvide a concise analysis in 3 short paragraphs:\n"
            "1. What is wrong.\n"
            "2. Why it is dangerous.\n"
            "3. How to fix it server-side."
        )

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 800,
            }
        }

        with httpx.Client(timeout=15.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
            logger.warning(f"Gemini API returned status {resp.status_code}: {resp.text[:200]}")
            return ""
