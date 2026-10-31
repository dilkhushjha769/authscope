"""Test-only Mock Adapters for AuthScope Parallel Sprint (Member 4).

Implements the exact cross-member integration contracts for isolated API and SSE testing:
- Group 1: `MockGeminiAuthScopeAgent.astream_assessment(request, cancel_token=None)`
- Group 2: `MockToolRegistryAdapter.list_tools()`, `execute_tool_call(tool_name, arguments, context)`
- Group 3: `MockMemoryManager.get_context(assessment_id)`, `save_observation(assessment_id, observation)`,
  `search_knowledge(query, category=None, limit=5)`, `save_finding(assessment_id, finding)`
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Union

from backend.core.assessment_engine import CancellationToken
from backend.storage.models import AssessmentEvent, AssessmentStage, EventType


class MockToolRegistryAdapter:
    """Test-only mock adapter implementing Group 2's `ToolRegistryAdapter` interface."""

    def __init__(self, fail_tool: Optional[str] = None) -> None:
        self.fail_tool = fail_tool
        self.executed_calls: List[Dict[str, Any]] = []

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "validate_target",
                "description": "Validates target URL against ScopeGuard allowlist.",
                "category": "website_discovery",
                "requires_scope_check": True,
            },
            {
                "name": "discover_endpoints",
                "description": "Discovers application routes and API endpoints.",
                "category": "website_discovery",
                "requires_scope_check": True,
            },
            {
                "name": "compare_endpoint_access",
                "description": "Executes multi-role differential authorization checks.",
                "category": "authorization_testing",
                "requires_scope_check": True,
            },
            {
                "name": "validate_evidence",
                "description": "Cryptographically signs and validates HTTP evidence.",
                "category": "report_generation",
                "requires_scope_check": False,
            },
            {
                "name": "map_endpoint_to_code",
                "description": "Maps runtime endpoint to backend route source location.",
                "category": "source_analysis",
                "requires_scope_check": False,
            },
        ]

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        call_record = {
            "tool_name": tool_name,
            "arguments": dict(arguments),
            "context": context,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.executed_calls.append(call_record)

        if self.fail_tool and tool_name == self.fail_tool:
            return {
                "tool_name": tool_name,
                "status": "failed",
                "success": False,
                "output": {},
                "error": f"Simulated failure in tool '{tool_name}'.",
            }

        return {
            "tool_name": tool_name,
            "status": "success",
            "success": True,
            "output": {"verified": True, "arguments": dict(arguments)},
            "error": None,
        }


class MockMemoryManager:
    """Test-only mock adapter implementing Group 3's `MemoryManager` interface."""

    def __init__(self) -> None:
        self.contexts: Dict[str, Dict[str, Any]] = {}
        self.observations: Dict[str, List[Dict[str, Any]]] = {}
        self.findings: Dict[str, List[Dict[str, Any]]] = {}

    def get_context(self, assessment_id: str) -> Dict[str, Any]:
        return {
            "assessment_id": assessment_id,
            "observations": list(self.observations.get(assessment_id, [])),
            "findings": list(self.findings.get(assessment_id, [])),
            **self.contexts.get(assessment_id, {}),
        }

    def save_observation(self, assessment_id: str, observation: Dict[str, Any]) -> None:
        if assessment_id not in self.observations:
            self.observations[assessment_id] = []
        self.observations[assessment_id].append(dict(observation))

    def search_knowledge(
        self,
        query: str,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        knowledge = [
            {
                "id": "owasp_api1_2023_bola",
                "category": "BOLA_IDOR",
                "title": "OWASP API1:2023 - Broken Object Level Authorization",
                "guidance": "Verify server-side resource ownership checks across roles.",
            },
            {
                "id": "owasp_api5_2023_bfla",
                "category": "BFLA",
                "title": "OWASP API5:2023 - Broken Function Level Authorization",
                "guidance": "Verify administrative routes enforce strict role checks.",
            },
        ]
        if category:
            knowledge = [k for k in knowledge if k["category"].upper() == category.upper()] or knowledge
        return knowledge[: max(1, limit)]

    def save_finding(self, assessment_id: str, finding: Any) -> str:
        if assessment_id not in self.findings:
            self.findings[assessment_id] = []
        finding_dict = (
            finding.model_dump(mode="json")
            if hasattr(finding, "model_dump")
            else dict(finding)
        )
        finding_id = str(finding_dict.get("id") or finding_dict.get("finding_id") or f"mock_fnd_{len(self.findings[assessment_id]) + 1}")
        finding_dict["id"] = finding_id
        self.findings[assessment_id].append(finding_dict)
        return finding_id


class MockGeminiAuthScopeAgent:
    """Test-only mock adapter implementing Group 1's `GeminiAuthScopeAgent` interface."""

    def __init__(
        self,
        tool_registry: Optional[MockToolRegistryAdapter] = None,
        memory_manager: Optional[MockMemoryManager] = None,
        mode: str = "standard",
    ) -> None:
        """Initializes the mock agent.

        Args:
            tool_registry: Optional MockToolRegistryAdapter.
            memory_manager: Optional MockMemoryManager.
            mode: One of:
                - "standard": Emits full lifecycle with confirmed BOLA finding & black-box notice.
                - "with_source": Emits confirmed finding with verified source code location.
                - "inconclusive": Emits inconclusive / suspicious finding without false confirmation.
                - "fail": Simulates tool failure and assessment_failed event.
                - "slow_cancellable": Pauses between steps so cancellation can be tested deterministically.
        """
        self.tool_registry = tool_registry or MockToolRegistryAdapter()
        self.memory_manager = memory_manager or MockMemoryManager()
        self.mode = mode
        self.requests_received: List[Any] = []

    async def astream_assessment(
        self,
        request: Union[Dict[str, Any], Any],
        cancel_token: Optional[CancellationToken] = None,
    ) -> AsyncGenerator[AssessmentEvent, None]:
        """Streams deterministic mock AssessmentEvent objects for testing."""
        self.requests_received.append(request)
        if isinstance(request, dict):
            scan_id = str(request.get("assessment_id", "scan_mock_001"))
            target_url = str(request.get("target_url", "http://localhost:3000"))
        else:
            scan_id = str(getattr(request, "assessment_id", "scan_mock_001"))
            target_url = str(getattr(request, "target_url", "http://localhost:3000"))

        # 1. Assessment started + thinking + plan
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.ASSESSMENT_STARTED.value,
            stage=AssessmentStage.SCOPE_VALIDATION.value,
            message=f"Starting security assessment for {target_url}.",
            metadata={
                "target_url": target_url,
                "thinking_message": f"Analyzing authorization surface for {target_url}.",
                "plan_summary": "Bounded 7-stage authorization assessment plan created.",
                "plan_steps": [
                    "1. Validate target scope via ScopeGuard.",
                    "2. Discover application endpoints.",
                    "3. Compare cross-role authorization responses.",
                    "4. Validate cryptographic evidence.",
                ],
            },
        )

        if cancel_token and cancel_token.is_cancelled:
            yield AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ASSESSMENT_CANCELLED.value,
                stage=AssessmentStage.REPORT_PREPARATION.value,
                message="Assessment cancelled safely by operator.",
            )
            return

        # 2. Scope validation tool execution
        self.tool_registry.execute_tool_call("validate_target", {"target_url": target_url}, {"assessment_id": scan_id})
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.SCOPE_VALIDATION_STARTED.value,
            stage=AssessmentStage.SCOPE_VALIDATION.value,
            message="Validating target scope against allowlist rules.",
            metadata={"target_url": target_url},
        )
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.SCOPE_VALIDATION_COMPLETED.value,
            stage=AssessmentStage.SCOPE_VALIDATION.value,
            message="Target authorization validated.",
            metadata={"target_url": target_url},
        )

        if self.mode == "slow_cancellable":
            for _ in range(20):
                if cancel_token and cancel_token.is_cancelled:
                    yield AssessmentEvent(
                        assessment_id=scan_id,
                        event_type=EventType.ASSESSMENT_CANCELLED.value,
                        stage=AssessmentStage.REPORT_PREPARATION.value,
                        message="Assessment cancelled safely by operator.",
                    )
                    return
                await asyncio.sleep(0.05)

        if self.mode == "fail":
            yield AssessmentEvent(
                assessment_id=scan_id,
                event_type="tool_failed",
                stage=AssessmentStage.TARGET_CONNECTION.value,
                message="Target connection tool failed: connection refused.",
                metadata={"tool": "discover_endpoints", "error": "Connection refused"},
            )
            yield AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.ASSESSMENT_FAILED.value,
                stage=AssessmentStage.TARGET_CONNECTION.value,
                message="Assessment halted: target connection refused.",
                metadata={"reason": "TARGET_UNREACHABLE", "tool": "discover_endpoints"},
            )
            return

        # 3. Connection & Endpoint discovery
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.CONNECTION_COMPLETED.value,
            stage=AssessmentStage.TARGET_CONNECTION.value,
            message="Application connection successful.",
        )
        self.tool_registry.execute_tool_call("discover_endpoints", {"target_url": target_url}, {"assessment_id": scan_id})
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.ENDPOINT_DISCOVERED.value,
            stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
            message="Discovered route: GET /rest/basket/1 [USER_OBJECT]",
            metadata={"path": "/rest/basket/1", "method": "GET", "category": "USER_OBJECT"},
        )
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.ENDPOINT_DISCOVERY_COMPLETED.value,
            stage=AssessmentStage.ENDPOINT_DISCOVERY.value,
            message="Discovered 4 endpoints.",
            metadata={"endpoints_discovered": 4},
        )

        # 4. Authorization testing
        self.tool_registry.execute_tool_call(
            "compare_endpoint_access",
            {"endpoint": "/rest/basket/1", "method": "GET"},
            {"assessment_id": scan_id},
        )
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.AUTHORIZATION_TEST_STARTED.value,
            stage=AssessmentStage.AUTHORIZATION_TESTING.value,
            message="Executing differential authorization checks.",
        )
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.AUTHORIZATION_TEST_COMPLETED.value,
            stage=AssessmentStage.AUTHORIZATION_TESTING.value,
            message="Completed differential authorization checks.",
            metadata={"tested_count": 4},
        )

        # 5. Finding & Evidence Validation
        if self.mode == "inconclusive":
            self.memory_manager.save_observation(
                scan_id,
                {"endpoint": "/rest/admin/application-configuration", "status": "INCONCLUSIVE"},
            )
            yield AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.SUSPICIOUS_BEHAVIOR_DETECTED.value,
                stage=AssessmentStage.AUTHORIZATION_TESTING.value,
                message="Inconclusive response observed on /rest/admin/application-configuration; multi-role baseline unavailable.",
                metadata={
                    "endpoint": "/rest/admin/application-configuration",
                    "severity": "MEDIUM",
                    "vulnerability_candidate": "BFLA",
                    "validation_status": "INCONCLUSIVE",
                    "verdict": "INCONCLUSIVE",
                    "source_info": {
                        "source_file": None,
                        "function_name": None,
                        "line_numbers": None,
                        "vulnerable_code": None,
                        "black_box_only": True,
                    },
                    "explanation": "Multi-role credentials were not configured; result marked INCONCLUSIVE rather than guessing.",
                },
            )
        else:
            source_info = (
                {
                    "source_file": "routes/basket.ts",
                    "function_name": "retrieveBasket",
                    "line_numbers": "18-29",
                    "vulnerable_code": "BasketModel.findOne({ where: { id: req.params.id } })",
                    "black_box_only": False,
                }
                if self.mode == "with_source"
                else {
                    "source_file": None,
                    "function_name": None,
                    "line_numbers": None,
                    "vulnerable_code": None,
                    "black_box_only": True,
                }
            )
            self.memory_manager.save_finding(
                scan_id,
                {
                    "id": f"fnd_{scan_id}_1",
                    "endpoint": "/rest/basket/1",
                    "severity": "HIGH",
                    "status": "CONFIRMED",
                },
            )
            yield AssessmentEvent(
                assessment_id=scan_id,
                event_type=EventType.FINDING_CONFIRMED.value,
                stage=AssessmentStage.EVIDENCE_VALIDATION.value,
                message="Confirmed BOLA/IDOR on /rest/basket/1 with signed SHA-256 evidence.",
                metadata={
                    "finding_id": f"fnd_{scan_id}_1",
                    "endpoint": "/rest/basket/1",
                    "severity": "HIGH",
                    "vulnerability_candidate": "BOLA_IDOR",
                    "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "source_info": source_info,
                    "explanation": "User B retrieved User A's private shopping basket via GET /rest/basket/1 (HTTP 200 OK).",
                    "remediation_code": "if (req.user.bid !== Number(req.params.id)) return res.status(403).send();",
                },
            )

        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.EVIDENCE_VALIDATION_COMPLETED.value,
            stage=AssessmentStage.EVIDENCE_VALIDATION.value,
            message="Evidence validation completed.",
            metadata={"confirmed_count": 0 if self.mode == "inconclusive" else 1, "suspicious_count": 1 if self.mode == "inconclusive" else 0},
        )

        # 6. Assessment completed
        yield AssessmentEvent(
            assessment_id=scan_id,
            event_type=EventType.ASSESSMENT_COMPLETED.value,
            stage=AssessmentStage.REPORT_PREPARATION.value,
            message="Assessment completed successfully.",
            metadata={
                "endpoints_discovered": 4,
                "endpoints_tested": 4,
                "confirmed_findings": 0 if self.mode == "inconclusive" else 1,
                "suspicious_results": 1 if self.mode == "inconclusive" else 0,
            },
        )

