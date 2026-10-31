# AuthScope: AI Agent Behavior & Operational Boundaries

This document defines how the Claude 3.5 Sonnet AI Agent operates within AuthScope, detailing prompt architecture, tool invocation constraints, context window management, and anti-hallucination guardrails.

---

## 1. Role & Operating Scope

The AI Agent acts as an **expert security strategist and analyst**. It is not an arbitrary script runner; it plans tests, analyzes differential outputs, identifies multi-endpoint correlations, and formats vulnerability findings.

### Tool Call Lifecycle
1. **Plan:** The agent analyzes the discovered attack surface and selects high-value targets for authorization testing.
2. **Call Tool:** Emits a structured tool call (e.g., `compare_access(endpoint="/rest/basket/1", method="GET")`).
3. **Engine Execution:** The Python core executes the tool, enforces the scope guard, runs the network requests, and returns structured JSON.
4. **Evaluate:** The agent reviews the tool response, checks for authorization discrepancies, and either:
   - Chains another tool call (if an attack chain is suspected).
   - Confirms a finding by calling `save_finding(...)`.
   - Concludes testing on this endpoint if access controls are enforced correctly.

---

## 2. Anti-Hallucination Guardrails

1. **Tool Output Grounding:** The model is forbidden from reporting findings that lack corresponding tool execution output in the current context.
2. **Schema-Constrained Tool Responses:** The engine supplies structured JSON responses with explicit boolean flags (`is_discrepancy_detected`) and HTTP status codes.
3. **No Speculative Severity:** Severity ratings must be justified by concrete CVSS 3.1 metrics and data sensitivity definitions.
4. **Prompt Injection Resistance:** Endpoint responses and user input passed into the agent's context are wrapped in strict XML tags (`<target_response>...</target_response>`) with system instructions stating that target payload contents must never be interpreted as agent instructions.

---

## 3. Human Approval Gates

The AI Agent must halt and request operator approval before:
1. Attempting requests that mutate critical persistent state (e.g., changing passwords or email addresses of baseline accounts).
2. Probing endpoints detected outside initial seed discovery paths.
3. Testing endpoints matching dangerous patterns (e.g., `/reset`, `/wipe`, `/purge`).

