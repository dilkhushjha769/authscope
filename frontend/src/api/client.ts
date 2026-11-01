import type {
  AssessmentActivityEvent,
  AssessmentSummaryResponse,
  FourRolesStatusResponse,
  EndpointGraphData,
  AttackChainCandidateData,
  AttackChainExecutionData,
} from "@/types/assessment";

const API = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      ...init,
      signal: init?.signal || AbortSignal.timeout(20000),
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new Error("The AuthScope API did not respond within 20 seconds. Check that the backend is running and retry.");
    }
    throw new Error("Could not reach the AuthScope API. Check that the backend is running.");
  }
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body && typeof body.detail === "string"
        ? body.detail
        : `The API returned HTTP ${response.status}.`;
    throw new Error(detail);
  }
  return body as T;
}

export const api = {
  start: (target_url: string) =>
    request<{ assessment_id: string; target_url: string; status: string; created_at: string; message: string }>(
      "/api/assessments",
      { method: "POST", body: JSON.stringify({ target_url }) }
    ),
  get: (id: string) =>
    request<AssessmentSummaryResponse>(`/api/assessments/${encodeURIComponent(id)}`),
  cancel: (id: string) =>
    request<{ status: string; message: string }>(`/api/assessments/${encodeURIComponent(id)}/stop`, {
      method: "POST",
    }),
  streamUrl: (id: string, lastId: number) =>
    `${API}/api/assessments/${encodeURIComponent(id)}/stream${lastId ? `?last_event_id=${lastId}` : ""}`,

  // Four-Role Configuration
  getRoles: () => request<FourRolesStatusResponse>("/api/roles"),
  configureRole: (req: {
    role: string;
    token?: string;
    user_id?: string;
    owned_resources?: Record<string, string>;
    custom_headers?: Record<string, string>;
  }) =>
    request<FourRolesStatusResponse>("/api/roles/configure", {
      method: "POST",
      body: JSON.stringify(req),
    }),

  // Multi-Endpoint Attack-Chain Planning & Execution
  getAttackChains: (assessment_id: string) =>
    request<{ candidates: AttackChainCandidateData[] }>(
      `/api/assessments/${encodeURIComponent(assessment_id)}/attack-chains`
    ),
  getEndpointGraph: (assessment_id: string) =>
    request<EndpointGraphData>(`/api/assessments/${encodeURIComponent(assessment_id)}/endpoint-graph`),
  planAttackChains: (assessment_id: string, options?: { max_steps?: number; max_candidates?: number }) =>
    request<{ candidates: AttackChainCandidateData[] }>(
      `/api/assessments/${encodeURIComponent(assessment_id)}/attack-chains/plan`,
      { method: "POST", body: JSON.stringify(options || {}) }
    ),
  validateAttackChain: (assessment_id: string, candidate: Record<string, unknown>) =>
    request<{ is_valid: boolean; rejection_reasons: string[] }>(
      `/api/assessments/${encodeURIComponent(assessment_id)}/attack-chains/validate`,
      { method: "POST", body: JSON.stringify({ chain: candidate }) }
    ),
  executeAttackChain: (
    assessment_id: string,
    body: {
      candidate_id?: string;
      chain?: Record<string, unknown>;
      role_assignments?: Record<string, string>;
      save_finding?: boolean;
    }
  ) =>
    request<AttackChainExecutionData>(
      `/api/assessments/${encodeURIComponent(assessment_id)}/attack-chains/execute`,
      { method: "POST", body: JSON.stringify(body) }
    ),
  verifyFix: (assessment_id: string, finding_id: string) =>
    request<{ verification: Record<string, unknown> }>(
      `/api/assessments/${encodeURIComponent(assessment_id)}/findings/${encodeURIComponent(finding_id)}/verify-fix`,
      { method: "POST" }
    ),
};

export function openAssessmentStream(
  id: string,
  lastId: number,
  onActivity: (event: AssessmentActivityEvent) => void,
  onDone: (data: { status?: string }) => void,
  onConnection: (connected: boolean) => void,
  onFailure: (message: string) => void
): AbortController {
  const controller = new AbortController();
  void (async () => {
    let retries = 0;
    while (!controller.signal.aborted && retries < 6) {
      try {
        const response = await fetch(api.streamUrl(id, lastId), {
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error("Event stream unavailable");
        onConnection(true);
        retries = 0;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (!controller.signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let pos = buffer.indexOf("\n\n");
          while (pos >= 0) {
            const raw = buffer.slice(0, pos).replace(/\r/g, "");
            buffer = buffer.slice(pos + 2);
            const lines = raw.split("\n");
            const name = lines.find((line) => line.startsWith("event:"))?.slice(6).trim() || "message";
            const idText = lines.find((line) => line.startsWith("id:"))?.slice(3).trim();
            const data = lines
              .filter((line) => line.startsWith("data:"))
              .map((line) => line.slice(5).trim())
              .join("\n");
            if (name === "activity" && data) {
              const parsed = JSON.parse(data) as AssessmentActivityEvent;
              const sequence = Number(idText ?? parsed.id);
              if (Number.isFinite(sequence) && sequence > lastId) {
                lastId = sequence;
                onActivity(parsed);
              }
            } else if (name === "done" && data) {
              onDone(JSON.parse(data) as { status?: string });
              controller.abort();
            } else if (name === "error" && data) {
              throw new Error("Assessment stream error");
            }
            pos = buffer.indexOf("\n\n");
          }
        }
        if (controller.signal.aborted) break;
        throw new Error("Event stream ended before completion");
      } catch {
        if (controller.signal.aborted) break;
        onConnection(false);
        retries += 1;
        if (retries >= 6) {
          onFailure(
            "The live assessment stream could not reconnect after 6 attempts. The assessment status can still be refreshed by reopening this scan."
          );
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** (retries - 1), 10000)));
      }
    }
  })();
  return controller;
}
