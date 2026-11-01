import type {
  AssessmentActivityEvent,
  AssessmentSummaryResponse,
  FourRolesStatusResponse,
  ConfigureRolePayload,
  EndpointGraphData,
  AttackChainCandidateData,
  AttackChainExecutionData,
  RoleMatrixItem,
  ProjectRecord,
  ValidateProjectUrlPayload,
  ValidateProjectUrlResponse,
  CreateProjectPayload,
} from "@/types/assessment";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch {
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
  get: (id: string) => request<AssessmentSummaryResponse>(`/api/assessments/${encodeURIComponent(id)}`),
  cancel: (id: string) =>
    request<{ status: string; message: string }>(`/api/assessments/${encodeURIComponent(id)}/stop`, {
      method: "POST",
    }),
  streamUrl: (id: string, lastId?: number) =>
    `${API_BASE_URL}/api/assessments/${encodeURIComponent(id)}/stream${lastId ? `?last_event_id=${lastId}` : ""}`,

  // Four-Role Configuration & Readiness APIs
  getRoles: () => request<FourRolesStatusResponse>("/api/roles"),
  configureRole: (payload: ConfigureRolePayload) =>
    request<FourRolesStatusResponse>("/api/roles/configure", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Endpoint Graph & Relationship APIs
  getEndpointGraph: (assessmentId: string) =>
    request<EndpointGraphData>(`/api/assessments/${encodeURIComponent(assessmentId)}/endpoint-graph`),

  // Attack-Chain Planning & Execution APIs
  planAttackChains: (assessmentId: string, options?: { max_steps?: number; max_candidates?: number }) =>
    request<{ assessment_id: string; candidates_count: number; candidates: AttackChainCandidateData[]; summary: string }>(
      `/api/assessments/${encodeURIComponent(assessmentId)}/attack-chains/plan`,
      {
        method: "POST",
        body: JSON.stringify(options || {}),
      }
    ),
  getAttackChains: (assessmentId: string) =>
    request<{ assessment_id: string; candidates_count: number; candidates: AttackChainCandidateData[]; summary: string }>(
      `/api/assessments/${encodeURIComponent(assessmentId)}/attack-chains`
    ),
  validateAttackChain: (assessmentId: string, chain: Record<string, unknown>) =>
    request<{ is_valid: boolean; rejection_reasons: string[]; warnings: string[] }>(
      `/api/assessments/${encodeURIComponent(assessmentId)}/attack-chains/validate`,
      { method: "POST", body: JSON.stringify({ chain }) }
    ),
  executeAttackChain: (
    assessmentId: string,
    payload: {
      candidate_id?: string;
      chain?: Record<string, unknown>;
      role_assignments?: Record<string, string>;
      save_finding?: boolean;
    }
  ) =>
    request<AttackChainExecutionData>(
      `/api/assessments/${encodeURIComponent(assessmentId)}/attack-chains/execute`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),

  // Multi-Role Differential Matrix
  getRoleMatrix: (assessmentId: string) =>
    request<{
      assessment_id: string;
      target_url: string;
      role_readiness: Record<string, unknown>;
      matrix: RoleMatrixItem[];
    }>(`/api/assessments/${encodeURIComponent(assessmentId)}/role-matrix`),

  // Retest & Fix Verification
  verifyFix: (assessmentId: string, findingId: string) =>
    request<{
      assessment_id: string;
      finding_id: string;
      verification: Record<string, unknown>;
      history: Array<Record<string, unknown>>;
    }>(`/api/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(findingId)}/verify-fix`, {
      method: "POST",
    }),

  // Dual Project Connection (GitHub OAuth + Website URL) APIs
  validateProjectUrl: (payload: ValidateProjectUrlPayload) =>
    request<ValidateProjectUrlResponse>("/api/projects/validate-url", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createProject: (payload: CreateProjectPayload) =>
    request<ProjectRecord>("/api/projects", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listProjects: () =>
    request<{ count: number; projects: ProjectRecord[] }>("/api/projects"),
  getProject: (id: string) =>
    request<ProjectRecord>(`/api/projects/${encodeURIComponent(id)}`),
  deleteProject: (id: string) =>
    request<{ status: string; project_id: string }>(`/api/projects/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  scanProject: (id: string) =>
    request<{
      project_id: string;
      project_type: string;
      scan_id?: string;
      assessment_id?: string;
      status: string;
    }>(`/api/projects/${encodeURIComponent(id)}/scan`, {
      method: "POST",
    }),
};

export function openAssessmentStream(
  id: string,
  lastId: number,
  onActivity: (event: AssessmentActivityEvent) => void,
  onDone: (payload: { status?: string }) => void,
  onConnection: (connected: boolean) => void
): AbortController {
  const controller = new AbortController();
  void (async () => {
    let retry = 0;
    while (!controller.signal.aborted) {
      try {
        const response = await fetch(api.streamUrl(id, lastId), {
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error("Event stream unavailable");
        onConnection(true);
        retry = 0;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (!controller.signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let split = buffer.indexOf("\n\n");
          while (split >= 0) {
            const raw = buffer.slice(0, split).replace(/\r/g, "");
            buffer = buffer.slice(split + 2);
            const lines = raw.split("\n");
            const eventName = lines.find((line) => line.startsWith("event:"))?.slice(6).trim() || "message";
            const eventId = lines.find((line) => line.startsWith("id:"))?.slice(3).trim();
            const data = lines
              .filter((line) => line.startsWith("data:"))
              .map((line) => line.slice(5).trim())
              .join("\n");
            if (eventName === "activity" && data) {
              const parsed = JSON.parse(data) as AssessmentActivityEvent;
              const numericId = Number(eventId ?? parsed.id);
              if (Number.isFinite(numericId) && numericId > lastId) {
                lastId = numericId;
                onActivity(parsed);
              }
            } else if (eventName === "done" && data) {
              onDone(JSON.parse(data) as { status?: string });
              controller.abort();
            } else if (eventName === "error" && data) throw new Error("The assessment stream reported an error.");
            split = buffer.indexOf("\n\n");
          }
        }
        if (controller.signal.aborted) break;
        throw new Error("Event stream closed before assessment completion");
      } catch {
        if (controller.signal.aborted) break;
        onConnection(false);
        retry += 1;
        await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** (retry - 1), 10000)));
      }
    }
  })();
  return controller;
}
