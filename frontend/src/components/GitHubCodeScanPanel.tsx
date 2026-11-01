"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle,
  ArrowUp,
  Check,
  ChevronDown,
  Copy,
  ExternalLink,
  GitBranch,
  Loader2,
  LockKeyhole,
  RefreshCw,
  Shield,
  Sparkles,
  Unplug,
  Upload,
} from "lucide-react";

export interface GitHubAccount {
  id: string;
  login: string;
  avatar_url: string;
}
export interface GitHubInstallation {
  id: number;
  account_login: string;
  account_type: string;
}
export interface GitHubRepositoryItem {
  id: number;
  name: string;
  full_name: string;
  owner: string;
  private: boolean;
  description?: string | null;
  default_branch: string;
  html_url: string;
}
export interface GitHubBranch {
  name: string;
  commit_sha: string;
}
export interface GitHubFinding {
  finding_id: string;
  vulnerability_category: string;
  severity: string;
  confidence: string;
  classification: string;
  validation_status: string;
  file_path: string;
  language: string;
  function_name?: string | null;
  start_line: number;
  end_line: number;
  code_snippet: string;
  detection_explanation: string;
  detection_method: string;
  remediation_hint: string;
  repository: string;
  branch: string;
  commit_sha: string;
  github_url: string;
  ai_review?: {
    status: string;
    simple_title?: string;
    what_is_the_problem?: string;
    what_attacker_can_do?: string;
    affected_data_or_users?: string;
    why_it_happens?: string;
    how_to_fix?: string[];
    recommended_code_change?: string;
    tests_to_add?: string[];
    additional_recommendations?: string[];
    limitations?: string[];
    message?: string;
  };
}
export interface GitHubScan {
  id: string;
  installation_id: number;
  repository_id: number;
  owner: string;
  repository: string;
  branch: string;
  commit_sha: string;
  status: string;
  created_at: string;
  completed_at?: string | null;
  error_code?: string;
  languages: Record<string, number>;
  findings: GitHubFinding[];
}
export interface GitHubStatus {
  connected: boolean;
  expired?: boolean;
  account: GitHubAccount | null;
  installations: GitHubInstallation[];
}
export interface GitHubEvent {
  id: number;
  event_type: string;
  stage: string;
  message: string;
  timestamp: string;
}

function errorMessage(payload: unknown, fallback: string): string {
  const detail = (payload as { detail?: { code?: string; message?: string } | string })?.detail;
  if (typeof detail === "string") return detail;
  const code = detail?.code || "";
  const message = detail?.message || "";
  const messages: Record<string, string> = {
    GITHUB_NOT_CONFIGURED:
      "GitHub App setup is incomplete on the backend. Configure the App credentials, App slug, callback URL, and token encryption key.",
    GITHUB_NOT_CONNECTED: "Connect your GitHub account to continue.",
    GITHUB_AUTH_EXPIRED: "Your GitHub authorization expired. Reconnect GitHub and retry.",
    GITHUB_SESSION_EXPIRED: "Your AuthScope GitHub session expired. Connect GitHub again.",
    GITHUB_PERMISSION_DENIED:
      "This account or GitHub App cannot access that repository. Check the selected installation and its repository permissions.",
    GITHUB_APP_PERMISSION:
      "Set the GitHub App repository permissions to read-only for Metadata and Contents, then update the installation.",
    GITHUB_RATE_LIMIT: "GitHub's API rate limit was reached. Wait and try again.",
    SCAN_ALREADY_RUNNING: "Wait for your current source scan to finish before starting another.",
    SCAN_TIMEOUT: "The source scan exceeded the allowed run time. Try a smaller repository.",
    EMPTY_OR_UNSUPPORTED_REPOSITORY:
      "No supported Python, JavaScript, or TypeScript files were found in this repository.",
    REPOSITORY_TOO_LARGE: "The repository exceeds the current safe source scan limits.",
    AI_UNAVAILABLE: "The source scan completed, but Gemini could not provide explanations.",
    SCAN_FAILED: "The source scan failed. Try again, or reconnect GitHub if access expired.",
  };
  return messages[code] || message || fallback;
}

async function readJson<T>(response: Response, fallback: string): Promise<T> {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(errorMessage(payload, fallback));
  return payload as T;
}

export function GitHubCodeScanPanel({
  apiBaseUrl,
  initialRepoUrl,
  onScanStarted,
  onScanSelected,
}: {
  apiBaseUrl: string;
  initialRepoUrl?: string;
  onScanStarted?: (info: {
    scanId: string;
    owner: string;
    repository: string;
    branch: string;
    commitSha?: string;
  }) => void;
  onScanSelected?: (scan: GitHubScan) => void;
}) {
  const [status, setStatus] = useState<GitHubStatus>({
    connected: false,
    account: null,
    installations: [],
  });
  const [installationId, setInstallationId] = useState("");
  const [repositories, setRepositories] = useState<GitHubRepositoryItem[]>([]);
  const [selectedRepository, setSelectedRepository] = useState("");
  const [branches, setBranches] = useState<GitHubBranch[]>([]);
  const [selectedBranch, setSelectedBranch] = useState("");
  const [history, setHistory] = useState<GitHubScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<GitHubScan | null>(null);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [events, setEvents] = useState<GitHubEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const streamRef = useRef<EventSource | null>(null);
  const [copiedFinding, setCopiedFinding] = useState<string | null>(null);
  const [publicRepoUrl, setPublicRepoUrl] = useState<string>(initialRepoUrl || "https://github.com/juice-shop/juice-shop");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Per-finding Q&A (Gemini API #1) and on-demand Code Analysis (Gemini API #2)
  const [qaInput, setQaInput] = useState<Record<string, string>>({});
  const [qaHistory, setQaHistory] = useState<
    Record<string, { role: "user" | "assistant"; content: string }[]>
  >({});
  const [qaLoading, setQaLoading] = useState<Record<string, boolean>>({});
  const [aiEnrichLoading, setAiEnrichLoading] = useState<Record<string, boolean>>({});
  const [aiEnriched, setAiEnriched] = useState<
    Record<
      string,
      {
        what_bug_can_do: string;
        root_cause: string;
        how_to_resolve: string[];
        secure_code_fix: string;
      }
    >
  >({});

  const scanning = Boolean(activeScanId);

  const api = useCallback((path: string) => `${apiBaseUrl}${path}`, [apiBaseUrl]);
  const loadStatus = useCallback(async () => {
    const response = await fetch(api("/api/github/status"), {
      credentials: "include",
      cache: "no-store",
    });
    const payload = await readJson<GitHubStatus>(
      response,
      "Could not check GitHub connection status."
    );
    setStatus(payload);
    if (
      payload.installations.length &&
      !payload.installations.some((item) => String(item.id) === installationId)
    ) {
      setInstallationId(String(payload.installations[0].id));
    }
    return payload;
  }, [api, installationId]);

  const loadHistory = useCallback(async () => {
    const response = await fetch(api("/api/github/scans"), {
      credentials: "include",
      cache: "no-store",
    });
    const payload = await readJson<{ scans: GitHubScan[] }>(
      response,
      "Could not load source scan history."
    );
    setHistory(payload.scans);
    return payload.scans;
  }, [api]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const callbackStatus = params.get("github_status");
    if (callbackStatus) {
      const notices: Record<string, string> = {
        connected:
          "GitHub account connected. Install the AuthScope GitHub App on the repositories you want to scan.",
        installed:
          "GitHub App installation is ready. Select an installation and repository below.",
        not_configured:
          "GitHub is not configured on the backend. Set the App client ID/secret, callback URL, App slug, and token encryption key.",
        install_not_configured:
          "GitHub App installation is not configured. Set GITHUB_APP_SLUG on the backend.",
        denied: "GitHub authorization was cancelled or denied.",
        state_error:
          "The GitHub sign-in expired or could not be verified. Start again.",
        install_state_error:
          "The installation could not be verified. Start the install flow again.",
        install_failed:
          "GitHub installation completed, but AuthScope could not verify repository access.",
        install_cancelled: "GitHub App installation was cancelled.",
        connect_failed:
          "GitHub sign-in failed. Check the App callback URL and backend configuration.",
        callback_error: "GitHub did not return a valid authorization response.",
      };
      const message =
        notices[callbackStatus] || "GitHub returned an unknown connection status.";
      window.setTimeout(() => {
        if (callbackStatus === "connected" || callbackStatus === "installed")
          setNotice(message);
        else setError(message);
      }, 0);
      params.delete("github_status");
      const nextUrl = `${window.location.pathname}${
        params.size ? `?${params}` : ""
      }`;
      window.history.replaceState({}, "", nextUrl);
    }
    void (async () => {
      try {
        const connection = await loadStatus();
        if (connection.connected) {
          const scans = await loadHistory();
          const running = scans.find((scan) => scan.status === "RUNNING");
          if (running) setActiveScanId(running.id);
        }
      } catch {
        setStatus({ connected: false, account: null, installations: [] });
        setError(null);
      }
    })();
    return () => streamRef.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!status.connected || !installationId) {
      return;
    }
    let cancelled = false;
    void (async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(
          api(`/api/github/installations/${installationId}/repositories`),
          { credentials: "include", cache: "no-store" }
        );
        const payload = await readJson<{ repositories: GitHubRepositoryItem[] }>(
          response,
          "Could not load installed repositories."
        );
        if (!cancelled) {
          setRepositories(payload.repositories);
          setSelectedRepository((prev) => {
            if (prev && payload.repositories.some((r) => r.full_name === prev)) {
              return prev;
            }
            const authscopeRepo = payload.repositories.find(
              (r) => r.name.toLowerCase() === "authscope"
            );
            return authscopeRepo
              ? authscopeRepo.full_name
              : payload.repositories[0]?.full_name || "";
          });
        }
      } catch (loadError: unknown) {
        if (!cancelled)
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Could not load repositories."
          );
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, installationId, status.connected]);

  const chosenRepository = useMemo(
    () =>
      repositories.find((item) => item.full_name === selectedRepository) || null,
    [repositories, selectedRepository]
  );

  useEffect(() => {
    if (!chosenRepository || !installationId) return;
    let cancelled = false;
    const path = `/api/github/installations/${installationId}/repositories/${encodeURIComponent(
      chosenRepository.owner
    )}/${encodeURIComponent(chosenRepository.name)}/branches`;
    void (async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(api(path), {
          credentials: "include",
          cache: "no-store",
        });
        const payload = await readJson<{ branches: GitHubBranch[] }>(
          response,
          "Could not load repository branches."
        );
        if (!cancelled) {
          setBranches(payload.branches);
          setSelectedBranch(
            payload.branches.find((b) => b.name === chosenRepository.default_branch)
              ?.name ||
              payload.branches[0]?.name ||
              ""
          );
        }
      } catch (loadError: unknown) {
        if (!cancelled)
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Could not load branches."
          );
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, chosenRepository, installationId]);

  useEffect(() => {
    if (!activeScanId) return;
    streamRef.current?.close();
    const stream = new EventSource(api(`/api/github/scans/${activeScanId}/stream`), {
      withCredentials: true,
    });
    streamRef.current = stream;
    stream.addEventListener("activity", (message) => {
      try {
        setEvents((current) => [
          ...current,
          JSON.parse((message as MessageEvent).data) as GitHubEvent,
        ]);
      } catch {
        setError("A scan activity update could not be read.");
      }
    });
    stream.addEventListener("done", (message) => {
      try {
        const data = JSON.parse((message as MessageEvent).data) as {
          message?: string;
        };
        setNotice(data.message || "AI source code scan completed.");
      } catch {
        setNotice("AI source code scan completed.");
      }
      stream.close();
      setActiveScanId(null);
      void loadHistory().then((scans) => {
        const finished = scans.find((scan) => scan.id === activeScanId);
        if (finished) setSelectedScan(finished);
      });
    });
    stream.addEventListener("error", (message) => {
      if (!(message instanceof MessageEvent) || !message.data) return;
      try {
        const data = JSON.parse(message.data) as {
          metadata?: { code?: string };
          message?: string;
        };
        setError(
          errorMessage(
            { detail: { code: data.metadata?.code, message: data.message } },
            "The source scan failed."
          )
        );
      } catch {
        setError("The source scan failed. Reconnect GitHub and try again.");
      }
      stream.close();
      setActiveScanId(null);
      void loadHistory();
    });
    stream.onerror = () => {
      if (stream.readyState === EventSource.CLOSED) {
        setError(
          "The live scan stream closed unexpectedly. Check scan history for the final status."
        );
        stream.close();
        setActiveScanId(null);
        void loadHistory();
      }
    };
    return () => stream.close();
  }, [activeScanId, api, loadHistory]);

  const startPublicScan = async (overrideUrl?: string) => {
    const rawUrl = (overrideUrl || publicRepoUrl).trim();
    if (!rawUrl) {
      setError("Enter a GitHub repository URL to scan.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(api("/api/github/public-scan"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ repo_url: rawUrl }),
      });
      const result = await readJson<{
        scan_id: string;
        repository: string;
        branch: string;
        commit_sha?: string;
      }>(response, "Could not start public repository scan.");
      setActiveScanId(result.scan_id);
      if (onScanStarted) {
        const parts = result.repository.split("/");
        onScanStarted({
          scanId: result.scan_id,
          owner: parts[0] || "repo",
          repository: parts[1] || result.repository,
          branch: result.branch || "main",
          commitSha: result.commit_sha,
        });
      }
      void loadHistory();
    } catch (scanErr) {
      setError(scanErr instanceof Error ? scanErr.message : "Could not start public repository scan.");
    } finally {
      setLoading(false);
    }
  };

  const handleZipUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setError("Please select a .zip project archive.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(api("/api/github/upload-scan"), {
        method: "POST",
        credentials: "include",
        body: formData,
      });
      const result = await readJson<{
        scan_id: string;
        repository: string;
        branch: string;
        commit_sha?: string;
      }>(response, "Could not upload and scan project archive.");
      setActiveScanId(result.scan_id);
      if (onScanStarted) {
        onScanStarted({
          scanId: result.scan_id,
          owner: "local",
          repository: file.name.replace(/\.zip$/i, ""),
          branch: "uploaded",
          commitSha: "LOCAL",
        });
      }
      void loadHistory();
    } catch (upErr) {
      setError(upErr instanceof Error ? upErr.message : "Could not scan project archive.");
    } finally {
      setLoading(false);
    }
  };

  const connect = () => {
    window.location.href = api("/api/github/connect");
  };
  const install = () => {
    window.location.href = api("/api/github/install");
  };

  const disconnect = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(api("/api/github/disconnect"), {
        method: "DELETE",
        credentials: "include",
      });
      const result = await readJson<{ revoked: boolean }>(
        response,
        "Could not disconnect GitHub."
      );
      setStatus({ connected: false, account: null, installations: [] });
      setHistory([]);
      setSelectedScan(null);
      setNotice(
        result.revoked
          ? "GitHub access was revoked and the local connection was deleted."
          : "The local connection was deleted."
      );
    } catch (disconnectError) {
      setError(
        disconnectError instanceof Error
          ? disconnectError.message
          : "Could not disconnect GitHub."
      );
    } finally {
      setLoading(false);
    }
  };

  const startScan = async () => {
    if (!chosenRepository || !selectedBranch || !installationId) return;
    setLoading(true);
    setError(null);
    setNotice(null);
    setEvents([]);
    setSelectedScan(null);
    try {
      const response = await fetch(api("/api/github/scans"), {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          installation_id: Number(installationId),
          owner: chosenRepository.owner,
          repository: chosenRepository.name,
          branch: selectedBranch,
        }),
      });
      const result = await readJson<{ scan_id: string; commit_sha?: string }>(
        response,
        "Could not start the source scan."
      );
      setActiveScanId(result.scan_id);
      if (onScanStarted) {
        onScanStarted({
          scanId: result.scan_id,
          owner: chosenRepository.owner,
          repository: chosenRepository.name,
          branch: selectedBranch,
          commitSha: result.commit_sha,
        });
      }
      const scans = await loadHistory();
      const created = scans.find((scan) => scan.id === result.scan_id);
      if (created) setSelectedScan(created);
    } catch (scanError) {
      setError(
        scanError instanceof Error
          ? scanError.message
          : "Could not start the source scan."
      );
    } finally {
      setLoading(false);
    }
  };

  const openHistory = async (scanId: string) => {
    setError(null);
    setNotice(null);
    try {
      const response = await fetch(api(`/api/github/scans/${scanId}`), {
        credentials: "include",
        cache: "no-store",
      });
      const loaded = await readJson<GitHubScan>(
        response,
        "Could not open this source scan."
      );
      setSelectedScan(loaded);
      if (onScanSelected && loaded.status === "COMPLETED") {
        onScanSelected(loaded);
      }
    } catch (historyError) {
      setError(
        historyError instanceof Error
          ? historyError.message
          : "Could not open this source scan."
      );
    }
  };

  const copyText = async (finding: GitHubFinding, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedFinding(finding.finding_id);
      window.setTimeout(() => setCopiedFinding(null), 1500);
    } catch {
      setError("Could not copy the recommendation to the clipboard.");
    }
  };

  const enrichWithGeminiCodeApi = async (finding: GitHubFinding) => {
    const fid = finding.finding_id;
    if (aiEnrichLoading[fid]) return;
    setAiEnrichLoading((prev) => ({ ...prev, [fid]: true }));
    try {
      const res = await fetch(api("/api/ai/explain-bug"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title:
            finding.ai_review?.simple_title ||
            finding.vulnerability_category.replaceAll("_", " "),
          category: finding.vulnerability_category,
          severity: finding.severity,
          endpoint: `${finding.file_path}:${finding.start_line}-${finding.end_line}`,
          http_method: "SOURCE",
          description: finding.detection_explanation,
          code_snippet: finding.code_snippet,
          language: finding.language,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiEnriched((prev) => ({
          ...prev,
          [fid]: {
            what_bug_can_do: data.what_bug_can_do,
            root_cause: data.root_cause,
            how_to_resolve: data.how_to_resolve || [],
            secure_code_fix: data.secure_code_fix || "",
          },
        }));
      }
    } catch {
      // ignore
    } finally {
      setAiEnrichLoading((prev) => ({ ...prev, [fid]: false }));
    }
  };

  const askGeminiAboutRepoFinding = async (finding: GitHubFinding) => {
    const fid = finding.finding_id;
    const question = (qaInput[fid] || "").trim();
    if (!question || qaLoading[fid]) return;
    const currentHist = qaHistory[fid] || [];
    setQaLoading((prev) => ({ ...prev, [fid]: true }));
    try {
      const res = await fetch(api("/api/ai/finding-qa"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title:
            finding.ai_review?.simple_title ||
            finding.vulnerability_category.replaceAll("_", " "),
          category: finding.vulnerability_category,
          severity: finding.severity,
          endpoint: `${finding.repository}/${finding.file_path}:${finding.start_line}-${finding.end_line}`,
          http_method: "SOURCE",
          description: finding.detection_explanation,
          what_could_happen:
            finding.ai_review?.what_attacker_can_do || finding.remediation_hint,
          request_proof: finding.code_snippet,
          response_proof: `File: ${finding.file_path} (lines ${finding.start_line}-${finding.end_line})`,
          how_to_fix: finding.ai_review?.how_to_fix || [finding.remediation_hint],
          question,
          history: currentHist.slice(-6),
        }),
      });
      const data = await res.json();
      if (res.ok && data.answer) {
        setQaHistory((prev) => ({
          ...prev,
          [fid]: [
            ...currentHist,
            { role: "user", content: question },
            { role: "assistant", content: data.answer },
          ],
        }));
        setQaInput((prev) => ({ ...prev, [fid]: "" }));
      }
    } catch {
      // ignore
    } finally {
      setQaLoading((prev) => ({ ...prev, [fid]: false }));
    }
  };

  return (
    <section className="mt-4 rounded-xl border border-[#41413d] bg-[#20201e] p-4 sm:p-5 space-y-4 text-left">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-[#f4f2ec]">
            <GitBranch className="h-4 w-4 text-[#5fa37f]" />
            Connect &amp; AI-Scan GitHub Repository
          </h2>
          <p className="mt-1 text-xs text-[#aaa8a1]">
            Inspect all files in the selected branch with AST analysis + Gemini AI security review &amp; PDF export.
          </p>
        </div>
        {status.connected ? (
          <button
            type="button"
            onClick={() => void disconnect()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#41413d] bg-[#2d2d2a] px-3 py-1.5 text-xs text-[#d0cec8] hover:bg-[#373733] disabled:opacity-50"
          >
            <Unplug className="h-3.5 w-3.5" />
            Disconnect
          </button>
        ) : (
          <span className="rounded-full border border-[#41413d] bg-[#2d2d2a] px-2.5 py-1 text-[10px] text-[#aaa8a1]">
            Not connected
          </span>
        )}
      </div>

      {status.connected && status.account ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-[#5fa37f]/30 bg-[#5fa37f]/10 p-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-[#5fa37f]/20 text-[#5fa37f]">
            <GitBranch className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="text-xs font-medium text-[#f4f2ec]">
              Connected as @{status.account.login}
            </p>
            <p className="text-[10px] text-[#aaa8a1]">
              GitHub user {status.account.id} · read-only repository access
            </p>
          </div>
          {status.expired && (
            <button
              type="button"
              onClick={connect}
              className="text-[10px] text-[#c5aa54] underline"
            >
              Authorization expired · reconnect
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="rounded-lg border border-[var(--line)] bg-[var(--surface)] p-3.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-[#f4f2ec] flex items-center gap-1.5">
                <Sparkles size={14} className="text-[#5fa37f]" />
                Scan Public GitHub Repository (Instant · No Sign-in Required)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={publicRepoUrl}
                onChange={(e) => setPublicRepoUrl(e.target.value)}
                placeholder="https://github.com/juice-shop/juice-shop"
                className="flex-1 rounded-md border border-[#41413d] bg-[#20201e] px-3 py-2 text-xs text-[#f4f2ec] placeholder-[#85837c] font-mono focus:border-[#5fa37f] focus:outline-none"
              />
              <button
                type="button"
                onClick={() => void startPublicScan()}
                disabled={loading || !publicRepoUrl.trim()}
                className="inline-flex items-center gap-1.5 rounded-md bg-[#5fa37f] px-3.5 py-2 text-xs font-semibold text-[#102218] hover:brightness-105 disabled:opacity-50"
              >
                {loading ? <Loader2 size={13} className="animate-spin" /> : <GitBranch size={13} />}
                <span>Scan Repository</span>
              </button>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-[var(--line)]">
            <div className="flex items-center gap-2">
              <input
                type="file"
                ref={fileInputRef}
                accept=".zip"
                className="hidden"
                onChange={(e) => void handleZipUpload(e)}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
                className="inline-flex items-center gap-1.5 rounded-md border border-[var(--line)] bg-[#20201e] px-3 py-1.5 text-xs text-[#d0cec8] hover:bg-[#2d2d2a] hover:text-[#f4f2ec] disabled:opacity-50"
              >
                <Upload size={13} />
                <span>Upload Project (.ZIP)</span>
              </button>

              <button
                type="button"
                onClick={connect}
                disabled={loading}
                className="inline-flex items-center gap-1.5 rounded-md border border-[var(--line)] bg-[#20201e] px-3 py-1.5 text-xs text-[#d0cec8] hover:bg-[#2d2d2a] hover:text-[#f4f2ec] disabled:opacity-50"
              >
                <GitBranch size={13} />
                <span>Connect GitHub (OAuth)</span>
              </button>
            </div>

            <p className="text-[11px] text-[#85837c]">
              Public repos &amp; uploads scan instantly without authentication.
            </p>
          </div>
        </div>
      )}

      {status.connected && (
        <>
          {!status.installations.length ? (
            <div className="rounded-lg border border-[#c5aa54]/30 bg-[#c5aa54]/10 p-3 text-xs text-[#f4f2ec]">
              <p className="font-medium">Install the AuthScope GitHub App</p>
              <p className="mt-1 text-[11px] text-[#aaa8a1]">
                Authorization and installation are separate. Choose only the repositories the App may read.
              </p>
              <button
                type="button"
                onClick={install}
                className="mt-2 rounded-md border border-[#c5aa54]/40 bg-[#2d2d2a] px-3 py-1.5 text-xs hover:bg-[#373733]"
              >
                Install App on repositories
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {status.installations.length > 1 && (
                <label className="text-[11px] text-[#aaa8a1]">
                  GitHub account / installation
                  <select
                    value={installationId}
                    onChange={(event) => {
                      setInstallationId(event.target.value);
                      setRepositories([]);
                      setSelectedRepository("");
                      setBranches([]);
                      setSelectedBranch("");
                    }}
                    className="mt-1 block w-full rounded-md border border-[#41413d] bg-[#2d2d2a] px-2.5 py-2 text-xs text-[#f4f2ec]"
                  >
                    {status.installations.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.account_login} ({item.account_type})
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label className="text-[11px] text-[#aaa8a1]">
                Repository
                <select
                  value={selectedRepository}
                  onChange={(event) => {
                    setSelectedRepository(event.target.value);
                    setBranches([]);
                    setSelectedBranch("");
                  }}
                  disabled={loading || !repositories.length}
                  className="mt-1 block w-full rounded-md border border-[#41413d] bg-[#2d2d2a] px-2.5 py-2 text-xs text-[#f4f2ec]"
                >
                  <option value="">
                    {loading
                      ? "Loading repositories…"
                      : repositories.length
                      ? "Choose repository"
                      : "No accessible repositories"}
                  </option>
                  {repositories.map((repo) => (
                    <option key={repo.id} value={repo.full_name}>
                      {repo.full_name} · {repo.private ? "Private" : "Public"}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-[11px] text-[#aaa8a1]">
                Branch
                <select
                  value={selectedBranch}
                  onChange={(event) => setSelectedBranch(event.target.value)}
                  disabled={!branches.length || loading}
                  className="mt-1 block w-full rounded-md border border-[#41413d] bg-[#2d2d2a] px-2.5 py-2 text-xs text-[#f4f2ec]"
                >
                  <option value="">
                    {chosenRepository
                      ? loading
                        ? "Loading branches…"
                        : branches.length
                        ? "Choose branch"
                        : "No branches returned"
                      : "Choose a repository first"}
                  </option>
                  {branches.map((branch) => (
                    <option key={branch.name} value={branch.name}>
                      {branch.name} · {branch.commit_sha.slice(0, 12)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
          <div className="flex flex-wrap items-center justify-between gap-3">
            {status.installations.length > 0 && (
              <button
                type="button"
                onClick={install}
                className="text-[11px] text-[#5fa37f] underline"
              >
                Add or update installed repositories
              </button>
            )}
            {status.installations.length > 0 && (
              <button
                type="button"
                onClick={() => void startScan()}
                disabled={
                  !chosenRepository || !selectedBranch || scanning || loading
                }
                className="inline-flex items-center gap-2 rounded-lg bg-[#5fa37f] px-3.5 py-2 text-xs font-semibold text-[#102218] hover:brightness-105 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {scanning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Shield className="h-4 w-4" />
                )}
                Start Code Scan on Dashboard
              </button>
            )}
          </div>
        </>
      )}

      {notice && (
        <p
          role="status"
          className="rounded-md border border-[#5fa37f]/30 bg-[#5fa37f]/10 px-3 py-2 text-xs text-[#f4f2ec]"
        >
          {notice}
        </p>
      )}
      {error && (
        <p
          role="alert"
          className="flex items-start gap-2 rounded-md border border-[#d2675f]/40 bg-[#d2675f]/15 px-3 py-2 text-xs text-[#f4d2d2]"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          {error}
        </p>
      )}

      {scanning && (
        <div className="rounded-lg border border-[#5fa37f]/30 bg-[#2d2d2a] p-3">
          <p className="text-xs font-medium text-[#f4f2ec] flex items-center gap-2">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-[#5fa37f]" />
            Live AI source scan activity
          </p>
          <ol
            aria-live="polite"
            className="mt-2 space-y-1.5 text-[11px] text-[#d0cec8]"
          >
            {events.map((item) => (
              <li key={item.id} className="flex gap-2">
                <span className="text-[#5fa37f]">✓</span>
                <span>{item.message}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {status.connected && (
        <section className="border-t border-[#333330] pt-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-xs font-semibold text-[#d0cec8]">
              Source scan history (click a completed scan to open on main dashboard)
            </h3>
            <button
              type="button"
              onClick={() =>
                void loadHistory().catch((e: unknown) =>
                  setError(
                    e instanceof Error ? e.message : "Could not refresh history."
                  )
                )
              }
              className="inline-flex items-center gap-1 text-[10px] text-[#aaa8a1] hover:text-[#f4f2ec]"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          {!history.length ? (
            <p className="mt-2 text-[11px] text-[#85837c]">
              No source scans yet.
            </p>
          ) : (
            <div className="mt-2 space-y-1.5">
              {history.slice(0, 5).map((scan) => (
                <button
                  type="button"
                  key={scan.id}
                  onClick={() => void openHistory(scan.id)}
                  className={`flex w-full flex-wrap items-center justify-between gap-2 rounded-md border px-2.5 py-2 text-left ${
                    selectedScan?.id === scan.id
                      ? "border-[#5fa37f] bg-[#373733]"
                      : "border-[#41413d] bg-[#2d2d2a] hover:bg-[#373733]"
                  }`}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[11px] text-[#f4f2ec]">
                      {scan.owner}/{scan.repository} · {scan.branch}
                    </span>
                    <span className="block truncate font-mono text-[10px] text-[#85837c]">
                      {scan.commit_sha.slice(0, 12)} ·{" "}
                      {new Date(scan.created_at).toLocaleString()}
                    </span>
                  </span>
                  <span className="shrink-0 text-[10px] text-[#aaa8a1]">
                    {scan.status} · {scan.findings.length} findings
                  </span>
                </button>
              ))}
            </div>
          )}
        </section>
      )}

      {selectedScan && (
        <section className="space-y-3 border-t border-[#333330] pt-3">
          <div>
            <h3 className="text-sm font-semibold text-[#f4f2ec]">
              {selectedScan.owner}/{selectedScan.repository} ·{" "}
              {selectedScan.branch}
            </h3>
            <p className="mt-1 break-all font-mono text-[10px] text-[#85837c]">
              Commit {selectedScan.commit_sha} · {selectedScan.status}
            </p>
          </div>
          {selectedScan.findings.length === 0 ? (
            <p className="text-xs text-[#aaa8a1]">
              {selectedScan.status === "COMPLETED"
                ? "No findings from the supported static checks."
                : "Findings are not available until the scan completes."}
            </p>
          ) : (
            selectedScan.findings.map((finding) => {
              const fid = finding.finding_id;
              const review = finding.ai_review;
              const enriched = aiEnriched[fid];
              const whatBugDoes =
                enriched?.what_bug_can_do ||
                review?.what_attacker_can_do ||
                finding.detection_explanation;
              const howToFixList =
                enriched?.how_to_resolve?.length
                  ? enriched.how_to_resolve
                  : review?.how_to_fix?.length
                  ? review.how_to_fix
                  : [finding.remediation_hint];
              const codeChange =
                enriched?.secure_code_fix || review?.recommended_code_change || "";
              const fixText = [...howToFixList, codeChange]
                .filter(Boolean)
                .join("\n");
              const messages = qaHistory[fid] || [];

              return (
                <article
                  key={fid}
                  className="rounded-lg border border-[#41413d] bg-[#262624] p-4 space-y-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <span className="rounded border border-[#5fa37f]/40 bg-[#5fa37f]/10 px-2 py-0.5 text-[10px] font-semibold text-[#5fa37f]">
                        AI Source Code Finding · {finding.language}
                      </span>
                      <h4 className="mt-2 text-sm font-semibold text-[#f4f2ec]">
                        {review?.simple_title ||
                          finding.vulnerability_category.replaceAll("_", " ")}
                      </h4>
                    </div>
                    <span className="rounded bg-[#2d2d2a] border border-[#41413d] px-2 py-1 text-[10px] text-[#d0cec8]">
                      {finding.severity} · {finding.confidence}
                    </span>
                  </div>

                  {/* Location / URL */}
                  <div className="text-xs">
                    <span className="text-[#85837c]">Found in file: </span>
                    <code className="font-mono text-[#f4f2ec]">
                      {finding.file_path}:{finding.start_line}-{finding.end_line}
                    </code>{" "}
                    <a
                      href={finding.github_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] text-[#5fa37f] hover:underline ml-2"
                    >
                      View on GitHub <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>

                  {/* Proof / Code Snippet */}
                  <div>
                    <div className="text-[11px] font-semibold text-[#d0cec8] mb-1">
                      Proof (Vulnerable Source Code)
                    </div>
                    <pre className="max-h-48 overflow-auto rounded border border-[#41413d] bg-[#20201e] p-2.5 text-[11px] font-mono text-[#d0cec8]">
                      {finding.code_snippet}
                    </pre>
                  </div>

                  {/* What this bug can do & How to resolve it */}
                  <div className="border-l-2 border-[#5fa37f] pl-3.5 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h5 className="text-xs font-semibold text-[#f4f2ec]">
                        What this bug can do
                      </h5>
                      <button
                        type="button"
                        onClick={() => void enrichWithGeminiCodeApi(finding)}
                        disabled={aiEnrichLoading[fid]}
                        className="inline-flex items-center gap-1 rounded border border-[#41413d] bg-[#2d2d2a] px-2 py-1 text-[10px] text-[#5fa37f] hover:bg-[#373733] disabled:opacity-50"
                      >
                        <Sparkles className="h-3 w-3" />
                        {aiEnrichLoading[fid]
                          ? "Generating with Gemini API #2..."
                          : "Generate AI Code Fix (Gemini API #2)"}
                      </button>
                    </div>
                    <p className="text-xs leading-relaxed text-[#aaa8a1]">
                      {whatBugDoes}
                    </p>

                    <div className="flex items-center justify-between pt-1">
                      <h5 className="text-xs font-semibold text-[#f4f2ec]">
                        How to resolve it
                      </h5>
                      <button
                        type="button"
                        onClick={() => void copyText(finding, fixText)}
                        disabled={!fixText}
                        className="inline-flex items-center gap-1 rounded border border-[#41413d] px-2 py-0.5 text-[10px] text-[#d0cec8] hover:bg-[#373733]"
                      >
                        {copiedFinding === fid ? (
                          <Check className="h-3 w-3" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        {copiedFinding === fid ? "Copied" : "Copy fix"}
                      </button>
                    </div>
                    <ul className="space-y-1 text-xs text-[#d0cec8]">
                      {howToFixList.map((step, index) => (
                        <li key={index} className="flex items-baseline gap-2">
                          <span className="text-[#5fa37f]">✓</span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>

                    {codeChange && (
                      <div className="pt-1">
                        <div className="text-[10px] font-mono text-[#85837c] mb-1">
                          Secure code replacement (Gemini API #2):
                        </div>
                        <pre className="overflow-auto rounded border border-[#41413d] bg-[#20201e] p-2.5 text-[11px] font-mono text-[#5fa37f]">
                          {codeChange}
                        </pre>
                      </div>
                    )}
                  </div>

                  {/* Interactive Question-Answer for this GitHub finding (Gemini API #1) */}
                  <div className="pt-2 border-t border-[#333330] space-y-2">
                    <div className="text-[11px] font-medium text-[#aaa8a1]">
                      Ask a question about this bug (Gemini API #1)
                    </div>
                    {messages.length > 0 && (
                      <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                        {messages.map((m, mIdx) => (
                          <div
                            key={mIdx}
                            className={`rounded-lg px-3 py-2 text-xs leading-relaxed ${
                              m.role === "user"
                                ? "bg-[#373733] text-[#f4f2ec] ml-6"
                                : "bg-[#20201e] border border-[#41413d] text-[#d0cec8]"
                            }`}
                          >
                            {m.content}
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={qaInput[fid] || ""}
                        onChange={(e) =>
                          setQaInput((prev) => ({
                            ...prev,
                            [fid]: e.target.value,
                          }))
                        }
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            void askGeminiAboutRepoFinding(finding);
                          }
                        }}
                        placeholder="Ask about this file, impact, or how to patch it..."
                        className="flex-1 rounded-lg border border-[#41413d] bg-[#2d2d2a] px-3 py-1.5 text-xs text-[#f4f2ec] placeholder-[#85837c] focus:outline-none focus:border-[#5fa37f]"
                      />
                      <button
                        type="button"
                        disabled={
                          qaLoading[fid] || !(qaInput[fid] || "").trim()
                        }
                        onClick={() => void askGeminiAboutRepoFinding(finding)}
                        className="grid h-7 w-7 place-items-center rounded-md bg-[#373733] text-[#f4f2ec] hover:bg-[#5fa37f] hover:text-[#102218] disabled:opacity-40"
                      >
                        {qaLoading[fid] ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <ArrowUp className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <details className="border-t border-[#333330] pt-2">
                    <summary className="flex cursor-pointer list-none items-center gap-1 text-[11px] text-[#85837c]">
                      <ChevronDown className="h-3 w-3" />
                      Technical detector details
                    </summary>
                    <div className="mt-2 space-y-1 text-[10px] text-[#85837c]">
                      <p>
                        Rule: {finding.detection_method} · {finding.language}
                        {finding.function_name
                          ? ` · ${finding.function_name}`
                          : ""}
                      </p>
                      <p>Detector: {finding.detection_explanation}</p>
                    </div>
                  </details>
                </article>
              );
            })
          )}
        </section>
      )}
      <p className="flex items-start gap-1.5 text-[10px] leading-relaxed text-[#85837c]">
        <LockKeyhole className="mt-0.5 h-3 w-3 shrink-0" />
        Repository contents are treated as untrusted. AuthScope never executes repository code. Only redacted finding excerpts are sent to Gemini.
      </p>
    </section>
  );
}
