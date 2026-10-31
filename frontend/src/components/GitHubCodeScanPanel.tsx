"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertCircle, Check, ChevronDown, Copy, ExternalLink,
  GitBranch, Loader2, LockKeyhole, RefreshCw, Shield,
  Unplug,
} from "lucide-react";

interface GitHubAccount { id: string; login: string; avatar_url: string }
interface GitHubInstallation { id: number; account_login: string; account_type: string }
interface GitHubRepositoryItem {
  id: number; name: string; full_name: string; owner: string; private: boolean;
  description?: string | null; default_branch: string; html_url: string;
}
interface GitHubBranch { name: string; commit_sha: string }
interface GitHubFinding {
  finding_id: string; vulnerability_category: string; severity: string; confidence: string;
  classification: string; validation_status: string; file_path: string; language: string;
  function_name?: string | null; start_line: number; end_line: number; code_snippet: string;
  detection_explanation: string; detection_method: string; remediation_hint: string;
  repository: string; branch: string; commit_sha: string; github_url: string;
  ai_review?: {
    status: string; simple_title?: string; what_is_the_problem?: string;
    what_attacker_can_do?: string; affected_data_or_users?: string; why_it_happens?: string;
    how_to_fix?: string[]; recommended_code_change?: string; tests_to_add?: string[];
    additional_recommendations?: string[]; limitations?: string[]; message?: string;
  };
}
interface GitHubScan {
  id: string; installation_id: number; repository_id: number; owner: string; repository: string;
  branch: string; commit_sha: string; status: string; created_at: string; completed_at?: string | null;
  error_code?: string; languages: Record<string, number>; findings: GitHubFinding[];
}
interface GitHubStatus {
  connected: boolean; expired?: boolean; account: GitHubAccount | null; installations: GitHubInstallation[];
}
interface GitHubEvent { id: number; event_type: string; stage: string; message: string; timestamp: string }

function errorMessage(payload: unknown, fallback: string): string {
  const detail = (payload as { detail?: { code?: string; message?: string } | string })?.detail;
  if (typeof detail === "string") return detail;
  const code = detail?.code || "";
  const message = detail?.message || "";
  const messages: Record<string, string> = {
    GITHUB_NOT_CONFIGURED: "GitHub App setup is incomplete on the backend. Configure the App credentials, App slug, callback URL, and token encryption key.",
    GITHUB_NOT_CONNECTED: "Connect your GitHub account to continue.",
    GITHUB_AUTH_EXPIRED: "Your GitHub authorization expired. Reconnect GitHub and retry.",
    GITHUB_SESSION_EXPIRED: "Your AuthScope GitHub session expired. Connect GitHub again.",
    GITHUB_PERMISSION_DENIED: "This account or GitHub App cannot access that repository. Check the selected installation and its repository permissions.",
    GITHUB_APP_PERMISSION: "Set the GitHub App repository permissions to read-only for Metadata and Contents, then update the installation.",
    GITHUB_RATE_LIMIT: "GitHub's API rate limit was reached. Wait and try again.",
    SCAN_ALREADY_RUNNING: "Wait for your current source scan to finish before starting another.",
    SCAN_TIMEOUT: "The source scan exceeded the allowed run time. Try a smaller repository or contact the deployment owner.",
    EMPTY_OR_UNSUPPORTED_REPOSITORY: "No supported Python, JavaScript, or TypeScript files were found in this repository.",
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

export function GitHubCodeScanPanel({ apiBaseUrl }: { apiBaseUrl: string }) {
  const [status, setStatus] = useState<GitHubStatus>({ connected: false, account: null, installations: [] });
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
  const scanning = Boolean(activeScanId);

  const api = useCallback((path: string) => `${apiBaseUrl}${path}`, [apiBaseUrl]);
  const loadStatus = useCallback(async () => {
    const response = await fetch(api("/api/github/status"), { credentials: "include", cache: "no-store" });
    const payload = await readJson<GitHubStatus>(response, "Could not check GitHub connection status.");
    setStatus(payload);
    if (payload.installations.length && !payload.installations.some((item) => String(item.id) === installationId)) {
      setInstallationId(String(payload.installations[0].id));
    }
    return payload;
  }, [api, installationId]);

  const loadHistory = useCallback(async () => {
    const response = await fetch(api("/api/github/scans"), { credentials: "include", cache: "no-store" });
    const payload = await readJson<{ scans: GitHubScan[] }>(response, "Could not load source scan history.");
    setHistory(payload.scans);
    return payload.scans;
  }, [api]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const callbackStatus = params.get("github_status");
    if (callbackStatus) {
      const notices: Record<string, string> = {
        connected: "GitHub account connected. Install the AuthScope GitHub App on the repositories you want to scan.",
        installed: "GitHub App installation is ready. Select an installation and repository below.",
        not_configured: "GitHub is not configured on the backend. Set the App client ID/secret, callback URL, App slug, and token encryption key.",
        install_not_configured: "GitHub App installation is not configured. Set GITHUB_APP_SLUG on the backend.",
        denied: "GitHub authorization was cancelled or denied.",
        state_error: "The GitHub sign-in expired or could not be verified. Start again.",
        install_state_error: "The installation could not be verified. Start the install flow again.",
        install_failed: "GitHub installation completed, but AuthScope could not verify repository access.",
        install_cancelled: "GitHub App installation was cancelled.",
        connect_failed: "GitHub sign-in failed. Check the App callback URL and backend configuration.",
        callback_error: "GitHub did not return a valid authorization response.",
      };
      const message = notices[callbackStatus] || "GitHub returned an unknown connection status.";
      window.setTimeout(() => {
        if (callbackStatus === "connected" || callbackStatus === "installed") setNotice(message);
        else setError(message);
      }, 0);
      params.delete("github_status");
      const nextUrl = `${window.location.pathname}${params.size ? `?${params}` : ""}`;
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
      } catch (loadError) {
        setError(loadError instanceof Error ? loadError.message : "Could not load GitHub state.");
      }
    })();
    return () => streamRef.current?.close();
  // This mount effect intentionally reads the current callback state once.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!status.connected || !installationId) {
      return;
    }
    let cancelled = false;
    void (async () => {
      setLoading(true); setError(null);
      try {
        const response = await fetch(api(`/api/github/installations/${installationId}/repositories`), { credentials: "include", cache: "no-store" });
        const payload = await readJson<{ repositories: GitHubRepositoryItem[] }>(response, "Could not load installed repositories.");
        if (!cancelled) { setRepositories(payload.repositories); setSelectedRepository(""); }
      } catch (loadError: unknown) {
        if (!cancelled) setError(loadError instanceof Error ? loadError.message : "Could not load repositories.");
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [api, installationId, status.connected]);

  const chosenRepository = useMemo(
    () => repositories.find((item) => item.full_name === selectedRepository) || null,
    [repositories, selectedRepository],
  );

  useEffect(() => {
    if (!chosenRepository || !installationId) return;
    let cancelled = false;
    const path = `/api/github/installations/${installationId}/repositories/${encodeURIComponent(chosenRepository.owner)}/${encodeURIComponent(chosenRepository.name)}/branches`;
    void (async () => {
      setLoading(true); setError(null);
      try {
        const response = await fetch(api(path), { credentials: "include", cache: "no-store" });
        const payload = await readJson<{ branches: GitHubBranch[] }>(response, "Could not load repository branches.");
        if (!cancelled) { setBranches(payload.branches); setSelectedBranch(""); }
      } catch (loadError: unknown) {
        if (!cancelled) setError(loadError instanceof Error ? loadError.message : "Could not load branches.");
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [api, chosenRepository, installationId]);

  useEffect(() => {
    if (!activeScanId) return;
    streamRef.current?.close();
    const stream = new EventSource(api(`/api/github/scans/${activeScanId}/stream`), { withCredentials: true });
    streamRef.current = stream;
    stream.addEventListener("activity", (message) => {
      try { setEvents((current) => [...current, JSON.parse((message as MessageEvent).data) as GitHubEvent]); }
      catch { setError("A scan activity update could not be read."); }
    });
    stream.addEventListener("done", (message) => {
      try {
        const data = JSON.parse((message as MessageEvent).data) as { message?: string };
        setNotice(data.message || "Source scan completed.");
      } catch { setNotice("Source scan completed."); }
      stream.close(); setActiveScanId(null);
      void loadHistory().then((scans) => {
        const finished = scans.find((scan) => scan.id === activeScanId);
        if (finished) setSelectedScan(finished);
      });
    });
    stream.addEventListener("error", (message) => {
      if (!(message instanceof MessageEvent) || !message.data) return;
      try {
        const data = JSON.parse(message.data) as { metadata?: { code?: string }; message?: string };
        setError(errorMessage({ detail: { code: data.metadata?.code, message: data.message } }, "The source scan failed."));
      } catch { setError("The source scan failed. Reconnect GitHub and try again."); }
      stream.close(); setActiveScanId(null); void loadHistory();
    });
    stream.onerror = () => {
      if (stream.readyState === EventSource.CLOSED) {
        setError("The live scan stream closed unexpectedly. Check scan history for the final status.");
        stream.close(); setActiveScanId(null); void loadHistory();
      }
    };
    return () => stream.close();
  }, [activeScanId, api, loadHistory]);

  const connect = () => { window.location.href = api("/api/github/connect"); };
  const install = () => { window.location.href = api("/api/github/install"); };

  const disconnect = async () => {
    setLoading(true); setError(null);
    try {
      const response = await fetch(api("/api/github/disconnect"), { method: "DELETE", credentials: "include" });
      const result = await readJson<{ revoked: boolean }>(response, "Could not disconnect GitHub.");
      setStatus({ connected: false, account: null, installations: [] }); setHistory([]); setSelectedScan(null);
      setNotice(result.revoked ? "GitHub access was revoked and the local connection was deleted." : "The local connection was deleted. If needed, revoke AuthScope in your GitHub application settings.");
    } catch (disconnectError) {
      setError(disconnectError instanceof Error ? disconnectError.message : "Could not disconnect GitHub.");
    } finally { setLoading(false); }
  };

  const startScan = async () => {
    if (!chosenRepository || !selectedBranch || !installationId) return;
    setLoading(true); setError(null); setNotice(null); setEvents([]); setSelectedScan(null);
    try {
      const response = await fetch(api("/api/github/scans"), {
        method: "POST", credentials: "include", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ installation_id: Number(installationId), owner: chosenRepository.owner, repository: chosenRepository.name, branch: selectedBranch }),
      });
      const result = await readJson<{ scan_id: string }>(response, "Could not start the source scan.");
      setActiveScanId(result.scan_id);
      const scans = await loadHistory();
      const created = scans.find((scan) => scan.id === result.scan_id);
      if (created) setSelectedScan(created);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Could not start the source scan.");
    } finally { setLoading(false); }
  };

  const openHistory = async (scanId: string) => {
    setError(null); setNotice(null);
    try {
      const response = await fetch(api(`/api/github/scans/${scanId}`), { credentials: "include", cache: "no-store" });
      setSelectedScan(await readJson<GitHubScan>(response, "Could not open this source scan."));
    } catch (historyError) {
      setError(historyError instanceof Error ? historyError.message : "Could not open this source scan.");
    }
  };

  const copyText = async (finding: GitHubFinding, value: string) => {
    try { await navigator.clipboard.writeText(value); setCopiedFinding(finding.finding_id); window.setTimeout(() => setCopiedFinding(null), 1500); }
    catch { setError("Could not copy the recommendation to the clipboard."); }
  };

  return (
    <section className="mt-4 rounded-xl border border-[#1E293B] bg-[#0F172A]/70 p-4 sm:p-5 space-y-4 text-left">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100"><GitBranch className="h-4 w-4 text-blue-400" />Connect your GitHub repository</h2>
          <p className="mt-1 text-xs text-gray-400">Let AuthScope inspect your project&apos;s source code and find potential security problems.</p>
        </div>
        {status.connected ? (
          <button type="button" onClick={() => void disconnect()} disabled={loading} className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 disabled:opacity-50"><Unplug className="h-3.5 w-3.5" />Disconnect</button>
        ) : <span className="rounded-full border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-[10px] text-zinc-400">Not connected</span>}
      </div>

      {status.connected && status.account ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-emerald-500/20 bg-emerald-950/10 p-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-600/20 text-blue-200"><GitBranch className="h-4 w-4" /></span>
          <div className="min-w-0"><p className="text-xs font-medium text-emerald-200">Connected as @{status.account.login}</p><p className="text-[10px] text-zinc-500">GitHub user {status.account.id} · read-only repository access</p></div>
          {status.expired && <button type="button" onClick={connect} className="text-[10px] text-amber-300 underline">Authorization expired · reconnect</button>}
        </div>
      ) : <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={connect} disabled={loading} className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"><GitBranch className="h-4 w-4" />Connect GitHub</button>
        <p className="text-[11px] text-zinc-500">GitHub credentials stay on the backend. AuthScope never asks for a password or personal access token.</p>
      </div>}

      {status.connected && <>
        {!status.installations.length ? <div className="rounded-lg border border-amber-500/20 bg-amber-950/10 p-3 text-xs text-amber-100">
          <p className="font-medium">Install the AuthScope GitHub App</p>
          <p className="mt-1 text-[11px] text-amber-100/70">Authorization and installation are separate. Choose only the repositories the App may read.</p>
          <button type="button" onClick={install} className="mt-2 rounded-md border border-amber-400/30 px-3 py-1.5 text-xs hover:bg-amber-900/30">Install App on repositories</button>
        </div> : <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {status.installations.length > 1 && <label className="text-[11px] text-zinc-400">GitHub account / installation<select value={installationId} onChange={(event) => { setInstallationId(event.target.value); setRepositories([]); setSelectedRepository(""); setBranches([]); setSelectedBranch(""); }} className="mt-1 block w-full rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-2 text-xs text-zinc-100">{status.installations.map((item) => <option key={item.id} value={item.id}>{item.account_login} ({item.account_type})</option>)}</select></label>}
          <label className="text-[11px] text-zinc-400">Repository<select value={selectedRepository} onChange={(event) => { setSelectedRepository(event.target.value); setBranches([]); setSelectedBranch(""); }} disabled={loading || !repositories.length} className="mt-1 block w-full rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-2 text-xs text-zinc-100"><option value="">{loading ? "Loading repositories…" : repositories.length ? "Choose repository" : "No accessible repositories"}</option>{repositories.map((repo) => <option key={repo.id} value={repo.full_name}>{repo.full_name} · {repo.private ? "Private" : "Public"}</option>)}</select>{chosenRepository?.description && <span className="mt-1 block text-[10px] text-zinc-500">{chosenRepository.description}</span>}{chosenRepository && <span className="mt-1 block text-[10px] text-zinc-500">{chosenRepository.private ? "Private" : "Public"} repository · default branch {chosenRepository.default_branch}</span>}</label>
          <label className="text-[11px] text-zinc-400">Branch<select value={selectedBranch} onChange={(event) => setSelectedBranch(event.target.value)} disabled={!branches.length || loading} className="mt-1 block w-full rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-2 text-xs text-zinc-100"><option value="">{chosenRepository ? (loading ? "Loading branches…" : branches.length ? "Choose branch" : "No branches returned") : "Choose a repository first"}</option>{branches.map((branch) => <option key={branch.name} value={branch.name}>{branch.name} · {branch.commit_sha.slice(0, 12)}</option>)}</select>{selectedBranch && branches.find((branch) => branch.name === selectedBranch) && <span className="mt-1 block break-all font-mono text-[10px] text-zinc-500">Commit: {branches.find((branch) => branch.name === selectedBranch)?.commit_sha}</span>}</label>
        </div>}
        {status.installations.length > 0 && <button type="button" onClick={install} className="text-[10px] text-blue-300 underline">Add or update installed repositories</button>}
        {status.installations.length > 0 && <button type="button" onClick={() => void startScan()} disabled={!chosenRepository || !selectedBranch || scanning || loading} className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40">{scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}Start Code Scan</button>}
      </>}

      {notice && <p role="status" className="rounded-md border border-emerald-500/20 bg-emerald-950/10 px-3 py-2 text-xs text-emerald-200">{notice}</p>}
      {error && <p role="alert" className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-950/20 px-3 py-2 text-xs text-red-200"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</p>}

      {scanning && <div className="rounded-lg border border-blue-500/20 bg-blue-950/10 p-3"><p className="text-xs font-medium text-blue-200">Live source scan activity</p><ol aria-live="polite" className="mt-2 space-y-1 text-[11px] text-zinc-300">{events.map((item) => <li key={item.id} className="flex gap-2"><span className="text-blue-400">•</span>{item.message}</li>)}</ol></div>}

      {status.connected && <section className="border-t border-zinc-800 pt-3">
        <div className="flex items-center justify-between gap-2"><h3 className="text-xs font-semibold text-zinc-200">Source scan history</h3><button type="button" onClick={() => void loadHistory().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not refresh history."))} className="inline-flex items-center gap-1 text-[10px] text-zinc-400 hover:text-zinc-200"><RefreshCw className="h-3 w-3" />Refresh</button></div>
        {!history.length ? <p className="mt-2 text-[11px] text-zinc-500">No source scans yet.</p> : <div className="mt-2 space-y-1.5">{history.map((scan) => <button type="button" key={scan.id} onClick={() => void openHistory(scan.id)} className={`flex w-full flex-wrap items-center justify-between gap-2 rounded-md border px-2.5 py-2 text-left ${selectedScan?.id === scan.id ? "border-blue-500/40 bg-blue-950/20" : "border-zinc-800 bg-zinc-950/60 hover:bg-zinc-900"}`}><span className="min-w-0"><span className="block truncate text-[11px] text-zinc-200">{scan.owner}/{scan.repository} · {scan.branch}</span><span className="block truncate font-mono text-[10px] text-zinc-500">{scan.commit_sha.slice(0, 12)} · {new Date(scan.created_at).toLocaleString()}</span></span><span className="shrink-0 text-[10px] text-zinc-400">{scan.status} · {scan.findings.length} findings</span></button>)}</div>}
      </section>}

      {selectedScan && <section className="space-y-3 border-t border-zinc-800 pt-3">
        <div><h3 className="text-sm font-semibold text-zinc-100">{selectedScan.owner}/{selectedScan.repository} · {selectedScan.branch}</h3><p className="mt-1 break-all font-mono text-[10px] text-zinc-500">Commit {selectedScan.commit_sha} · {selectedScan.status} · {new Date(selectedScan.created_at).toLocaleString()}</p></div>
        {Object.keys(selectedScan.languages).length > 0 && <p className="text-[10px] text-zinc-400">Languages detected: {Object.entries(selectedScan.languages).map(([language, count]) => `${language} (${count})`).join(", ")}</p>}
        {selectedScan.findings.length === 0 ? <p className="text-xs text-zinc-400">{selectedScan.status === "COMPLETED" ? "No findings from the supported static checks." : "Findings are not available until the scan completes."}</p> : selectedScan.findings.map((finding) => {
          const review = finding.ai_review;
          const fixText = [...(review?.how_to_fix || []), review?.recommended_code_change || finding.remediation_hint].filter(Boolean).join("\n");
          return <article key={finding.finding_id} className="rounded-lg border border-amber-500/20 bg-[#0A0E17] p-3.5 space-y-3">
            <div className="flex flex-wrap items-start justify-between gap-2"><div><span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[9px] font-semibold text-amber-200">Source Code Finding · Runtime NOT TESTED</span><h4 className="mt-2 text-sm font-semibold text-zinc-100">{review?.simple_title || finding.vulnerability_category.replaceAll("_", " ")}</h4></div><span className="rounded bg-zinc-800 px-2 py-1 text-[10px] text-zinc-300">{finding.severity} · {finding.confidence}</span></div>
            <section className="space-y-1"><h5 className="text-xs font-semibold text-zinc-200">What is the problem?</h5><p className="text-xs leading-relaxed text-zinc-300">{review?.what_is_the_problem || finding.detection_explanation}</p></section>
            <section className="space-y-1"><h5 className="text-xs font-semibold text-zinc-200">What can an attacker do?</h5><p className="text-xs leading-relaxed text-zinc-300">{review?.what_attacker_can_do || "The static code pattern suggests a possible misuse path. Runtime exploitability has not been tested."}</p></section>
            <section className="space-y-1"><h5 className="text-xs font-semibold text-zinc-200">Where is the problem?</h5><p className="break-all font-mono text-[10px] text-zinc-400">{finding.repository} · {finding.branch} · {finding.commit_sha} · {finding.file_path}:{finding.start_line}-{finding.end_line}</p><pre className="max-h-48 overflow-auto rounded bg-zinc-950 p-2 text-[10px] text-zinc-300">{finding.code_snippet}</pre><a href={finding.github_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[10px] text-blue-300 hover:text-blue-200">Open verified source location <ExternalLink className="h-3 w-3" /></a></section>
            <section className="space-y-1"><h5 className="text-xs font-semibold text-zinc-200">How serious is it?</h5><p className="text-xs text-zinc-300">Engine risk: {finding.severity} · Static status: {finding.validation_status} · {finding.classification.replaceAll("_", " ")}. A static result does not confirm runtime exploitability.</p></section>
            <section className="space-y-1"><div className="flex items-center justify-between"><h5 className="text-xs font-semibold text-zinc-200">How to fix it</h5><button type="button" onClick={() => void copyText(finding, fixText)} disabled={!fixText} className="inline-flex items-center gap-1 rounded border border-zinc-700 px-2 py-1 text-[10px] text-zinc-300 disabled:opacity-40">{copiedFinding === finding.finding_id ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}{copiedFinding === finding.finding_id ? "Copied" : "Copy fix"}</button></div>{review?.how_to_fix?.length ? <ol className="list-decimal space-y-1 pl-5 text-xs text-zinc-300">{review.how_to_fix.map((step, index) => <li key={`${index}-${step}`}>{step}</li>)}</ol> : <p className="text-xs text-zinc-300">{finding.remediation_hint || "Review the surrounding authorization and input-handling logic."}</p>}{review?.recommended_code_change && <pre className="overflow-auto rounded bg-zinc-950 p-2 text-[10px] text-emerald-200">{review.recommended_code_change}</pre>}{review?.tests_to_add?.length ? <ul className="list-disc space-y-1 pl-5 text-[11px] text-zinc-400">{review.tests_to_add.map((test, index) => <li key={`${index}-${test}`}>{test}</li>)}</ul> : null}</section>
            {review?.additional_recommendations?.length ? <section><h5 className="text-xs font-semibold text-zinc-200">Additional recommendations</h5><ul className="mt-1 list-disc pl-5 text-[11px] text-zinc-400">{review.additional_recommendations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul></section> : null}
            {review?.limitations?.map((item, index) => <p key={`${index}-${item}`} className="text-[10px] text-amber-200">{item}</p>)}
            <details className="border-t border-zinc-800 pt-2"><summary className="flex cursor-pointer list-none items-center gap-1 text-[11px] text-zinc-400"><ChevronDown className="h-3 w-3" />Technical details</summary><div className="mt-2 space-y-1 text-[10px] text-zinc-500"><p>Rule: {finding.detection_method} · {finding.language}{finding.function_name ? ` · ${finding.function_name}` : ""}</p><p>Detector: {finding.detection_explanation}</p><p>Finding ID: {finding.finding_id}</p>{review?.status !== "available" && <p>{review?.message || "AI explanation is unavailable. The deterministic static finding remains unchanged."}</p>}</div></details>
          </article>;
        })}
      </section>}
      <p className="flex items-start gap-1.5 text-[10px] leading-relaxed text-zinc-500"><LockKeyhole className="mt-0.5 h-3 w-3 shrink-0" />Repository contents are treated as untrusted. AuthScope never executes repository code. Only redacted finding excerpts are sent to Gemini; tokens and credentials are excluded.</p>
    </section>
  );
}
