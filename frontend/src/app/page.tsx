"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import {
  Shield,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Loader2,
  StopCircle,
  RotateCcw,
  Copy,
  ExternalLink,
  GitBranch,
  UploadCloud,
  FileArchive,
  X,
  RefreshCw,
  Sparkles,
} from "lucide-react";
import {
  AssessmentState,
  AssessmentActivityEvent,
  FindingItem,
  EvidenceArtifactModel,
} from "@/types/assessment";
import { AgentActivityPanel } from "@/components/AgentActivityPanel";
import { FindingCard } from "@/components/FindingCard";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/**
 * Maps raw backend finding records into typed FindingItem structures
 * for the progressive finding card components.
 */
function mapRecordToFindingItem(rec: Record<string, unknown>): FindingItem {
  const id = String(rec.id || `f-${Date.now()}`);
  const endpoint = String(rec.endpoint || rec.target_endpoint || "");
  const method = String(rec.http_method || "GET");
  const category = String(
    rec.vulnerability_category || rec.vulnerability_type || "BOLA_IDOR"
  );
  const title = String(rec.title || `${category} on ${endpoint}`);
  const severity = String(rec.severity || "MEDIUM").toUpperCase();
  const confirmation_status = String(
    rec.confirmation_status || rec.status || "confirmed"
  ).toUpperCase();
  const validation_status = String(
    rec.validation_status || "CONFIRMED"
  ).toUpperCase();
  const explanation = String(
    rec.impact_explanation ||
      rec.description ||
      `Differential authorization discrepancy observed on ${endpoint}.`
  );

  const technicalDetails =
    (rec.technical_details as Record<string, unknown>) || {};
  const evidenceObj =
    (rec.evidence as EvidenceArtifactModel) || null;

  const source_file =
    (technicalDetails.source_file as string) ||
    (rec.source_file as string) ||
    null;
  const function_name =
    (technicalDetails.function_name as string) ||
    (rec.function_name as string) ||
    null;
  const line_numbers =
    (technicalDetails.line_numbers as string) ||
    (rec.line_numbers as string) ||
    null;
  const vulnerable_code =
    (technicalDetails.vulnerable_code as string) ||
    (rec.vulnerable_code as string) ||
    null;
  const suggested_code =
    (technicalDetails.suggested_code as string) ||
    (rec.suggested_code as string) ||
    null;

  const how_to_fix = String(
    rec.remediation_recommendation ||
      rec.remediation_guidance ||
      "Enforce server-side access control checks before returning resource data."
  );

  return {
    id,
    title,
    vulnerability_category: category,
    severity,
    confidence: confirmation_status,
    validation_status,
    explanation,
    affected_endpoint: endpoint,
    http_method: method,
    source_file,
    function_name,
    line_numbers,
    vulnerable_code,
    suggested_code,
    how_to_fix,
    expected_behavior: rec.expected_behavior
      ? String(rec.expected_behavior)
      : undefined,
    actual_behavior: rec.actual_behavior
      ? String(rec.actual_behavior)
      : undefined,
    evidence: evidenceObj,
  };
}

export default function Home() {
  // Input states
  const [targetUrl, setTargetUrl] = useState<string>("http://localhost:3000");
  const [githubRepo, setGithubRepo] = useState<string>("");
  const [sourceArchive, setSourceArchive] = useState<File | null>(null);
  const [showAdvancedInputs, setShowAdvancedInputs] = useState<boolean>(false);

  // Assessment lifecycle states
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [status, setStatus] = useState<AssessmentState>("ready");
  const [error, setError] = useState<string | null>(null);

  // Operational events and progressive findings
  const [activityEvents, setActivityEvents] = useState<AssessmentActivityEvent[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [isActivityExpanded, setIsActivityExpanded] = useState<boolean>(false);

  // Streaming text output
  const [streamingText, setStreamingText] = useState<string>("");

  // Elapsed time tracking
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);

  // Reconnection tracking
  const [reconnectAttempts, setReconnectAttempts] = useState<number>(0);
  const maxReconnectAttempts = 3;

  // Refs
  const eventSourceRef = useRef<EventSource | null>(null);
  const messageEndRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const connectSSERef = useRef<((scanId: string) => void) | null>(null);

  // Timer effect for tracking elapsed duration
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    const isActivelyRunning =
      status === "running" ||
      status === "connecting" ||
      status === "analyzing" ||
      status === "findings_discovered" ||
      status === "reconnecting";

    if (isActivelyRunning && startTime) {
      timer = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000));
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [status, startTime]);

  // Auto-scroll as messages and findings stream in
  useEffect(() => {
    const isActivelyRunning =
      status === "running" ||
      status === "connecting" ||
      status === "analyzing" ||
      status === "findings_discovered";

    if (isActivelyRunning) {
      messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [streamingText, activityEvents.length, findings.length, status]);

  /**
   * Refetches full assessment record from backend SQLite repository
   * to populate structured findings and detailed evidence artifacts.
   */
  const fetchAssessmentDetails = useCallback(async (id: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments/${id}`);
      if (!res.ok) return;
      const data = await res.json();

      if (Array.isArray(data.findings) && data.findings.length > 0) {
        const mapped = data.findings.map((f: Record<string, unknown>) =>
          mapRecordToFindingItem(f)
        );
        setFindings(mapped);
      }
    } catch (err) {
      console.warn("Could not fetch detailed assessment findings:", err);
    }
  }, []);

  /**
   * Restores last assessment on browser refresh if preserved in localStorage.
   */
  useEffect(() => {
    const savedId = localStorage.getItem("authscope_last_assessment_id");
    if (savedId && !assessmentId && status === "ready") {
      fetch(`${API_BASE_URL}/api/assessments/${savedId}`)
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error("Not found");
        })
        .then((data) => {
          setAssessmentId(data.id);
          setTargetUrl(data.target_url);

          const backendStatus = String(data.status).toLowerCase();
          if (backendStatus === "completed") {
            const hasFindings =
              (data.confirmed_findings_count || 0) > 0 ||
              (data.suspicious_results_count || 0) > 0;
            setStatus(hasFindings ? "completed" : "no_vulnerabilities");
          } else if (backendStatus === "failed") {
            setStatus("failed");
          } else if (backendStatus === "cancelled") {
            setStatus("cancelled");
          } else {
            setStatus("running");
          }

          setActivityEvents(data.events || []);
          setStreamingText(data.markdown_content || "");

          if (Array.isArray(data.findings) && data.findings.length > 0) {
            setFindings(
              data.findings.map((f: Record<string, unknown>) =>
                mapRecordToFindingItem(f)
              )
            );
          }

          setElapsedSeconds(
            data.completed_at && data.started_at
              ? Math.max(
                  1,
                  Math.floor(
                    (new Date(data.completed_at).getTime() -
                      new Date(data.started_at).getTime()) /
                      1000
                  )
                )
              : 12
          );
        })
        .catch(() => {
          localStorage.removeItem("authscope_last_assessment_id");
        });
    }
  }, [assessmentId, status]);

  /**
   * Connects to the SSE stream with automatic reconnection support.
   */
  const connectSSE = useCallback(
    (scanId: string) => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      const es = new EventSource(`${API_BASE_URL}/api/assessments/${scanId}/stream`);
      eventSourceRef.current = es;

      es.addEventListener("activity", (e: MessageEvent) => {
        try {
          const eventItem: AssessmentActivityEvent = JSON.parse(e.data);
          setActivityEvents((prev) => [...prev, eventItem]);

          // Dynamically map operational stage to UI state
          const etype = eventItem.event_type;
          const stage = eventItem.stage;

          if (
            etype === "finding_confirmed" ||
            etype === "suspicious_behavior_detected"
          ) {
            setStatus("findings_discovered");
            // Asynchronously fetch full finding records
            fetchAssessmentDetails(scanId);
          } else if (
            stage === "endpoint_discovery" ||
            stage === "session_verification" ||
            stage === "authorization_testing" ||
            stage === "evidence_validation"
          ) {
            setStatus((prev) =>
              prev === "findings_discovered" ? "findings_discovered" : "analyzing"
            );
          } else if (
            stage === "target_connection" ||
            stage === "scope_validation"
          ) {
            setStatus((prev) =>
              prev === "findings_discovered" ? "findings_discovered" : "connecting"
            );
          }
        } catch (err) {
          console.error("Failed to parse SSE activity event:", err);
        }
      });

      es.addEventListener("message", (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload.text) {
            setStreamingText((prev) => prev + payload.text);
          }
        } catch (err) {
          console.error("Failed to parse SSE message chunk:", err);
        }
      });

      es.addEventListener("done", (e: MessageEvent) => {
        try {
          const doneData = JSON.parse(e.data);
          const rawStatus = String(doneData.status || "").toLowerCase();

          if (rawStatus === "failed") {
            setStatus("failed");
          } else if (rawStatus === "cancelled") {
            setStatus("cancelled");
          } else {
            const confirmed = Number(doneData.confirmed_findings || 0);
            const suspicious = Number(doneData.suspicious_results || 0);
            if (confirmed === 0 && suspicious === 0) {
              setStatus("no_vulnerabilities");
            } else {
              setStatus("completed");
            }
          }
        } catch {
          setStatus("completed");
        }

        // Fetch complete final findings from repository
        fetchAssessmentDetails(scanId);
        setReconnectAttempts(0);
        es.close();
      });

      es.addEventListener("error", (e: Event) => {
        console.warn("SSE connection interrupted:", e);
        es.close();

        // Check if stream closed after completion or needs reconnection
        setStatus((prevStatus) => {
          if (
            prevStatus === "completed" ||
            prevStatus === "no_vulnerabilities" ||
            prevStatus === "cancelled" ||
            prevStatus === "failed"
          ) {
            return prevStatus;
          }

          // Attempt reconnection if active
          if (reconnectAttempts < maxReconnectAttempts) {
            setReconnectAttempts((prev) => prev + 1);
            setTimeout(() => {
              connectSSERef.current?.(scanId);
            }, 2000 * (reconnectAttempts + 1));
            return "reconnecting";
          } else {
            setError(
              "SSE stream connection lost. Backend testing may have finished or timed out."
            );
            return "failed";
          }
        });
      });
    },
    [fetchAssessmentDetails, reconnectAttempts]
  );

  useEffect(() => {
    connectSSERef.current = connectSSE;
  }, [connectSSE]);

  /**
   * Dispatches assessment initiation to backend FastAPI.
   */
  const startAssessment = async (urlOverride?: string) => {
    const finalUrl = (urlOverride || targetUrl).trim();
    if (!finalUrl) {
      setError("Please specify an authorized target URL.");
      return;
    }

    setError(null);
    setStatus("connecting");
    setStreamingText("");
    setActivityEvents([]);
    setFindings([]);
    setIsActivityExpanded(false);
    setReconnectAttempts(0);

    const now = Date.now();
    setStartTime(now);
    setElapsedSeconds(0);

    try {
      // 1. Submit POST request to backend
      const res = await fetch(`${API_BASE_URL}/api/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: finalUrl }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Assessment launch failed.");
      }

      const scanId = data.assessment_id;
      setAssessmentId(scanId);
      localStorage.setItem("authscope_last_assessment_id", scanId);

      // 2. Open EventSource stream
      connectSSE(scanId);
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to start assessment.";
      setError(msg);
      setStatus("failed");
    }
  };

  /**
   * Safely cancels an active security assessment.
   */
  const stopAssessment = async () => {
    if (!assessmentId) return;
    try {
      await fetch(`${API_BASE_URL}/api/assessments/${assessmentId}/stop`, {
        method: "POST",
      });
      setStatus("cancelled");
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    } catch (err) {
      console.error("Error stopping assessment:", err);
    }
  };

  /**
   * Resets the UI back to initial ChatGPT-like prompt screen.
   */
  const resetAssessment = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    localStorage.removeItem("authscope_last_assessment_id");
    setAssessmentId(null);
    setStatus("ready");
    setStreamingText("");
    setActivityEvents([]);
    setFindings([]);
    setIsActivityExpanded(false);
    setError(null);
    setReconnectAttempts(0);
    setGithubRepo("");
    setSourceArchive(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSourceArchive(file);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-[#0B0F17] text-[#F9FAFB]">
      {/* =================================================================== */}
      {/* 1. TOP MINIMAL BAR                                                  */}
      {/* =================================================================== */}
      <header className="sticky top-0 z-50 flex items-center justify-between px-6 py-3.5 border-b border-[#1E293B]/70 bg-[#0B0F17]/90 backdrop-blur">
        <div className="flex items-center gap-2.5">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-blue-600/15 border border-blue-500/30 text-blue-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <span className="font-semibold text-base tracking-tight text-white">
              AuthScope
            </span>
            <span className="ml-2 text-xs text-gray-400 font-mono">
              AI Security Agent
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#111827] border border-[#1E293B] text-[11px] font-mono text-gray-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Scope: localhost:3000
          </div>

          {status !== "ready" && (
            <button
              onClick={resetAssessment}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-300 hover:text-white bg-[#111827] hover:bg-[#1E293B] border border-[#1E293B] rounded-lg transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              New Assessment
            </button>
          )}
        </div>
      </header>

      {/* =================================================================== */}
      {/* MAIN CONTAINER                                                      */}
      {/* =================================================================== */}
      <main className="flex-1 flex flex-col items-center justify-start max-w-3xl w-full mx-auto px-4 sm:px-6 py-8">
        {/* =================================================================== */}
        {/* 2. INITIAL CHATGPT-LIKE HOME SCREEN (Status: Ready)                 */}
        {/* =================================================================== */}
        {status === "ready" && (
          <div className="flex-1 flex flex-col items-center justify-center w-full my-auto text-center py-12">
            <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 mb-6 shadow-lg shadow-blue-500/5">
              <Shield className="w-7 h-7" />
            </div>

            <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-white mb-3">
              What should I secure?
            </h1>
            <p className="text-sm sm:text-base text-gray-400 max-w-lg mb-8 leading-relaxed">
              Enter an authorized web application or API URL to test for Broken
              Object Level Authorization (IDOR), privilege escalation, and access
              control bypasses.
            </p>

            {/* Main Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                startAssessment();
              }}
              className="w-full max-w-xl text-left"
            >
              {/* Primary URL Input Bar */}
              <div className="relative flex items-center bg-[#111827] border border-[#263248] focus-within:border-blue-500/70 focus-within:ring-2 focus-within:ring-blue-500/20 rounded-2xl p-2 transition-all shadow-xl shadow-black/40">
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="http://localhost:3000"
                  className="flex-1 bg-transparent px-4 py-3 text-sm sm:text-base text-white placeholder-gray-500 focus:outline-none font-mono"
                />
                <button
                  type="submit"
                  disabled={!targetUrl.trim()}
                  className="flex items-center justify-center px-4 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 text-white font-medium text-sm transition-colors shrink-0"
                >
                  Start Assessment
                  <ArrowRight className="w-4 h-4 ml-1.5" />
                </button>
              </div>

              {/* Quick suggestion button */}
              <div className="flex items-center justify-between mt-3 text-xs text-gray-400">
                <div className="flex items-center gap-1.5">
                  <span>Authorized target:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetUrl("http://localhost:3000");
                    }}
                    className="px-2 py-0.5 rounded bg-[#161F30] hover:bg-[#1E2D4A] border border-blue-500/30 text-blue-400 font-mono transition-colors flex items-center gap-1"
                  >
                    http://localhost:3000 (Juice Shop)
                    <ExternalLink className="w-2.5 h-2.5" />
                  </button>
                </div>

                {/* Toggle optional source code & repo inputs */}
                <button
                  type="button"
                  onClick={() => setShowAdvancedInputs(!showAdvancedInputs)}
                  className="text-xs text-gray-400 hover:text-blue-400 transition-colors flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3 text-blue-400" />
                  {showAdvancedInputs ? "Hide source context" : "Add source code (optional)"}
                </button>
              </div>

              {/* Expandable Optional Source Code & Repository Input */}
              {showAdvancedInputs && (
                <div className="mt-4 p-4 rounded-xl bg-[#111827]/80 border border-[#1E293B] space-y-3.5 animate-in fade-in duration-200">
                  <div className="text-xs font-medium text-gray-300">
                    Optional Source Code Context
                  </div>
                  <p className="text-[11px] text-gray-400 leading-normal">
                    Provide a repository or source archive to map detected runtime vulnerabilities directly to source code files and functions.
                  </p>

                  {/* GitHub Repo Input */}
                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      GitHub Repository URL
                    </label>
                    <div className="flex items-center gap-2 bg-[#0A0E17] border border-[#263248] rounded-lg px-3 py-2 text-xs font-mono text-gray-200">
                      <GitBranch className="w-4 h-4 text-gray-400 shrink-0" />
                      <input
                        type="text"
                        value={githubRepo}
                        onChange={(e) => setGithubRepo(e.target.value)}
                        placeholder="https://github.com/juice-shop/juice-shop"
                        className="flex-1 bg-transparent placeholder-gray-600 focus:outline-none text-xs"
                      />
                    </div>
                  </div>

                  {/* Source Archive Upload */}
                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      Source Archive (.zip, .tar.gz)
                    </label>
                    <div className="flex items-center gap-2">
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".zip,.tar.gz,.tgz"
                        onChange={handleFileUpload}
                        className="hidden"
                        id="source-archive-upload"
                      />
                      <label
                        htmlFor="source-archive-upload"
                        className="cursor-pointer flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0A0E17] hover:bg-[#161F30] border border-[#263248] text-xs font-mono text-gray-300 transition-colors"
                      >
                        <UploadCloud className="w-4 h-4 text-blue-400" />
                        <span>{sourceArchive ? "Change file" : "Choose archive"}</span>
                      </label>

                      {sourceArchive && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-blue-600/10 border border-blue-500/30 text-blue-300 text-xs font-mono">
                          <FileArchive className="w-3.5 h-3.5 text-blue-400" />
                          <span className="truncate max-w-[200px]">
                            {sourceArchive.name}
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              setSourceArchive(null);
                              if (fileInputRef.current) {
                                fileInputRef.current.value = "";
                              }
                            }}
                            className="text-gray-400 hover:text-white ml-1"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Error message */}
              {error && (
                <div className="mt-4 p-3 rounded-xl bg-red-950/40 border border-red-700/50 text-red-300 text-xs flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" />
                  <span>{error}</span>
                </div>
              )}
            </form>
          </div>
        )}

        {/* =================================================================== */}
        {/* 3. CONVERSATIONAL STREAMING SCREEN (Active Assessment)              */}
        {/* =================================================================== */}
        {status !== "ready" && (
          <div className="w-full flex flex-col space-y-6 pb-28">
            {/* User Target Prompt */}
            <div className="flex items-start gap-3 w-full">
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center shrink-0 text-white text-xs font-bold shadow-md shadow-blue-600/30">
                U
              </div>
              <div className="flex-1">
                <div className="text-xs text-gray-400 mb-1">Target Application</div>
                <div className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#161F30] border border-[#263248] font-mono text-sm text-blue-300">
                  <span>{targetUrl}</span>
                  {githubRepo && (
                    <span className="text-[11px] px-2 py-0.5 rounded bg-[#111827] text-gray-400 border border-gray-700 flex items-center gap-1">
                      <GitBranch className="w-3 h-3" />
                      Repo Linked
                    </span>
                  )}
                  {sourceArchive && (
                    <span className="text-[11px] px-2 py-0.5 rounded bg-[#111827] text-gray-400 border border-gray-700 flex items-center gap-1">
                      <FileArchive className="w-3 h-3" />
                      Archive Loaded
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Agent Streaming Response Area */}
            <div className="flex items-start gap-3 w-full">
              <div className="w-7 h-7 rounded-full bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400 shadow-md shadow-emerald-500/10">
                <Shield className="w-4 h-4" />
              </div>

              <div className="flex-1 w-full overflow-hidden">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs text-gray-400">AuthScope Agent</div>
                  {/* Status Indicator Badge */}
                  <div className="text-[11px] font-mono">
                    {status === "connecting" && (
                      <span className="text-blue-400">Connecting to target...</span>
                    )}
                    {status === "analyzing" && (
                      <span className="text-indigo-400">Analyzing routes & auth...</span>
                    )}
                    {status === "findings_discovered" && (
                      <span className="text-amber-400">Vulnerabilities flagged</span>
                    )}
                    {status === "reconnecting" && (
                      <span className="text-amber-300 animate-pulse flex items-center gap-1">
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        Reconnecting to stream...
                      </span>
                    )}
                    {status === "completed" && (
                      <span className="text-emerald-400">Assessment Complete</span>
                    )}
                    {status === "no_vulnerabilities" && (
                      <span className="text-emerald-400">No vulnerabilities detected</span>
                    )}
                    {status === "failed" && (
                      <span className="text-red-400">Assessment Halted</span>
                    )}
                    {status === "cancelled" && (
                      <span className="text-gray-400">Assessment Cancelled</span>
                    )}
                  </div>
                </div>

                {/* ========================================================= */}
                {/* 3A. Expandable Agent Activity Component                   */}
                {/* ========================================================= */}
                <AgentActivityPanel
                  status={status}
                  events={activityEvents}
                  isExpanded={isActivityExpanded}
                  onToggleExpand={() => setIsActivityExpanded(!isActivityExpanded)}
                  elapsedSeconds={elapsedSeconds}
                />

                {/* ========================================================= */}
                {/* 3B. Progressive Findings Cards (When Discovered)          */}
                {/* ========================================================= */}
                {findings.length > 0 && (
                  <div className="mb-6 space-y-4">
                    <div className="flex items-center justify-between px-1">
                      <div className="text-xs font-mono font-semibold tracking-wide uppercase text-gray-400 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        Identified Vulnerabilities ({findings.length})
                      </div>
                    </div>

                    {findings.map((f, idx) => (
                      <FindingCard key={f.id || idx} finding={f} index={idx} />
                    ))}
                  </div>
                )}

                {/* No vulnerabilities notification */}
                {status === "no_vulnerabilities" && (
                  <div className="mb-6 p-4 rounded-2xl bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    <div>
                      <div className="font-semibold text-white text-sm">
                        No authorization vulnerabilities detected
                      </div>
                      <div className="text-gray-400 mt-0.5">
                        The security testing agent evaluated all discovered endpoints and verified that tested routes enforced expected authorization controls.
                      </div>
                    </div>
                  </div>
                )}

                {/* ========================================================= */}
                {/* 3C. Streaming Conversational Markdown Output              */}
                {/* ========================================================= */}
                <div className="prose prose-invert max-w-none text-sm sm:text-base leading-relaxed text-gray-200">
                  {streamingText ? (
                    <ReactMarkdown
                      components={{
                        h3: ({ children }) => (
                          <h3 className="text-lg font-semibold text-white mt-6 mb-2 border-b border-[#1E293B] pb-1">
                            {children}
                          </h3>
                        ),
                        p: ({ children }) => (
                          <p className="mb-3.5 text-gray-300 leading-relaxed">
                            {children}
                          </p>
                        ),
                        ul: ({ children }) => (
                          <ul className="list-disc pl-5 mb-4 space-y-1.5 text-gray-300">
                            {children}
                          </ul>
                        ),
                        li: ({ children }) => (
                          <li className="text-gray-300">{children}</li>
                        ),
                        code: ({
                          className,
                          children,
                        }: {
                          className?: string;
                          children?: React.ReactNode;
                        }) => {
                          const codeText = String(children).replace(/\n$/, "");
                          const isInline =
                            !className && !codeText.includes("\n");

                          if (isInline) {
                            return (
                              <code className="px-1.5 py-0.5 rounded bg-[#161F30] text-blue-300 font-mono text-xs border border-[#263248]">
                                {children}
                              </code>
                            );
                          }

                          return (
                            <div className="relative group my-4 rounded-xl overflow-hidden border border-[#263248] bg-[#0A0E17]">
                              <div className="flex items-center justify-between px-4 py-1.5 bg-[#111827] text-gray-400 text-xs border-b border-[#263248]">
                                <span className="font-mono">remediation.js</span>
                                <button
                                  type="button"
                                  onClick={() =>
                                    navigator.clipboard.writeText(codeText)
                                  }
                                  className="flex items-center gap-1 text-[11px] hover:text-white transition-colors"
                                >
                                  <Copy className="w-3 h-3" />
                                  Copy
                                </button>
                              </div>
                              <pre className="p-4 text-xs font-mono text-emerald-300 overflow-x-auto leading-normal">
                                <code>{children}</code>
                              </pre>
                            </div>
                          );
                        },
                      }}
                    >
                      {streamingText}
                    </ReactMarkdown>
                  ) : (
                    <div className="flex items-center gap-2 text-gray-400 text-sm italic">
                      <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                      Connecting to application and executing authorization tests...
                    </div>
                  )}

                  {/* Streaming pulse indicator while active */}
                  {(status === "running" ||
                    status === "connecting" ||
                    status === "analyzing" ||
                    status === "findings_discovered") &&
                    streamingText && (
                      <span className="inline-block w-2 h-4 ml-1 bg-blue-500 animate-pulse align-middle" />
                    )}
                </div>

                <div ref={messageEndRef} />
              </div>
            </div>
          </div>
        )}
      </main>

      {/* =================================================================== */}
      {/* 4. PINNED BOTTOM ACTION BAR (When active)                           */}
      {/* =================================================================== */}
      {status !== "ready" && (
        <footer className="fixed bottom-0 left-0 right-0 z-40 bg-gradient-to-t from-[#0B0F17] via-[#0B0F17]/95 to-transparent pt-6 pb-6 px-4">
          <div className="max-w-3xl mx-auto flex items-center justify-between gap-4 p-2.5 rounded-2xl bg-[#111827] border border-[#263248] shadow-2xl">
            <div className="flex items-center gap-2 px-3 text-xs text-gray-400 font-mono">
              {status === "connecting" ||
              status === "analyzing" ||
              status === "running" ||
              status === "findings_discovered" ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
                  <span className="text-blue-400 font-medium">
                    {status === "findings_discovered"
                      ? `Testing active (${findings.length} findings)`
                      : "Assessing target..."}
                  </span>
                </>
              ) : status === "reconnecting" ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 text-amber-400 animate-spin" />
                  <span className="text-amber-300 font-medium">
                    Reconnecting to stream...
                  </span>
                </>
              ) : status === "completed" || status === "no_vulnerabilities" ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-gray-300">Assessment Complete</span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-amber-400 capitalize">{status}</span>
                </>
              )}
            </div>

            <div className="flex items-center gap-2">
              {(status === "running" ||
                status === "connecting" ||
                status === "analyzing" ||
                status === "findings_discovered" ||
                status === "reconnecting") && (
                <button
                  type="button"
                  onClick={stopAssessment}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-red-300 bg-red-950/40 hover:bg-red-900/60 border border-red-800/60 rounded-xl transition-colors"
                >
                  <StopCircle className="w-3.5 h-3.5" />
                  Stop
                </button>
              )}

              <button
                type="button"
                onClick={resetAssessment}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-xl transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                New Target
              </button>
            </div>
          </div>
        </footer>
      )}
    </div>
  );
}
