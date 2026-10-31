"use client";

import React, { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import {
  Shield,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Loader2,
  StopCircle,
  RotateCcw,
  Copy,
  ExternalLink,
} from "lucide-react";

interface AssessmentActivityEvent {
  assessment_id: string;
  event_type: string;
  stage: string;
  message: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Home() {
  const [targetUrl, setTargetUrl] = useState<string>("http://localhost:3000");
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [status, setStatus] = useState<
    "idle" | "starting" | "running" | "completed" | "failed" | "cancelled"
  >("idle");
  const [error, setError] = useState<string | null>(null);

  // Expandable activity section state
  const [isActivityExpanded, setIsActivityExpanded] = useState<boolean>(false);
  const [activityEvents, setActivityEvents] = useState<AssessmentActivityEvent[]>([]);

  // Streaming markdown text output
  const [streamingText, setStreamingText] = useState<string>("");

  // Elapsed time counter
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);

  const eventSourceRef = useRef<EventSource | null>(null);
  const messageEndRef = useRef<HTMLDivElement | null>(null);

  // Timer effect
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (status === "running" && startTime) {
      timer = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000));
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [status, startTime]);

  // Auto-scroll as streaming text grows
  useEffect(() => {
    if (status === "running") {
      messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [streamingText, activityEvents, status]);

  // Handle URL recovery on refresh if assessment ID exists in localStorage
  useEffect(() => {
    const savedId = localStorage.getItem("authscope_last_assessment_id");
    if (savedId && !assessmentId && status === "idle") {
      // Re-fetch assessment status
      fetch(`${API_BASE_URL}/api/assessments/${savedId}`)
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error("Not found");
        })
        .then((data) => {
          setAssessmentId(data.id);
          setTargetUrl(data.target_url);
          setStatus(data.status.toLowerCase());
          setActivityEvents(data.events || []);
          setStreamingText(data.markdown_content || "");
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startAssessment = async (urlToTest?: string) => {
    const finalUrl = (urlToTest || targetUrl).trim();
    if (!finalUrl) {
      setError("Please enter a target URL.");
      return;
    }

    setError(null);
    setStatus("starting");
    setStreamingText("");
    setActivityEvents([]);
    setIsActivityExpanded(false);
    const now = Date.now();
    setStartTime(now);
    setElapsedSeconds(0);

    try {
      // 1. Submit assessment creation request
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
      setStatus("running");
      localStorage.setItem("authscope_last_assessment_id", scanId);

      // 2. Open Server-Sent Events (SSE) stream
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      const es = new EventSource(`${API_BASE_URL}/api/assessments/${scanId}/stream`);
      eventSourceRef.current = es;

      es.addEventListener("activity", (e: MessageEvent) => {
        try {
          const eventItem: AssessmentActivityEvent = JSON.parse(e.data);
          setActivityEvents((prev) => [...prev, eventItem]);
        } catch (err) {
          console.error("Failed to parse activity event:", err);
        }
      });

      es.addEventListener("message", (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload.text) {
            setStreamingText((prev) => prev + payload.text);
          }
        } catch (err) {
          console.error("Failed to parse message chunk:", err);
        }
      });

      es.addEventListener("done", (e: MessageEvent) => {
        try {
          const doneData = JSON.parse(e.data);
          setStatus(doneData.status?.toLowerCase() === "failed" ? "failed" : "completed");
        } catch {
          setStatus("completed");
        }
        es.close();
      });

      es.addEventListener("error", (e: Event) => {
        console.warn("SSE connection error or closed:", e);
        // If assessment completes or closes normally, close EventSource
        es.close();
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to start assessment.";
      setError(msg);
      setStatus("failed");
    }
  };

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

  const resetAssessment = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    localStorage.removeItem("authscope_last_assessment_id");
    setAssessmentId(null);
    setStatus("idle");
    setStreamingText("");
    setActivityEvents([]);
    setIsActivityExpanded(false);
    setError(null);
  };

  return (
    <div className="flex flex-col min-h-screen bg-[#0B0F17] text-[#F9FAFB]">
      {/* Top Minimal Bar */}
      <header className="sticky top-0 z-50 flex items-center justify-between px-6 py-4 border-b border-[#1E293B]/70 bg-[#0B0F17]/90 backdrop-blur">
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
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            Scope: localhost:3000
          </div>

          {assessmentId && (
            <button
              onClick={resetAssessment}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-gray-300 hover:text-white bg-[#111827] hover:bg-[#1E293B] border border-[#1E293B] rounded-lg transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              New
            </button>
          )}
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 flex flex-col items-center justify-start max-w-3xl w-full mx-auto px-4 sm:px-6 py-8">
        {/* =================================================================== */}
        {/* 1. INITIAL EMPTY SCREEN (Like ChatGPT Home)                         */}
        {/* =================================================================== */}
        {status === "idle" && (
          <div className="flex-1 flex flex-col items-center justify-center w-full my-auto text-center py-12">
            <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 mb-6">
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

            {/* URL Input Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                startAssessment();
              }}
              className="w-full max-w-xl"
            >
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
                  className="flex items-center justify-center px-4 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 text-white font-medium text-sm transition-colors"
                >
                  Start Testing
                  <ArrowRight className="w-4 h-4 ml-1.5" />
                </button>
              </div>

              {/* Quick suggestion button */}
              <div className="flex items-center justify-center gap-2 mt-4 text-xs text-gray-400">
                <span>Authorized target:</span>
                <button
                  type="button"
                  onClick={() => {
                    setTargetUrl("http://localhost:3000");
                    startAssessment("http://localhost:3000");
                  }}
                  className="px-2.5 py-1 rounded-md bg-[#161F30] hover:bg-[#1E2D4A] border border-blue-500/30 text-blue-400 font-mono transition-colors flex items-center gap-1"
                >
                  http://localhost:3000 (Juice Shop)
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>

              {error && (
                <div className="mt-4 p-3 rounded-xl bg-red-950/40 border border-red-700/50 text-red-300 text-xs text-left flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" />
                  <span>{error}</span>
                </div>
              )}
            </form>
          </div>
        )}

        {/* =================================================================== */}
        {/* 2. CONVERSATIONAL STREAMING SCREEN                                  */}
        {/* =================================================================== */}
        {status !== "idle" && (
          <div className="w-full flex flex-col space-y-6 pb-28">
            {/* User Target Prompt */}
            <div className="flex items-start gap-3 w-full">
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center shrink-0 text-white text-xs font-bold">
                U
              </div>
              <div className="flex-1">
                <div className="text-xs text-gray-400 mb-1">Target Tested</div>
                <div className="inline-block px-3.5 py-2 rounded-xl bg-[#161F30] border border-[#263248] font-mono text-sm text-blue-300">
                  {targetUrl}
                </div>
              </div>
            </div>

            {/* Agent Response Area */}
            <div className="flex items-start gap-3 w-full">
              <div className="w-7 h-7 rounded-full bg-emerald-600/20 border border-emerald-500/30 flex items-center justify-center shrink-0 text-emerald-400">
                <Shield className="w-4 h-4" />
              </div>

              <div className="flex-1 w-full overflow-hidden">
                <div className="text-xs text-gray-400 mb-2">AuthScope Agent</div>

                {/* ========================================================= */}
                {/* Expandable Activity Section (Like ChatGPT "Worked for 15s") */}
                {/* ========================================================= */}
                <div className="mb-5 border border-[#1E293B] rounded-xl bg-[#111827]/70 overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setIsActivityExpanded(!isActivityExpanded)}
                    className="w-full flex items-center justify-between px-4 py-2.5 text-xs text-gray-400 hover:text-gray-200 hover:bg-[#161F30]/40 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      {status === "running" ? (
                        <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />
                      ) : status === "completed" ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <AlertCircle className="w-3.5 h-3.5 text-red-400" />
                      )}
                      <span className="font-medium text-gray-300">
                        {status === "running"
                          ? `Working for ${elapsedSeconds}s...`
                          : `Worked for ${Math.max(1, elapsedSeconds)}s`}
                      </span>
                      <span className="text-gray-500 font-mono text-[11px]">
                        ({activityEvents.length} operational events)
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-gray-500">
                      <span>{isActivityExpanded ? "Hide" : "Show steps"}</span>
                      {isActivityExpanded ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </div>
                  </button>

                  {/* Expanded Operational Event List */}
                  {isActivityExpanded && (
                    <div className="px-4 py-3 border-t border-[#1E293B] bg-[#0D121D] max-h-72 overflow-y-auto space-y-2 text-xs font-mono">
                      {activityEvents.length === 0 ? (
                        <div className="text-gray-500 italic">
                          Initializing security engine...
                        </div>
                      ) : (
                        activityEvents.map((ev, idx) => {
                          const timeStr = ev.timestamp?.slice(11, 19) || "";
                          const isWarning =
                            ev.event_type.includes("suspicious") ||
                            ev.event_type.includes("failed");
                          const isSuccess =
                            ev.event_type.includes("completed") ||
                            ev.event_type.includes("confirmed");

                          return (
                            <div
                              key={idx}
                              className="flex items-start gap-2.5 text-gray-300 leading-relaxed"
                            >
                              <span className="text-gray-500 shrink-0 select-none">
                                [{timeStr}]
                              </span>
                              {isWarning ? (
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                              ) : isSuccess ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                              ) : (
                                <div className="w-2 h-2 rounded-full bg-blue-400 shrink-0 mt-1.5" />
                              )}
                              <span
                                className={
                                  isWarning
                                    ? "text-amber-200"
                                    : isSuccess
                                    ? "text-gray-200"
                                    : "text-gray-400"
                                }
                              >
                                {ev.message}
                              </span>
                            </div>
                          );
                        })
                      )}
                    </div>
                  )}
                </div>

                {/* ========================================================= */}
                {/* Streaming Conversational Markdown Output                  */}
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
                          const isInline = !className && !codeText.includes("\n");

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
                                  onClick={() => navigator.clipboard.writeText(codeText)}
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
                  {status === "running" && streamingText && (
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
      {/* 3. PINNED BOTTOM ACTION BAR (When active)                           */}
      {/* =================================================================== */}
      {status !== "idle" && (
        <footer className="fixed bottom-0 left-0 right-0 z-40 bg-gradient-to-t from-[#0B0F17] via-[#0B0F17]/95 to-transparent pt-6 pb-6 px-4">
          <div className="max-w-3xl mx-auto flex items-center justify-between gap-4 p-2.5 rounded-2xl bg-[#111827] border border-[#263248] shadow-2xl">
            <div className="flex items-center gap-2 px-3 text-xs text-gray-400 font-mono">
              {status === "running" ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
                  <span className="text-blue-400 font-medium">Assessing target...</span>
                </>
              ) : status === "completed" ? (
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
              {status === "running" && (
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
