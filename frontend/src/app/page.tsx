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
  Globe,
  Cpu,
  HelpCircle,
  MinusCircle,
  Lock,
  KeyRound,
} from "lucide-react";
import {
  AIProviderInfo,
  AssessmentEventItem,
  AssessmentStageState,
  AssessmentSummaryResponse,
  AuthorizationBasis,
  DiscoveredEndpointItem,
  FindingItem,
  TargetCheckResponse,
} from "@/types/assessment";
import { AgentActivityPanel } from "@/components/AgentActivityPanel";
import { FindingCard } from "@/components/FindingCard";
import { GitHubCodeScanPanel } from "@/components/GitHubCodeScanPanel";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type UIStatus =
  | "ready"
  | "connecting"
  | "running"
  | "analyzing"
  | "findings_discovered"
  | "reconnecting"
  | "completed"
  | "no_vulnerabilities"
  | "failed"
  | "cancelled";

/**
 * Validates URL syntax in the frontend for usability.
 * Supports http:// and https:// with optional custom ports and paths.
 * Never rewrites or downgrades https:// to http://.
 * Final authorization is always determined by the backend ScopeGuard.
 */
export function validateWebsiteUrlSyntax(rawInput: string): {
  valid: boolean;
  normalizedUrl: string;
  scheme?: string;
  host?: string;
  port?: number;
  error?: string;
} {
  const trimmed = (rawInput || "").trim();
  if (!trimmed) {
    return {
      valid: false,
      normalizedUrl: "",
      error: "Please enter a target website URL (e.g. http://localhost:3000 or https://staging.example.com).",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      valid: false,
      normalizedUrl: trimmed,
      error:
        "Invalid URL syntax. Include the scheme (http:// or https://) and hostname, e.g. http://localhost:3000 or https://authorized-domain.example:8443/app.",
    };
  }

  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    return {
      valid: false,
      normalizedUrl: trimmed,
      scheme,
      error: `Scheme '${scheme}://' is not allowed. Only authorized HTTP or HTTPS targets are supported.`,
    };
  }

  if (!parsed.hostname) {
    return {
      valid: false,
      normalizedUrl: trimmed,
      error: "Invalid URL syntax: hostname is missing.",
    };
  }

  const port = parsed.port
    ? Number(parsed.port)
    : scheme === "https"
    ? 443
    : 80;

  if (Number.isNaN(port) || port < 1 || port > 65535) {
    return {
      valid: false,
      normalizedUrl: trimmed,
      error: "Invalid port number in URL.",
    };
  }

  // Preserve exact scheme (never downgrade https to http)
  const cleanUrl = trimmed.endsWith("/") && parsed.pathname === "/"
    ? trimmed.slice(0, -1)
    : trimmed;

  return {
    valid: true,
    normalizedUrl: cleanUrl,
    scheme,
    host: parsed.hostname,
    port,
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
  const [status, setStatus] = useState<UIStatus>("ready");
  const [error, setError] = useState<string | null>(null);

  // Dynamic Target Authorization states
  const [targetAuth, setTargetAuth] = useState<TargetCheckResponse | null>(null);
  const [isCheckingAuth, setIsCheckingAuth] = useState<boolean>(false);
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [authBasis, setAuthBasis] = useState<AuthorizationBasis>("admin_approved");
  const [permissionRef, setPermissionRef] = useState<string>("");
  const [authNotes, setAuthNotes] = useState<string>("");
  const [adminApprover, setAdminApprover] = useState<string>("security_admin");
  const [approvalDays, setApprovalDays] = useState<number>(30);
  const [authActionMessage, setAuthActionMessage] = useState<string | null>(null);
  const [isSubmittingAuth, setIsSubmittingAuth] = useState<boolean>(false);

  // Operational events, stages, findings, and summary
  const [stages, setStages] = useState<Record<string, AssessmentStageState>>({});
  const [activityEvents, setActivityEvents] = useState<AssessmentEventItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [verifyingFindingId, setVerifyingFindingId] = useState<string | null>(null);
  const [verificationErrors, setVerificationErrors] = useState<Record<string, string>>({});
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<DiscoveredEndpointItem[]>([]);
  const [summaryData, setSummaryData] = useState<AssessmentSummaryResponse | null>(null);
  const [aiProvider, setAiProvider] = useState<AIProviderInfo | null>(null);

  // Streaming text output
  const [streamingText, setStreamingText] = useState<string>("");

  // Reconnection tracking
  const [reconnectAttempts, setReconnectAttempts] = useState<number>(0);
  const reconnectAttemptsRef = useRef<number>(0);
  const maxReconnectAttempts = 3;

  // Refs
  const eventSourceRef = useRef<EventSource | null>(null);
  const messageEndRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const connectSSERef = useRef<((scanId: string) => void) | null>(null);

  // Fetch verified backend health & AI provider info on mount
  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.ai_provider) {
          setAiProvider(data.ai_provider);
        }
      })
      .catch(() => {
        // Ignore if backend is offline initially
      });
  }, []);

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
   * Evaluates server-side target authorization status via ScopeGuard & TargetRegistry.
   */
  const checkTargetAuth = useCallback(async (candidateUrl: string) => {
    const trimmed = (candidateUrl || "").trim();
    if (!trimmed) {
      setTargetAuth(null);
      return;
    }
    const syntax = validateWebsiteUrlSyntax(trimmed);
    if (!syntax.valid) {
      setTargetAuth(null);
      return;
    }

    setIsCheckingAuth(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/targets/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: syntax.normalizedUrl }),
      });
      if (res.ok) {
        const data: TargetCheckResponse = await res.json();
        setTargetAuth(data);
      } else {
        setTargetAuth(null);
      }
    } catch {
      // Backend may be offline initially
    } finally {
      setIsCheckingAuth(false);
    }
  }, []);

  // Debounced authorization check when targetUrl changes
  useEffect(() => {
    const timer = setTimeout(() => {
      checkTargetAuth(targetUrl);
    }, 350);
    return () => clearTimeout(timer);
  }, [targetUrl, checkTargetAuth]);

  /**
   * Submits a target URL to the backend TargetRegistry for authorization review.
   */
  const submitTargetForAuth = async () => {
    const syntax = validateWebsiteUrlSyntax(targetUrl);
    if (!syntax.valid) {
      setError(syntax.error || "Invalid URL syntax.");
      return;
    }

    setIsSubmittingAuth(true);
    setAuthActionMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/targets`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: syntax.normalizedUrl,
          authorization_basis: authBasis,
          permission_reference: permissionRef.trim(),
          allowed_paths: [],
          allowed_methods: ["GET", "HEAD"],
          notes: authNotes.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthActionMessage(`Error: ${data.detail || "Submission failed"}`);
      } else {
        setAuthActionMessage(`Submitted: ${data.message}`);
        await checkTargetAuth(syntax.normalizedUrl);
      }
    } catch (err: unknown) {
      setAuthActionMessage(
        `Failed to submit target: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  /**
   * Approves a pending target profile with administrator credentials.
   */
  const approveTargetAction = async (targetId: string) => {
    setIsSubmittingAuth(true);
    setAuthActionMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/targets/${targetId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          approved_by: adminApprover.trim() || "security_admin",
          expires_in_days: approvalDays,
          notes: authNotes.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthActionMessage(`Error: ${data.detail || "Approval failed"}`);
      } else {
        setAuthActionMessage(`Target approved: ${data.message}`);
        await checkTargetAuth(targetUrl);
      }
    } catch (err: unknown) {
      setAuthActionMessage(
        `Approval failed: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  /**
   * Verifies domain ownership via HTTP well-known challenge token.
   */
  const verifyDomainChallengeAction = async (targetId: string) => {
    setIsSubmittingAuth(true);
    setAuthActionMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/targets/${targetId}/verify-challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge_type: "http" }),
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setAuthActionMessage(`Verification failed: ${data.message || data.detail}`);
      } else {
        setAuthActionMessage(`Verification succeeded: ${data.message}`);
        await checkTargetAuth(targetUrl);
      }
    } catch (err: unknown) {
      setAuthActionMessage(
        `Challenge check failed: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  /**
   * Revokes authorization for an approved target.
   */
  const revokeTargetAction = async (targetId: string) => {
    setIsSubmittingAuth(true);
    setAuthActionMessage(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/targets/${targetId}/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          revoked_by: adminApprover.trim() || "security_admin",
          reason: "Revoked by operator in dashboard",
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthActionMessage(`Error: ${data.detail || "Revocation failed"}`);
      } else {
        setAuthActionMessage(`Target revoked: ${data.message}`);
        await checkTargetAuth(targetUrl);
      }
    } catch (err: unknown) {
      setAuthActionMessage(
        `Revocation failed: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setIsSubmittingAuth(false);
    }
  };

  /**
   * Refetches full assessment record from backend SQLite repository
   * to populate structured findings, stage states, and summary metrics.
   */
  const fetchAssessmentDetails = useCallback(async (id: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments/${id}`);
      if (!res.ok) return;
      const data: AssessmentSummaryResponse = await res.json();

      setSummaryData(data);
      if (data.stages) {
        setStages(data.stages);
      }
      if (Array.isArray(data.findings)) {
        setFindings(data.findings);
      }
      if (Array.isArray(data.discovered_endpoints)) {
        setDiscoveredEndpoints(data.discovered_endpoints);
      }
      if (data.ai_provider) {
        setAiProvider(data.ai_provider);
      }
    } catch (err) {
      console.warn("Could not fetch detailed assessment findings:", err);
    }
  }, []);

  /**
   * Connects to the SSE stream with support for all 14 agent activity events.
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
          const eventItem: AssessmentEventItem = JSON.parse(e.data);
          setActivityEvents((prev) => [...prev, eventItem]);

          const etype = eventItem.event_type;
          const stage = eventItem.stage;

          if (
            etype === "finding_confirmed" ||
            etype === "suspicious_behavior_detected"
          ) {
            setStatus("findings_discovered");
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
            fetchAssessmentDetails(scanId);
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

      // All 14 required genuine SSE agent events (Section 9)
      const agentEventNames = [
        "assessment_started",
        "agent_thinking",
        "agent_plan",
        "tool_started",
        "tool_completed",
        "tool_failed",
        "endpoint_discovered",
        "finding_hypothesis",
        "finding_discovered",
        "evidence_validated",
        "source_location_found",
        "explanation_generated",
        "assessment_completed",
        "assessment_failed",
      ];

      agentEventNames.forEach((ename) => {
        es.addEventListener(ename, (e: MessageEvent) => {
          try {
            const payload = JSON.parse(e.data);
            if (payload.ai_provider) {
              setAiProvider(payload.ai_provider);
            }
            const evItem: AssessmentEventItem = {
              assessment_id: payload.assessment_id || scanId,
              event_type: ename,
              stage: payload.tool ? `tool_${payload.tool}` : "agent_reasoning",
              message:
                payload.message ||
                `${ename}: ${payload.tool || payload.path || payload.category || ""}`,
              timestamp: payload.timestamp || new Date().toISOString(),
              metadata: payload,
            };
            setActivityEvents((prev) => {
              const duplicate = prev.some(
                (p) => p.event_type === ename && p.message === evItem.message
              );
              return duplicate ? prev : [...prev, evItem];
            });

            if (ename === "finding_discovered" || ename === "evidence_validated") {
              setStatus("findings_discovered");
              fetchAssessmentDetails(scanId);
            }
          } catch (err) {
            console.warn(`Failed to parse ${ename} event:`, err);
          }
        });
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

        fetchAssessmentDetails(scanId);
        setReconnectAttempts(0);
    reconnectAttemptsRef.current = 0;
        es.close();
      });

      es.addEventListener("error", (e: Event) => {
        console.warn("SSE connection interrupted:", e);
        es.close();

        setStatus((prevStatus) => {
          if (
            prevStatus === "completed" ||
            prevStatus === "no_vulnerabilities" ||
            prevStatus === "cancelled" ||
            prevStatus === "failed"
          ) {
            return prevStatus;
          }

          if (reconnectAttemptsRef.current < maxReconnectAttempts) {
            reconnectAttemptsRef.current += 1;
            setReconnectAttempts(reconnectAttemptsRef.current);
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
        .then((data: AssessmentSummaryResponse) => {
          setAssessmentId(data.id);
          setTargetUrl(data.target_url);
          setSummaryData(data);
          setStages(data.stages || {});
          setActivityEvents(data.events || []);
          setStreamingText(data.markdown_content || "");
          setFindings(data.findings || []);
          setDiscoveredEndpoints(data.discovered_endpoints || []);
          if (data.ai_provider) {
            setAiProvider(data.ai_provider);
          }

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
            connectSSE(data.id);
          }
        })
        .catch(() => {
          localStorage.removeItem("authscope_last_assessment_id");
        });
    }
  }, [assessmentId, status, connectSSE]);

  /**
   * Dispatches assessment initiation to backend FastAPI after usability syntax check.
   */
  const startAssessment = async (urlOverride?: string) => {
    const rawCandidate = (urlOverride ?? targetUrl).trim();
    const syntaxCheck = validateWebsiteUrlSyntax(rawCandidate);
    if (!syntaxCheck.valid) {
      setError(syntaxCheck.error || "Invalid URL syntax.");
      return;
    }

    const finalUrl = syntaxCheck.normalizedUrl;
    setError(null);
    setStatus("connecting");
    setStreamingText("");
    setStages({});
    setActivityEvents([]);
    setFindings([]);
    setDiscoveredEndpoints([]);
    setSummaryData(null);
    setReconnectAttempts(0);
    reconnectAttemptsRef.current = 0;

    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: finalUrl,
          github_repo: githubRepo.trim() || undefined,
          source_archive_path: sourceArchive ? sourceArchive.name : undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        // Keep the user on the input screen with the clear backend scope/TLS/profile error visible
        setError(data.detail || "Target URL authorization failed.");
        setStatus("ready");
        return;
      }

      const scanId = data.assessment_id;
      setAssessmentId(scanId);
      localStorage.setItem("authscope_last_assessment_id", scanId);
      fetchAssessmentDetails(scanId);
      connectSSE(scanId);
    } catch (err: unknown) {
      const rawMsg = err instanceof Error ? err.message : "Failed to start assessment.";
      const msg =
        rawMsg.toLowerCase().includes("failed to fetch") ||
        rawMsg.toLowerCase().includes("networkerror")
          ? "Unable to reach the AuthScope API backend on http://localhost:8000. Please ensure the FastAPI backend is running."
          : rawMsg;
      setError(msg);
      setStatus("ready");
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
      fetchAssessmentDetails(assessmentId);
    } catch (err) {
      console.error("Error stopping assessment:", err);
    }
  };

  const verifyFix = async (findingId: string) => {
    if (!assessmentId || verifyingFindingId) return;
    setVerifyingFindingId(findingId);
    setVerificationErrors((current) => ({ ...current, [findingId]: "" }));
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/assessments/${assessmentId}/findings/${findingId}/verify-fix`,
        { method: "POST" },
      );
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(typeof payload.detail === "string" ? payload.detail : "Fix verification could not run.");
      }
      const history = (payload.history || []) as FindingItem["verification_history"];
      setFindings((current) => current.map((finding) => finding.id === findingId
        ? { ...finding, retest_status: history?.[0]?.new_status || payload.verification?.new_status, verification_history: history }
        : finding));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Fix verification failed.";
      setVerificationErrors((current) => ({ ...current, [findingId]: message }));
    } finally {
      setVerifyingFindingId(null);
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
    setStages({});
    setActivityEvents([]);
    setFindings([]);
    setDiscoveredEndpoints([]);
    setSummaryData(null);
    setError(null);
    setReconnectAttempts(0);
    reconnectAttemptsRef.current = 0;
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

  // Separate findings by the 5 required statuses (Section 8)
  const confirmedFindings = findings.filter(
    (f) =>
      f.validation_status === "CONFIRMED" &&
      f.status !== "suspected" &&
      f.access_verdict !== "SUSPICIOUS_ACCESS"
  );
  const suspiciousFindings = findings.filter(
    (f) =>
      f.validation_status === "SUSPICIOUS" ||
      f.status === "suspected" ||
      f.access_verdict === "SUSPICIOUS_ACCESS"
  );
  const notConfirmedFindings = findings.filter(
    (f) => f.validation_status === "NOT_CONFIRMED"
  );
  const inconclusiveFindings = findings.filter(
    (f) => f.validation_status === "INCONCLUSIVE"
  );
  const notTestedFindings = findings.filter(
    (f) => f.validation_status === "NOT_TESTED"
  );

  // Endpoint-level checks for NOT_CONFIRMED, INCONCLUSIVE, NOT_TESTED
  const untestedEndpoints = discoveredEndpoints.filter(
    (ep) => ep.finding_status === "NOT_TESTED"
  );
  const inconclusiveEndpoints = discoveredEndpoints.filter(
    (ep) => ep.finding_status === "INCONCLUSIVE"
  );
  const notConfirmedEndpoints = discoveredEndpoints.filter(
    (ep) => ep.finding_status === "NOT_CONFIRMED"
  );

  const isRunningState =
    status === "connecting" ||
    status === "running" ||
    status === "analyzing" ||
    status === "findings_discovered" ||
    status === "reconnecting";

  const parsedTarget = validateWebsiteUrlSyntax(summaryData?.target_url || targetUrl);
  const displayScheme = (summaryData?.scheme || parsedTarget.scheme || "http").toUpperCase();
  const displayPort = summaryData?.port ?? parsedTarget.port ?? 3000;

  const reportFindings = summaryData?.findings || findings;
  const confirmedReportFindings = reportFindings.filter((finding) => finding.validation_status === "CONFIRMED");
  const investigatingFindings = reportFindings.filter((finding) => finding.validation_status !== "CONFIRMED");
  const severityRank: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const highestRiskFinding = [...reportFindings].sort(
    (left, right) => (severityRank[String(right.severity).toUpperCase()] || 0) - (severityRank[String(left.severity).toUpperCase()] || 0)
  )[0];
  const highestRiskLabel = highestRiskFinding && ["INFO", "INFORMATIONAL"].includes(String(highestRiskFinding.severity).toUpperCase())
    ? "Informational"
    : highestRiskFinding?.severity;
  const firstRecommendedFix = highestRiskFinding?.beginner_explanation?.how_to_fix?.[0];
  const reportRecommendations = Array.from(new Set(
    reportFindings.flatMap((finding) => finding.beginner_explanation?.additional_recommendations || [])
  )).slice(0, 3);

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
              AI Security Assessment
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Verified Backend AI Provider Badge (Section 11) */}
          {aiProvider && (
            <div
              className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#111827] border border-[#1E293B] text-[11px] font-mono text-gray-300"
              title={
                aiProvider.configured
                  ? `Active AI Provider: ${aiProvider.provider} (${aiProvider.model})`
                  : `${aiProvider.provider} (${aiProvider.model}) — Deterministic Fallback Mode`
              }
            >
              <Cpu className="w-3 h-3 text-purple-400" />
              <span>
                {aiProvider.provider}: {aiProvider.model}
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                {aiProvider.configured ? "API Active" : "Deterministic Mode"}
              </span>
            </div>
          )}

          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#111827] border border-[#1E293B] text-[11px] font-mono text-gray-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            ScopeGuard Enforced
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
      <main className="flex-1 flex flex-col items-center justify-start max-w-4xl w-full mx-auto px-4 sm:px-6 py-8">
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
              Enter an authorized HTTP or HTTPS website URL to test for Broken
              Object Level Authorization (BOLA / IDOR), Broken Function Level
              Authorization, and privilege escalation.
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
                <Globe className="w-4 h-4 text-gray-500 ml-3 shrink-0" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => {
                    setTargetUrl(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="http://localhost:3000 or https://staging.example.com"
                  aria-label="Target Website URL"
                  className="flex-1 bg-transparent px-3 py-3 text-sm sm:text-base text-white placeholder-gray-500 focus:outline-none font-mono"
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

              {/* Dynamic Target Authorization Status Badge */}
              <div className="flex items-center justify-between mt-2.5 px-3.5 py-2 rounded-xl bg-[#0F172A]/70 border border-[#1E293B] text-xs">
                <div className="flex items-center gap-2 overflow-hidden">
                  {isCheckingAuth ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400 shrink-0" />
                  ) : targetAuth?.is_authorized ? (
                    <span className="flex h-2 w-2 relative shrink-0">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                  ) : targetAuth?.status === "PENDING" ? (
                    <span className="inline-flex rounded-full h-2 w-2 bg-amber-400 shrink-0"></span>
                  ) : targetAuth?.status === "REVOKED" ? (
                    <span className="inline-flex rounded-full h-2 w-2 bg-red-400 shrink-0"></span>
                  ) : targetAuth?.status === "EXPIRED" ? (
                    <span className="inline-flex rounded-full h-2 w-2 bg-orange-400 shrink-0"></span>
                  ) : (
                    <span className="inline-flex rounded-full h-2 w-2 bg-zinc-500 shrink-0"></span>
                  )}

                  <div className="flex items-center gap-2 truncate">
                    <span
                      className={`font-medium ${
                        targetAuth?.is_authorized
                          ? "text-emerald-400"
                          : targetAuth?.status === "PENDING"
                          ? "text-amber-400"
                          : targetAuth?.status === "REVOKED"
                          ? "text-red-400"
                          : targetAuth?.status === "EXPIRED"
                          ? "text-orange-400"
                          : "text-gray-300"
                      }`}
                    >
                      {targetAuth?.is_authorized
                        ? "Authorized Target (ScopeGuard Permitted)"
                        : targetAuth?.status === "PENDING"
                        ? "Authorization Pending Review"
                        : targetAuth?.status === "REVOKED"
                        ? "Authorization Revoked"
                        : targetAuth?.status === "EXPIRED"
                        ? "Authorization Expired"
                        : "Target Requires Authorization"}
                    </span>
                    <span className="text-gray-500 font-mono text-[11px] truncate">
                      {targetAuth?.hostname || parsedTarget.host || "hostname"}
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setShowAuthModal(true);
                    setAuthActionMessage(null);
                  }}
                  className="text-xs font-medium text-blue-400 hover:text-blue-300 underline underline-offset-2 transition-colors ml-2 shrink-0"
                >
                  {targetAuth?.is_authorized
                    ? "Scope Details"
                    : "Authorize Target"}
                </button>
              </div>

              <GitHubCodeScanPanel apiBaseUrl={API_BASE_URL} />

              {/* Example URLs & Optional Source Context */}
              <div className="flex flex-wrap items-center justify-between gap-2 mt-3 text-xs text-gray-400">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span>Examples:</span>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetUrl("http://localhost:3000");
                      setError(null);
                    }}
                    className="px-2 py-0.5 rounded bg-[#161F30] hover:bg-[#1E2D4A] border border-blue-500/30 text-blue-400 font-mono transition-colors flex items-center gap-1"
                  >
                    http://localhost:3000
                    <ExternalLink className="w-2.5 h-2.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTargetUrl("https://staging.example.com");
                      setError(null);
                    }}
                    className="px-2 py-0.5 rounded bg-[#161F30] hover:bg-[#1E2D4A] border border-zinc-700 text-gray-300 font-mono transition-colors"
                  >
                    https://staging.example.com
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => setShowAdvancedInputs(!showAdvancedInputs)}
                  className="text-xs text-gray-400 hover:text-blue-400 transition-colors flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3 text-blue-400" />
                  {showAdvancedInputs
                    ? "Hide source context"
                    : "Add source code (optional)"}
                </button>
              </div>

              {/* Expandable Optional Source Code & Repository Input */}
              {showAdvancedInputs && (
                <div className="mt-4 p-4 rounded-xl bg-[#111827]/80 border border-[#1E293B] space-y-3.5">
                  <div className="text-xs font-medium text-gray-300">
                    Optional Source Code Context
                  </div>
                  <p className="text-[11px] text-gray-400 leading-normal">
                    Provide a repository or source archive to map detected runtime
                    vulnerabilities directly to verified source code files and line
                    numbers.
                  </p>

                  <div>
                    <label className="block text-[11px] font-mono text-gray-400 mb-1">
                      Repository URL (context only; does not connect or download)
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
                        <span>
                          {sourceArchive ? "Change file" : "Choose archive"}
                        </span>
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

              {/* Clear Scope / URL / TLS Error Display (Section 4) */}
              {error && (
                <div
                  role="alert"
                  className="mt-4 p-3.5 rounded-xl bg-red-950/50 border border-red-600/50 text-red-200 text-xs flex items-start justify-between gap-2.5"
                >
                  <div className="flex items-start gap-2.5">
                    <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" />
                    <div className="space-y-1">
                      <div className="font-semibold text-red-300">
                        Target Authorization or Validation Error
                      </div>
                      <div className="leading-relaxed">{error}</div>
                    </div>
                  </div>

                  {(error.includes("authorized") || error.includes("Scope violation")) && (
                    <button
                      type="button"
                      onClick={() => {
                        setShowAuthModal(true);
                        setAuthActionMessage(null);
                      }}
                      className="px-2.5 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-800 text-red-100 font-medium text-xs whitespace-nowrap transition-colors shrink-0"
                    >
                      Authorize Target
                    </button>
                  )}
                </div>
              )}
            </form>
          </div>
        )}

        {/* =================================================================== */}
        {/* 3. CONVERSATIONAL ASSESSMENT SCREEN (Active / Completed)            */}
        {/* =================================================================== */}
        {status !== "ready" && (
          <div className="w-full flex flex-col space-y-6 pb-28">
            {/* User Target Prompt */}
            <div className="flex items-start gap-3 w-full">
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center shrink-0 text-white text-xs font-bold shadow-md shadow-blue-600/30">
                U
              </div>
              <div className="flex-1">
                <div className="text-xs text-gray-400 mb-1">
                  Authorized Target Website
                </div>
                <div className="inline-flex flex-wrap items-center gap-2 px-3.5 py-2 rounded-xl bg-[#161F30] border border-[#263248] font-mono text-sm text-blue-300">
                  <span>{summaryData?.target_url || targetUrl}</span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-[#111827] text-emerald-300 border border-emerald-500/30">
                    {displayScheme} · Port {displayPort}
                  </span>
                  {githubRepo && (
                    <span className="text-[11px] px-2 py-0.5 rounded bg-[#111827] text-gray-400 border border-gray-700 flex items-center gap-1">
                      <GitBranch className="w-3 h-3" />
                      Repo Linked
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
                  <div className="text-xs text-gray-400">
                    AuthScope Security Engine &amp; Agent
                  </div>
                  <div className="text-[11px] font-mono">
                    {status === "connecting" && (
                      <span className="text-blue-400">
                        Validating scope &amp; connecting...
                      </span>
                    )}
                    {status === "analyzing" && (
                      <span className="text-indigo-400">
                        Testing endpoints &amp; authorization...
                      </span>
                    )}
                    {status === "findings_discovered" && (
                      <span className="text-amber-400">
                        Findings identified
                      </span>
                    )}
                    {status === "reconnecting" && (
                      <span className="text-amber-300 animate-pulse flex items-center gap-1">
                        <RefreshCw className="w-3 h-3 animate-spin" />
                        Reconnecting to stream...
                      </span>
                    )}
                    {status === "completed" && (
                      <span className="text-emerald-400">
                        Assessment Completed
                      </span>
                    )}
                    {status === "no_vulnerabilities" && (
                      <span className="text-emerald-400">
                        No Confirmed Vulnerabilities Found
                      </span>
                    )}
                    {status === "failed" && (
                      <span className="text-red-400">Assessment Halted</span>
                    )}
                    {status === "cancelled" && (
                      <span className="text-gray-400">
                        Assessment Cancelled
                      </span>
                    )}
                  </div>
                </div>

                {/* ========================================================= */}
                {/* 3A. Expandable Agent Activity Panel                       */}
                {/* ========================================================= */}
                <AgentActivityPanel
                  stages={stages}
                  events={activityEvents}
                  isRunning={isRunningState}
                />

                {/* ========================================================= */}
                {/* 3B. Live Findings Grouped by Status (Section 7 & 8)       */}
                {/* ========================================================= */}
                {findings.length > 0 && (() => {
                  const counts = findings.reduce<Record<string, number>>((acc, finding) => {
                    const value = finding.retest_status || "NOT_TESTED";
                    acc[value] = (acc[value] || 0) + 1;
                    return acc;
                  }, {});
                  return <div className="my-4 grid grid-cols-2 gap-2 rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 text-xs sm:grid-cols-5">
                    <div>Issues found: <strong>{findings.length}</strong></div>
                    <div>Fixed: <strong>{counts.FIXED || 0}</strong></div>
                    <div>Still vulnerable: <strong>{counts["STILL VULNERABLE"] || 0}</strong></div>
                    <div>Partially fixed: <strong>{counts["PARTIALLY FIXED"] || 0}</strong></div>
                    <div>Need investigation: <strong>{(counts.INCONCLUSIVE || 0) + (counts.NOT_TESTED || 0)}</strong></div>
                  </div>;
                })()}
                {confirmedFindings.length > 0 && (
                  <div className="my-5 space-y-3">
                    <div className="text-xs font-mono font-semibold tracking-wide uppercase text-red-400 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4" />
                      Confirmed Findings ({confirmedFindings.length}) — Validated
                      by Security Engine
                    </div>
                    {confirmedFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} onVerifyFix={verifyFix} verificationPending={verifyingFindingId === f.id} verificationError={verificationErrors[f.id]} />
                    ))}
                  </div>
                )}

                {suspiciousFindings.length > 0 && (
                  <div className="my-5 space-y-3">
                    <div className="text-xs font-mono font-semibold tracking-wide uppercase text-amber-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Suspicious Findings ({suspiciousFindings.length}) —
                      Potential Issue, Evidence Incomplete
                    </div>
                    {suspiciousFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} onVerifyFix={verifyFix} verificationPending={verifyingFindingId === f.id} verificationError={verificationErrors[f.id]} />
                    ))}
                  </div>
                )}

                {inconclusiveFindings.length > 0 && (
                  <div className="my-5 space-y-3">
                    <div className="text-xs font-mono font-semibold tracking-wide uppercase text-purple-400 flex items-center gap-2">
                      <HelpCircle className="w-4 h-4" />
                      Inconclusive Checks ({inconclusiveFindings.length})
                    </div>
                    {inconclusiveFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} onVerifyFix={verifyFix} verificationPending={verifyingFindingId === f.id} verificationError={verificationErrors[f.id]} />
                    ))}
                  </div>
                )}

                {notConfirmedFindings.length > 0 && (
                  <div className="my-5 space-y-3">
                    <div className="text-xs font-mono font-semibold tracking-wide uppercase text-emerald-400 flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4" />
                      Not Confirmed ({notConfirmedFindings.length})
                    </div>
                    {notConfirmedFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} onVerifyFix={verifyFix} verificationPending={verifyingFindingId === f.id} verificationError={verificationErrors[f.id]} />
                    ))}
                  </div>
                )}

                {notTestedFindings.length > 0 && (
                  <div className="my-5 space-y-3">
                    <div className="text-xs font-mono font-semibold tracking-wide uppercase text-zinc-400 flex items-center gap-2">
                      <MinusCircle className="w-4 h-4" />
                      Not Tested ({notTestedFindings.length})
                    </div>
                    {notTestedFindings.map((f) => (
                      <FindingCard key={f.id} finding={f} onVerifyFix={verifyFix} verificationPending={verifyingFindingId === f.id} verificationError={verificationErrors[f.id]} />
                    ))}
                  </div>
                )}

                {/* Endpoint Check Status Breakdown (NOT_CONFIRMED / INCONCLUSIVE / NOT_TESTED) */}
                {(untestedEndpoints.length > 0 ||
                  inconclusiveEndpoints.length > 0 ||
                  notConfirmedEndpoints.length > 0) && (
                  <div className="my-4 rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3 text-xs">
                    <div className="font-semibold text-zinc-200 uppercase tracking-wider text-[11px]">
                      Endpoint Authorization Check Breakdown
                    </div>
                    <div className="grid grid-cols-1 gap-2">
                      {notConfirmedEndpoints.map((ep) => (
                        <div
                          key={ep.id}
                          className="flex flex-wrap items-center justify-between gap-2 p-2 rounded bg-zinc-950/70 border border-zinc-800"
                        >
                          <div className="font-mono text-zinc-200">
                            <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[10px] font-bold mr-2">
                              NOT_CONFIRMED
                            </span>
                            {ep.method} {ep.path}
                          </div>
                          <span className="text-zinc-400 text-[11px]">
                            {ep.summary ||
                              "Testing did not establish the suspected vulnerability (access properly restricted)."}
                          </span>
                        </div>
                      ))}
                      {inconclusiveEndpoints.map((ep) => (
                        <div
                          key={ep.id}
                          className="flex flex-wrap items-center justify-between gap-2 p-2 rounded bg-zinc-950/70 border border-zinc-800"
                        >
                          <div className="font-mono text-zinc-200">
                            <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold mr-2">
                              INCONCLUSIVE
                            </span>
                            {ep.method} {ep.path}
                          </div>
                          <span className="text-zinc-400 text-[11px]">
                            {ep.summary || "The result could not be determined."}
                          </span>
                        </div>
                      ))}
                      {untestedEndpoints.map((ep) => (
                        <div
                          key={ep.id}
                          className="flex flex-wrap items-center justify-between gap-2 p-2 rounded bg-zinc-950/70 border border-zinc-800"
                        >
                          <div className="font-mono text-zinc-200">
                            <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700 text-[10px] font-bold mr-2">
                              NOT_TESTED
                            </span>
                            {ep.method} {ep.path}
                          </div>
                          <span className="text-zinc-400 text-[11px]">
                            {ep.summary ||
                              "Required credentials, permissions or resource ownership were unavailable."}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ========================================================= */}
                {/* 3C. Final Assessment Summary (Section 10)                 */}
                {/* ========================================================= */}
                {summaryData && !isRunningState && (
                  <div
                    className="my-5 rounded-2xl border border-zinc-800 bg-zinc-900/80 p-5 space-y-4"
                    data-testid="final-assessment-summary"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 pb-3">
                      <div>
                        <h3 className="text-base font-semibold text-white">
                          Final Assessment Summary
                        </h3>
                        <p className="text-xs text-zinc-400 font-mono mt-0.5">
                          Target: {summaryData.target_url} ({displayScheme} · Port{" "}
                          {displayPort})
                        </p>
                      </div>
                      <span className="px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-zinc-800 text-zinc-200 border border-zinc-700">
                        Status: {summaryData.status}
                      </span>
                    </div>

                    {/* Clear "No confirmed vulnerabilities found" banner when confirmed === 0 */}
                    {summaryData.confirmed_findings_count === 0 && (
                      <div className="p-3.5 rounded-xl bg-emerald-950/25 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-3">
                        <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                        <div>
                          <div className="font-semibold text-white text-sm">
                            No confirmed vulnerabilities found
                          </div>
                          <div className="text-zinc-400 mt-0.5">
                            {summaryData.suspicious_results_count > 0
                              ? `${summaryData.suspicious_results_count} suspicious access pattern(s) were flagged for operator review, but zero vulnerabilities met cryptographic cross-role confirmation criteria.`
                              : "All tested endpoints enforced expected authorization boundaries."}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Summary Metrics Grid */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2.5 text-center">
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-zinc-800">
                        <div className="text-[10px] uppercase text-zinc-500 font-semibold">
                          Endpoints Discovered
                        </div>
                        <div className="text-lg font-mono font-bold text-white mt-0.5">
                          {summaryData.endpoints_discovered_count}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-zinc-800">
                        <div className="text-[10px] uppercase text-zinc-500 font-semibold">
                          Endpoints Tested
                        </div>
                        <div className="text-lg font-mono font-bold text-sky-400 mt-0.5">
                          {summaryData.endpoints_tested_count}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-red-500/30">
                        <div className="text-[10px] uppercase text-red-400 font-semibold">
                          Confirmed Findings
                        </div>
                        <div className="text-lg font-mono font-bold text-red-400 mt-0.5">
                          {summaryData.confirmed_findings_count}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-amber-500/30">
                        <div className="text-[10px] uppercase text-amber-400 font-semibold">
                          Suspicious Findings
                        </div>
                        <div className="text-lg font-mono font-bold text-amber-400 mt-0.5">
                          {summaryData.suspicious_results_count}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-purple-500/30">
                        <div className="text-[10px] uppercase text-purple-400 font-semibold">
                          Inconclusive Checks
                        </div>
                        <div className="text-lg font-mono font-bold text-purple-300 mt-0.5">
                          {summaryData.inconclusive_count ??
                            inconclusiveEndpoints.length}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-zinc-700">
                        <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                          Untested Checks
                        </div>
                        <div className="text-lg font-mono font-bold text-zinc-300 mt-0.5">
                          {summaryData.not_tested_count ??
                            untestedEndpoints.length}
                        </div>
                      </div>
                    </div>

                    <section className="rounded-xl border border-blue-500/30 bg-blue-950/15 p-4 space-y-2" aria-label="Beginner-friendly final report">
                      <h4 className="font-semibold text-white">What this assessment found</h4>
                      <p className="text-sm text-zinc-300">
                        {confirmedReportFindings.length} confirmed issue(s); {investigatingFindings.length} result(s) still need investigation.
                      </p>
                      {highestRiskFinding ? (
                        <>
                          <p className="text-sm text-zinc-300"><strong className="text-white">{highestRiskFinding.validation_status === "CONFIRMED" ? "Most serious confirmed issue:" : "Highest-risk result still under investigation:"}</strong> {highestRiskFinding.beginner_explanation?.simple_title || highestRiskFinding.title} ({highestRiskLabel}).</p>
                          <p className="text-sm text-zinc-300"><strong className="text-white">Possible effect on users:</strong> {highestRiskFinding.beginner_explanation?.real_world_impact || "The impact is not established by the available evidence."}</p>
                          {firstRecommendedFix && <p className="text-sm text-zinc-300"><strong className="text-white">{highestRiskFinding.validation_status === "CONFIRMED" ? "Fix first:" : "Next step:"}</strong> {firstRecommendedFix}</p>}
                        </>
                      ) : (
                        <p className="text-sm text-zinc-300">No issue was confirmed. Review any results still under investigation before drawing conclusions.</p>
                      )}
                      {reportRecommendations.length > 0 && <div><strong className="text-sm text-white">Important recommendations</strong><ul className="list-disc pl-5 text-sm text-zinc-300">{reportRecommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul></div>}
                    </section>

                    {summaryData.summary_text && (
                      <div className="text-xs text-zinc-300 bg-zinc-950/60 border border-zinc-800 rounded-lg p-3 leading-relaxed">
                        <strong className="text-zinc-100">Final Summary: </strong>
                        {summaryData.summary_text}
                      </div>
                    )}
                  </div>
                )}

                {/* ========================================================= */}
                {/* 3D. Streaming Conversational Markdown Output              */}
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
                                <span className="font-mono">
                                  proposed-remediation.js (Not applied to website)
                                </span>
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
                      Connecting to application and executing authorization
                      tests...
                    </div>
                  )}

                  {isRunningState && streamingText && (
                    <span className="inline-block w-2 h-4 ml-1 bg-blue-500 animate-pulse align-middle" />
                  )}
                </div>

                {error && (
                  <div className="mt-4 p-3 rounded-xl bg-red-950/40 border border-red-700/50 text-red-300 text-xs flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" />
                    <span>{error}</span>
                  </div>
                )}

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
          <div className="max-w-4xl mx-auto flex items-center justify-between gap-4 p-2.5 rounded-2xl bg-[#111827] border border-[#263248] shadow-2xl">
            <div className="flex items-center gap-2 px-3 text-xs text-gray-400 font-mono">
              {isRunningState ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
                  <span className="text-blue-400 font-medium">
                    {status === "findings_discovered"
                      ? `Testing active (${findings.length} finding(s))`
                      : "Assessing target..."}
                  </span>
                </>
              ) : status === "completed" || status === "no_vulnerabilities" ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-gray-300">
                    Assessment Complete · {confirmedFindings.length} Confirmed ·{" "}
                    {suspiciousFindings.length} Suspicious
                  </span>
                </>
              ) : (
                <>
                  <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-amber-400 capitalize">{status}</span>
                </>
              )}
            </div>

            <div className="flex items-center gap-2">
              {isRunningState && (
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

      {/* =================================================================== */}
      {/* TARGET AUTHORIZATION & SCOPE REVIEW MODAL                            */}
      {/* =================================================================== */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="relative w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-2xl bg-[#0F172A] border border-[#1E293B] shadow-2xl p-6 text-left">
            <div className="flex items-center justify-between pb-4 border-b border-[#1E293B]">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-blue-600/15 border border-blue-500/30 text-blue-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-white">
                    Target Website Authorization Review
                  </h3>
                  <p className="text-xs text-gray-400">
                    Server-Side Authorized Scope & Boundary Approval
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowAuthModal(false)}
                className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-[#1E293B] transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target Breakdown */}
            <div className="mt-4 p-3.5 rounded-xl bg-[#090D16] border border-[#1E293B] space-y-2">
              <div className="text-xs font-semibold text-gray-300">
                Target Parameters (Exact Scope Boundaries)
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <div>
                  <div className="text-[10px] text-gray-500">EXACT HOST</div>
                  <div className="text-blue-300 truncate">
                    {targetAuth?.hostname || parsedTarget.host || "hostname"}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500">SCHEME</div>
                  <div className="text-gray-200">
                    {(parsedTarget.scheme || "http").toUpperCase()}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500">PORT</div>
                  <div className="text-gray-200">
                    {parsedTarget.port || 80}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-gray-500 pt-1 border-t border-gray-800">
                Exact-host authorization enforced. Subdomains are never automatically authorized.
              </div>
            </div>

            {/* Approval Status Banner */}
            <div className="mt-4">
              <div
                className={`p-3.5 rounded-xl text-xs flex items-center justify-between ${
                  targetAuth?.is_authorized
                    ? "bg-emerald-950/40 border border-emerald-600/50 text-emerald-300"
                    : targetAuth?.status === "PENDING"
                    ? "bg-amber-950/40 border border-amber-600/50 text-amber-300"
                    : targetAuth?.status === "REVOKED"
                    ? "bg-red-950/40 border border-red-600/50 text-red-300"
                    : targetAuth?.status === "EXPIRED"
                    ? "bg-orange-950/40 border border-orange-600/50 text-orange-300"
                    : "bg-zinc-900 border border-zinc-700 text-gray-300"
                }`}
              >
                <div className="flex items-center gap-2">
                  {targetAuth?.is_authorized ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : targetAuth?.status === "PENDING" ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  ) : (
                    <Lock className="w-4 h-4 text-zinc-400 shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold">
                      Status: {targetAuth?.status || "UNREGISTERED"}
                    </div>
                    <div className="text-[11px] opacity-80">
                      {targetAuth?.reason || "Target requires review and approval."}
                    </div>
                  </div>
                </div>

                {targetAuth?.profile?.approved_by && (
                  <div className="text-[10px] font-mono opacity-80 text-right">
                    Approved by: {targetAuth.profile.approved_by}
                  </div>
                )}
              </div>
            </div>

            {/* Authorization Grounds Form */}
            <div className="mt-4 space-y-3">
              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">
                  Authorization Grounds / Basis
                </label>
                <select
                  value={authBasis}
                  onChange={(e) => setAuthBasis(e.target.value as AuthorizationBasis)}
                  className="w-full px-3 py-2 rounded-lg bg-[#090D16] border border-[#263248] text-xs text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="admin_approved">
                    Admin Approved — Explicit security administrator authorization
                  </option>
                  <option value="written_permission">
                    Documented Written Permission — Client agreement, SOW, or ticket
                  </option>
                  <option value="bug_bounty_scope">
                    Authorized Bug Bounty Scope — Documented in-scope program
                  </option>
                  <option value="domain_ownership_challenge">
                    Domain Ownership Verification — HTTP /.well-known challenge
                  </option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">
                  Permission Evidence / Reference
                </label>
                <input
                  type="text"
                  value={permissionRef}
                  onChange={(e) => setPermissionRef(e.target.value)}
                  placeholder="Ticket #, SOW document ID, or Bug Bounty policy link"
                  className="w-full px-3 py-2 rounded-lg bg-[#090D16] border border-[#263248] text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Approver Identifier
                  </label>
                  <input
                    type="text"
                    value={adminApprover}
                    onChange={(e) => setAdminApprover(e.target.value)}
                    placeholder="security_admin"
                    className="w-full px-3 py-2 rounded-lg bg-[#090D16] border border-[#263248] text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 mb-1">
                    Validity (Days)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={approvalDays}
                    onChange={(e) => setApprovalDays(Number(e.target.value) || 30)}
                    className="w-full px-3 py-2 rounded-lg bg-[#090D16] border border-[#263248] text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 mb-1">
                  Operator Notes (Optional)
                </label>
                <input
                  type="text"
                  value={authNotes}
                  onChange={(e) => setAuthNotes(e.target.value)}
                  placeholder="Notes regarding scope constraints, testing window, or authorized entities"
                  className="w-full px-3 py-2 rounded-lg bg-[#090D16] border border-[#263248] text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
                />
              </div>

              {/* If Domain Challenge is selected */}
              {authBasis === "domain_ownership_challenge" && (
                <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30 text-xs text-blue-200 space-y-1.5">
                  <div className="font-semibold flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-blue-400" />
                    Domain Challenge Verification
                  </div>
                  <p className="text-[11px] text-gray-300">
                    Host the token at `http(s)://&lt;host&gt;/.well-known/authscope-challenge.txt`:
                  </p>
                  <div className="p-1.5 rounded bg-black/50 font-mono text-[11px] text-emerald-300 break-all select-all">
                    {targetAuth?.profile?.verification_token
                      ? targetAuth.profile.verification_token
                      : "Submit target first to generate verification challenge token"}
                  </div>
                  {targetAuth?.profile?.verification_token && (
                    <button
                      type="button"
                      disabled={isSubmittingAuth}
                      onClick={() => verifyDomainChallengeAction(targetAuth.profile!.id)}
                      className="mt-2 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors"
                    >
                      Verify Challenge Now
                    </button>
                  )}
                </div>
              )}

              {/* Actions & Feedback */}
              {authActionMessage && (
                <div className="p-2.5 rounded-lg bg-blue-950/40 border border-blue-600/40 text-blue-200 text-xs">
                  {authActionMessage}
                </div>
              )}

              <div className="pt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[#1E293B]">
                {/* Submit / Register target */}
                <button
                  type="button"
                  disabled={isSubmittingAuth}
                  onClick={submitTargetForAuth}
                  className="px-3.5 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-white font-medium text-xs transition-colors"
                >
                  {isSubmittingAuth ? "Submitting..." : "1. Submit for Approval"}
                </button>

                <div className="flex items-center gap-2">
                  {/* Admin Approval Button if Profile exists and not approved */}
                  {targetAuth?.profile && targetAuth.profile.approval_status !== "APPROVED" && (
                    <button
                      type="button"
                      disabled={isSubmittingAuth}
                      onClick={() => approveTargetAction(targetAuth.profile!.id)}
                      className="px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors flex items-center gap-1.5"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      2. Admin Approve Target
                    </button>
                  )}

                  {/* Revoke Target if already approved */}
                  {targetAuth?.profile && targetAuth.profile.approval_status === "APPROVED" && (
                    <button
                      type="button"
                      disabled={isSubmittingAuth}
                      onClick={() => revokeTargetAction(targetAuth.profile!.id)}
                      className="px-3 py-2 rounded-xl bg-red-950/60 hover:bg-red-900 border border-red-700/60 text-red-200 font-medium text-xs transition-colors"
                    >
                      Revoke Authorization
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => {
                      setShowAuthModal(false);
                      if (targetAuth?.is_authorized && status === "ready") {
                        startAssessment();
                      }
                    }}
                    className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs transition-colors"
                  >
                    {targetAuth?.is_authorized ? "Start Assessment" : "Done"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
