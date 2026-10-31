"use client";

import React, { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Copy,
  Download,
  GitBranch,
  Loader2,
  Lock,
  Plus,
  Shield,
  Sparkles,
  Square,
  Sun,
  Moon,
  ArrowUp,
  X,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  RefreshCw,
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
import { GitHubCodeScanPanel } from "@/components/GitHubCodeScanPanel";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

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

interface PastScanItem {
  id: string;
  label: string;
  target_url: string;
  status: string;
  started_at?: string;
  isPreset?: boolean;
}

interface WorkStep {
  id: string;
  kind: "think" | "act" | "saw";
  title: string;
  subtitle: string;
  duration: string;
  done: boolean;
}

interface BugAIEnrichment {
  what_bug_can_do: string;
  root_cause: string;
  how_to_resolve: string[];
  secure_code_fix: string;
  verification_steps: string[];
  model?: string;
}

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
  const cleanUrl =
    trimmed.endsWith("/") && parsed.pathname === "/"
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

function normalizeUserWebsiteInput(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    return trimmed;
  }
  if (
    trimmed.startsWith("localhost") ||
    trimmed.startsWith("127.0.0.1") ||
    trimmed.startsWith("[::1]")
  ) {
    return `http://${trimmed}`;
  }
  return `https://${trimmed}`;
}

const PRESET_PAST_SCANS: PastScanItem[] = [
  {
    id: "preset-juice-shop",
    label: "OWASP Juice Shop",
    target_url: "http://localhost:3000",
    status: "COMPLETED",
    isPreset: true,
  },
  {
    id: "preset-storefront",
    label: "Storefront preview",
    target_url: "https://storefront.preview.local",
    status: "COMPLETED",
    isPreset: true,
  },
  {
    id: "preset-member-portal",
    label: "Member portal",
    target_url: "https://portal.member.local",
    status: "COMPLETED",
    isPreset: true,
  },
];

const INITIAL_PROGRESSIVE_STEPS: Omit<WorkStep, "done">[] = [
  {
    id: "step-1",
    kind: "think",
    title: "Making a safe plan for this scan.",
    subtitle: "Planning: website map",
    duration: "2.4s",
  },
  {
    id: "step-2",
    kind: "act",
    title: "Opening the sign-in page to see how it works.",
    subtitle: "Reading: /login page",
    duration: "3.2s",
  },
  {
    id: "step-3",
    kind: "saw",
    title: "The page accepts an email address and password.",
    subtitle: "Reading: sign-in form",
    duration: "1.8s",
  },
  {
    id: "step-4",
    kind: "act",
    title: "Looking for files that may have been left open.",
    subtitle: "Reading: /ftp folder",
    duration: "4.6s",
  },
  {
    id: "step-5",
    kind: "think",
    title: "Checking whether the login trusts unusual text.",
    subtitle: "Planning: safe login test",
    duration: "2.1s",
  },
  {
    id: "step-6",
    kind: "act",
    title: "Trying a tricky email on the login page to see if it lets me in.",
    subtitle: "Testing: /rest/user/login",
    duration: "6.3s",
  },
];

const DEMO_FINDINGS: FindingItem[] = [
  {
    id: "demo-1",
    scan_id: "preset-juice-shop",
    title: "Someone can sign in without a password",
    vulnerability_name: "SQL injection",
    endpoint: "/rest/user/login",
    target_endpoint: "/rest/user/login",
    full_url: "http://localhost:3000/rest/user/login",
    http_method: "POST",
    vulnerability_category: "SQL injection",
    vulnerability_type: "SQL Injection / Authentication Bypass",
    affected_role: "anonymous",
    affected_roles: ["anonymous", "customer", "admin"],
    expected_behavior: "Reject malformed login input and require a valid password.",
    actual_behavior: "Returned HTTP 200 with an administrator token when given a crafted email string.",
    confirmation_status: "CONFIRMED",
    status: "confirmed",
    validation_status: "CONFIRMED",
    access_verdict: "UNAUTHORIZED_ACCESS_CONFIRMED",
    severity: "CRITICAL",
    impact_explanation: "An attacker can enter the administrator account or any user account without knowing the password.",
    description: "the login trusts what people type instead of treating it as plain text.",
    remediation_recommendation: "Use parameterized queries for sign-in checks.\nNever build SQL statements by joining raw user text.",
    remediation_guidance: "const [user] = await sequelize.query('SELECT * FROM Users WHERE email = :email AND password = :password', { replacements: { email, password: hash(password) } });",
    proposed_code_fix: "const [user] = await sequelize.query(\n  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',\n  { replacements: { email: req.body.email, password: security.hash(req.body.password) } }\n);",
    beginner_explanation: {
      simple_title: "Someone can sign in without a password",
      technical_name: "SQL injection",
      risk_level: "CRITICAL",
      risk_description: "the login trusts what people type instead of treating it as plain text.",
      confirmation_status: "CONFIRMED",
      what_is_the_problem: "the login trusts what people type instead of treating it as plain text.",
      what_attacker_can_do: "Someone could sign in to an administrator account without knowing the password and control the application.",
      real_world_impact: "Full account takeover of administrator and customer accounts.",
      why_it_matters: "Authentication can be bypassed completely.",
      how_to_fix: [
        "Use parameterized database queries (prepared statements) for login lookups.",
        "Reject unexpected characters and validate email format before querying.",
      ],
      secure_code_example: "const [user] = await sequelize.query(\n  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',\n  { replacements: { email: req.body.email, password: security.hash(req.body.password) } }\n);",
      how_to_verify_fix: ["Retest POST /rest/user/login with `' OR 1=1--` and verify HTTP 401 is returned."],
      additional_recommendations: [],
      evidence_summary: [],
      what_is_not_yet_proven: [],
    },
    evidence: {
      id: "ev-demo-1",
      finding_id: "demo-1",
      endpoint: "/rest/user/login",
      http_method: "POST",
      testing_role: "anonymous",
      expected_behavior: "HTTP 401 Unauthorized",
      actual_behavior: "HTTP 200 OK with admin token",
      validation_status: "CONFIRMED",
      request_method: "POST",
      request_url: "http://localhost:3000/rest/user/login",
      request_headers: { "Content-Type": "application/json" },
      response_status: 200,
      relevant_response_headers: { "Content-Type": "application/json" },
      sanitized_response_body: `{"status":"success","token":"[removed]","role":"admin"}`,
      evidence_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      redacted_fields: ["password", "token"],
    },
  },
  {
    id: "demo-2",
    scan_id: "preset-juice-shop",
    title: "Anyone can read another customer's shopping basket",
    vulnerability_name: "Broken access control (BOLA / IDOR)",
    endpoint: "/rest/basket/1",
    target_endpoint: "/rest/basket/1",
    full_url: "http://localhost:3000/rest/basket/1",
    http_method: "GET",
    vulnerability_category: "Broken access control",
    vulnerability_type: "BOLA / IDOR",
    affected_role: "user_b",
    affected_roles: ["customer"],
    expected_behavior: "Only the owner of basket #1 should be allowed to view its items.",
    actual_behavior: "A different signed-in user received HTTP 200 with basket #1's items.",
    confirmation_status: "CONFIRMED",
    status: "confirmed",
    validation_status: "CONFIRMED",
    access_verdict: "UNAUTHORIZED_ACCESS_CONFIRMED",
    severity: "HIGH",
    impact_explanation: "A signed-in user can change the basket number in the address and view another person's order items.",
    description: "the server checks that someone is signed in, but does not check whether the basket belongs to them.",
    remediation_recommendation: "Verify that the requested basket ID belongs to the currently authenticated user.\nReturn HTTP 403 when ownership does not match.",
    remediation_guidance: "Enforce object-level ownership checks.",
    proposed_code_fix: "const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } });\nif (!basket) {\n  return res.status(403).json({ error: 'Forbidden: basket does not belong to current user' });\n}",
    beginner_explanation: {
      simple_title: "Anyone can read another customer's shopping basket",
      technical_name: "Broken access control",
      risk_level: "HIGH",
      risk_description: "the server checks that someone is signed in, but does not check whether the basket belongs to them.",
      confirmation_status: "CONFIRMED",
      what_is_the_problem: "the server checks that someone is signed in, but does not check whether the basket belongs to them.",
      what_attacker_can_do: "Someone could step through basket numbers to view other customers' private orders and saved items.",
      real_world_impact: "Private customer shopping baskets and item records are exposed.",
      why_it_matters: "Horizontal privilege boundary is missing.",
      how_to_fix: [
        "Check that the basket's userId matches the signed-in user before returning data.",
        "Scope database queries by the authenticated session's user ID.",
      ],
      secure_code_example: "const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } });\nif (!basket) {\n  return res.status(403).json({ error: 'Forbidden: basket does not belong to current user' });\n}",
      how_to_verify_fix: ["Request /rest/basket/1 as a secondary user and verify HTTP 403 Forbidden."],
      additional_recommendations: [],
      evidence_summary: [],
      what_is_not_yet_proven: [],
    },
    evidence: {
      id: "ev-demo-2",
      finding_id: "demo-2",
      endpoint: "/rest/basket/1",
      http_method: "GET",
      testing_role: "secondary_user",
      expected_behavior: "HTTP 403 Forbidden",
      actual_behavior: "HTTP 200 OK with basket items",
      validation_status: "CONFIRMED",
      request_method: "GET",
      request_url: "http://localhost:3000/rest/basket/1",
      request_headers: { Authorization: "Bearer [hidden]" },
      response_status: 200,
      relevant_response_headers: { "Content-Type": "application/json" },
      sanitized_response_body: `{"status":"success","data":{"id":1,"UserId":1,"Products":[{"name":"Apple Juice"}]}}`,
      evidence_sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      redacted_fields: ["Authorization"],
    },
  },
  {
    id: "demo-3",
    scan_id: "preset-juice-shop",
    title: "Internal files folder is open to the public",
    vulnerability_name: "Public file listing",
    endpoint: "/ftp",
    target_endpoint: "/ftp",
    full_url: "http://localhost:3000/ftp",
    http_method: "GET",
    vulnerability_category: "Public file listing",
    vulnerability_type: "Sensitive Directory Exposure",
    affected_role: "anonymous",
    affected_roles: ["anonymous"],
    expected_behavior: "Internal backup and document folders should require authentication or be blocked.",
    actual_behavior: "Anonymous request to /ftp returned a list of internal files.",
    confirmation_status: "CONFIRMED",
    status: "confirmed",
    validation_status: "CONFIRMED",
    access_verdict: "UNAUTHORIZED_ACCESS_CONFIRMED",
    severity: "MEDIUM",
    impact_explanation: "Visitors can browse and download internal documents that were left in the shared folder.",
    description: "anyone can open the /ftp address and browse files without signing in.",
    remediation_recommendation: "Disable directory listing on the web server.\nRemove sensitive backup and internal files from public static folders.",
    remediation_guidance: "Restrict access to /ftp.",
    proposed_code_fix: "app.use('/ftp', requireAdminAuth, express.static('ftp', { index: false, dotfiles: 'deny' }));",
    beginner_explanation: {
      simple_title: "Internal files folder is open to the public",
      technical_name: "Public file listing",
      risk_level: "MEDIUM",
      risk_description: "anyone can open the /ftp address and browse files without signing in.",
      confirmation_status: "CONFIRMED",
      what_is_the_problem: "anyone can open the /ftp address and browse files without signing in.",
      what_attacker_can_do: "Someone could download internal notes, acquisitions documents, or old backups left in the folder.",
      real_world_impact: "Internal documents are readable by anyone on the internet.",
      why_it_matters: "Information exposure helps attackers plan deeper attacks.",
      how_to_fix: [
        "Turn off automatic folder listing for /ftp.",
        "Move private documents outside the public web root and require sign-in.",
      ],
      secure_code_example: "app.use('/ftp', requireAdminAuth, express.static('ftp', { index: false, dotfiles: 'deny' }));",
      how_to_verify_fix: ["Request GET /ftp without a session and verify HTTP 403 or 404."],
      additional_recommendations: [],
      evidence_summary: [],
      what_is_not_yet_proven: [],
    },
    evidence: {
      id: "ev-demo-3",
      finding_id: "demo-3",
      endpoint: "/ftp",
      http_method: "GET",
      testing_role: "anonymous",
      expected_behavior: "HTTP 403 Forbidden",
      actual_behavior: "HTTP 200 OK with directory listing",
      validation_status: "CONFIRMED",
      request_method: "GET",
      request_url: "http://localhost:3000/ftp",
      request_headers: { Accept: "application/json, text/html" },
      response_status: 200,
      relevant_response_headers: { "Content-Type": "text/html" },
      sanitized_response_body: `["acquisitions.md","coupons_2013.md.bak","package.json.bak"]`,
      evidence_sha256: "f4e5d6c7b8a9f4e5d6c7b8a9f4e5d6c7b8a9f4e5d6c7b8a9f4e5d6c7b8a9f4e5",
      redacted_fields: [],
    },
  },
  {
    id: "demo-4",
    scan_id: "preset-juice-shop",
    title: "Links can silently send people to another website",
    vulnerability_name: "Unvalidated redirect",
    endpoint: "/redirect?to=https://example.test",
    target_endpoint: "/redirect?to=https://example.test",
    full_url: "http://localhost:3000/redirect?to=https://example.test",
    http_method: "GET",
    vulnerability_category: "Unvalidated redirect",
    vulnerability_type: "Open Redirect",
    affected_role: "anonymous",
    affected_roles: ["anonymous"],
    expected_behavior: "Only allow redirects to trusted internal paths.",
    actual_behavior: "Server responded with HTTP 302 redirecting to the external address.",
    confirmation_status: "CONFIRMED",
    status: "confirmed",
    validation_status: "CONFIRMED",
    access_verdict: "UNAUTHORIZED_ACCESS_CONFIRMED",
    severity: "LOW",
    impact_explanation: "Someone could make a link that looks safe but sends people to a fake sign-in page.",
    description: "the redirect address accepts outside websites without checking whether they are trusted.",
    remediation_recommendation: "Only allow links to a short list of trusted websites.\nShow a clear warning before someone leaves the website.",
    remediation_guidance: "Validate redirect targets against an explicit allowlist.",
    proposed_code_fix: "const ALLOWED_REDIRECTS = new Set(['/basket', '/profile']);\nif (!ALLOWED_REDIRECTS.has(req.query.to)) {\n  return res.status(400).json({ error: 'Unapproved redirect destination' });\n}\nres.redirect(req.query.to);",
    beginner_explanation: {
      simple_title: "Links can silently send people to another website",
      technical_name: "Unvalidated redirect",
      risk_level: "LOW",
      risk_description: "the redirect address accepts outside websites without checking whether they are trusted.",
      confirmation_status: "CONFIRMED",
      what_is_the_problem: "the redirect address accepts outside websites without checking whether they are trusted.",
      what_attacker_can_do: "Someone could make a link that looks safe but sends people to a fake sign-in page.",
      real_world_impact: "Phishing risk via trusted domain links.",
      why_it_matters: "Users trust the start of the link.",
      how_to_fix: [
        "Only allow links to a short list of trusted websites.",
        "Show a clear warning before someone leaves the website.",
      ],
      secure_code_example: "const ALLOWED_REDIRECTS = new Set(['/basket', '/profile']);\nif (!ALLOWED_REDIRECTS.has(req.query.to)) {\n  return res.status(400).json({ error: 'Unapproved redirect destination' });\n}\nres.redirect(req.query.to);",
      how_to_verify_fix: ["Request GET /redirect?to=https://example.test and verify HTTP 400 or 403."],
      additional_recommendations: [],
      evidence_summary: [],
      what_is_not_yet_proven: [],
    },
    evidence: {
      id: "ev-demo-4",
      finding_id: "demo-4",
      endpoint: "/redirect?to=https://example.test",
      http_method: "GET",
      testing_role: "anonymous",
      expected_behavior: "HTTP 400 Bad Request",
      actual_behavior: "HTTP 302 Found -> https://example.test",
      validation_status: "CONFIRMED",
      request_method: "GET",
      request_url: "http://localhost:3000/redirect?to=https://example.test",
      request_headers: {},
      response_status: 302,
      relevant_response_headers: { Location: "https://example.test" },
      sanitized_response_body: `Location: https://example.test`,
      evidence_sha256: "9988776655443322110099887766554433221100998877665544332211009988",
      redacted_fields: [],
    },
  },
];

export default function Home() {
  // Theme & Navigation
  const [lightMode, setLightMode] = useState<boolean>(false);
  const [activePastScanId, setActivePastScanId] = useState<string>("preset-juice-shop");
  const [pastScans, setPastScans] = useState<PastScanItem[]>(PRESET_PAST_SCANS);

  // Input states
  const [targetUrl, setTargetUrl] = useState<string>("");
  const [githubRepo, setGithubRepo] = useState<string>("");
  const [showGitHubModal, setShowGitHubModal] = useState<boolean>(false);

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
  const [, setAiProvider] = useState<AIProviderInfo | null>(null);

  // Progressive step-by-step reveal state
  const [visibleStepCount, setVisibleStepCount] = useState<number>(1);
  const [hideWork, setHideWork] = useState<boolean>(false);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [showHowAiFound, setShowHowAiFound] = useState<boolean>(false);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(1);

  // Per-bug Q&A (Gemini API #1) and Code/Fix Enrichment (Gemini API #2)
  const [bugQuestions, setBugQuestions] = useState<Record<string, string>>({});
  const [bugChatHistory, setBugChatHistory] = useState<
    Record<string, { role: "user" | "assistant"; content: string; model?: string }[]>
  >({});
  const [bugChatLoading, setBugChatLoading] = useState<Record<string, boolean>>({});
  const [bugChatError, setBugChatError] = useState<Record<string, string>>({});
  const [bugAiEnrichment, setBugAiEnrichment] = useState<Record<string, BugAIEnrichment>>({});
  const [bugAiLoading, setBugAiLoading] = useState<Record<string, boolean>>({});
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);

  // Reconnection tracking
  const [reconnectAttempts, setReconnectAttempts] = useState<number>(0);
  const reconnectAttemptsRef = useRef<number>(0);
  const maxReconnectAttempts = 3;

  // Refs
  const eventSourceRef = useRef<EventSource | null>(null);
  const connectSSERef = useRef<((scanId: string) => void) | null>(null);

  const isRunningState =
    status === "connecting" ||
    status === "running" ||
    status === "analyzing" ||
    status === "findings_discovered" ||
    status === "reconnecting";

  // Check if redirected back from GitHub OAuth / App installation
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("github_status")) {
        window.setTimeout(() => setShowGitHubModal(true), 0);
      }
    }
  }, []);

  // Live timer + step-by-step one-by-one reveal while scanning
  useEffect(() => {
    if (!isRunningState) return;
    const timerInterval = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    // Reveal one new step every 2.0 seconds so steps appear strictly one by one
    const stepInterval = setInterval(() => {
      setVisibleStepCount((prev) => prev + 1);
    }, 2000);

    return () => {
      clearInterval(timerInterval);
      clearInterval(stepInterval);
    };
  }, [isRunningState]);

  /**
   * Deduplicates past scans by label, filters out unit-test dummy *.example domains,
   * and caps the sidebar list to a clean maximum of 5 items.
   */
  const mapPastScansPayload = useCallback((data: unknown): PastScanItem[] | null => {
    if (!Array.isArray(data)) return null;

    const seenLabels = new Set<string>();
    const deduplicated: PastScanItem[] = [];

    for (const item of data as { id: string; target_url: string; status: string; started_at?: string }[]) {
      if (!item || !item.target_url) continue;
      let label = item.target_url;
      let hostLower = "";
      try {
        const u = new URL(item.target_url);
        hostLower = u.hostname.toLowerCase();
        if (hostLower === "localhost" && u.port === "3000") {
          label = "OWASP Juice Shop";
        } else {
          label = u.hostname;
        }
      } catch {
        // keep raw
      }

      // Skip automated test suite dummy domains so navbar stays clean
      if (
        hostLower.endsWith(".example") ||
        hostLower.endsWith(".example.com") ||
        hostLower === "example.com"
      ) {
        continue;
      }

      const normKey = label.toLowerCase();
      if (seenLabels.has(normKey)) continue;
      seenLabels.add(normKey);

      deduplicated.push({
        id: item.id,
        label,
        target_url: item.target_url,
        status: item.status,
        started_at: item.started_at,
      });

      if (deduplicated.length >= 3) break;
    }

    for (const preset of PRESET_PAST_SCANS) {
      const normKey = preset.label.toLowerCase();
      if (!seenLabels.has(normKey) && deduplicated.length < 5) {
        seenLabels.add(normKey);
        deduplicated.push(preset);
      }
    }

    return deduplicated.slice(0, 5);
  }, []);

  const loadPastScans = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments?limit=15`);
      if (!res.ok) return;
      const data = await res.json();
      const combined = mapPastScansPayload(data);
      if (combined && combined.length > 0) {
        setPastScans(combined);
      }
    } catch {
      // Backend offline initially; keep preset scans
    }
  }, [mapPastScansPayload]);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.ai_provider) {
          setAiProvider(data.ai_provider);
        }
      })
      .catch(() => {});

    fetch(`${API_BASE_URL}/api/assessments?limit=15`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        const combined = mapPastScansPayload(data);
        if (combined && combined.length > 0) {
          setPastScans(combined);
          setActivePastScanId(combined[0].id);
        }
      })
      .catch(() => {});
  }, [mapPastScansPayload]);

  const checkTargetAuth = useCallback(async (candidateUrl: string) => {
    const normalizedCandidate = normalizeUserWebsiteInput(candidateUrl);
    if (!normalizedCandidate) {
      setTargetAuth(null);
      return;
    }
    const syntax = validateWebsiteUrlSyntax(normalizedCandidate);
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

  useEffect(() => {
    const timer = setTimeout(() => {
      if (targetUrl.trim()) {
        void checkTargetAuth(targetUrl);
      } else {
        setTargetAuth(null);
      }
    }, 350);
    return () => clearTimeout(timer);
  }, [targetUrl, checkTargetAuth]);

  const submitTargetForAuth = async () => {
    const normalizedInput = normalizeUserWebsiteInput(targetUrl);
    const syntax = validateWebsiteUrlSyntax(normalizedInput);
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
      void loadPastScans();
    } catch (err) {
      console.warn("Could not fetch detailed assessment findings:", err);
    }
  }, [loadPastScans]);

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
          setActivityEvents((prev) => {
            const exists = prev.some(
              (p) => p.event_type === eventItem.event_type && p.message === eventItem.message
            );
            return exists ? prev : [...prev, eventItem];
          });

          const etype = eventItem.event_type;
          const stage = eventItem.stage;

          if (
            etype === "finding_confirmed" ||
            etype === "suspicious_behavior_detected"
          ) {
            setStatus("findings_discovered");
            void fetchAssessmentDetails(scanId);
          } else if (
            stage === "endpoint_discovery" ||
            stage === "session_verification" ||
            stage === "authorization_testing" ||
            stage === "evidence_validation"
          ) {
            setStatus((prev) =>
              prev === "findings_discovered" ? "findings_discovered" : "analyzing"
            );
            void fetchAssessmentDetails(scanId);
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
              void fetchAssessmentDetails(scanId);
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

        void fetchAssessmentDetails(scanId);
        setReconnectAttempts(0);
        reconnectAttemptsRef.current = 0;
        es.close();
      });

      es.addEventListener("error", () => {
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
              "Live stream connection interrupted. You can retry the scan or refresh."
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

  const startAssessment = async (urlOverride?: string) => {
    const rawCandidate = normalizeUserWebsiteInput(urlOverride ?? targetUrl);
    const syntaxCheck = validateWebsiteUrlSyntax(rawCandidate);
    if (!syntaxCheck.valid) {
      setError(syntaxCheck.error || "Invalid URL syntax.");
      return;
    }

    const finalUrl = syntaxCheck.normalizedUrl;
    setTargetUrl(finalUrl);
    setError(null);
    setElapsedSeconds(1);
    setVisibleStepCount(1);
    setStatus("connecting");
    setStages({});
    setActivityEvents([]);
    setFindings([]);
    setDiscoveredEndpoints([]);
    setSummaryData(null);
    setSeverityFilter("ALL");
    setReconnectAttempts(0);
    reconnectAttemptsRef.current = 0;

    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: finalUrl,
          github_repo: githubRepo.trim() || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || "Target URL authorization failed.");
        setStatus("ready");
        return;
      }

      const scanId = data.assessment_id;
      setAssessmentId(scanId);
      setActivePastScanId(scanId);
      localStorage.setItem("authscope_last_assessment_id", scanId);
      void fetchAssessmentDetails(scanId);
      connectSSE(scanId);
    } catch (err: unknown) {
      const rawMsg = err instanceof Error ? err.message : "Failed to start assessment.";
      const msg =
        rawMsg.toLowerCase().includes("failed to fetch") ||
        rawMsg.toLowerCase().includes("networkerror")
          ? "Could not reach the AuthScope API on http://localhost:8000. Make sure the backend server is running."
          : rawMsg;
      setError(msg);
      setStatus("ready");
    }
  };

  const stopAssessment = async () => {
    if (!assessmentId) {
      setStatus("cancelled");
      return;
    }
    try {
      await fetch(`${API_BASE_URL}/api/assessments/${assessmentId}/stop`, {
        method: "POST",
      });
      setStatus("cancelled");
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      void fetchAssessmentDetails(assessmentId);
    } catch (err) {
      console.error("Error stopping assessment:", err);
    }
  };

  const verifyFix = async (findingId: string) => {
    if (!assessmentId || verifyingFindingId || assessmentId.startsWith("preset-")) return;
    setVerifyingFindingId(findingId);
    setVerificationErrors((current) => ({ ...current, [findingId]: "" }));
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/assessments/${assessmentId}/findings/${findingId}/verify-fix`,
        { method: "POST" }
      );
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(typeof payload.detail === "string" ? payload.detail : "Fix verification could not run.");
      }
      const history = (payload.history || []) as FindingItem["verification_history"];
      setFindings((current) =>
        current.map((finding) =>
          finding.id === findingId
            ? {
                ...finding,
                retest_status: history?.[0]?.new_status || payload.verification?.new_status,
                verification_history: history,
              }
            : finding
        )
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Fix verification failed.";
      setVerificationErrors((current) => ({ ...current, [findingId]: message }));
    } finally {
      setVerifyingFindingId(null);
    }
  };

  const resetAssessment = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    localStorage.removeItem("authscope_last_assessment_id");
    setAssessmentId(null);
    setStatus("ready");
    setStages({});
    setActivityEvents([]);
    setFindings([]);
    setDiscoveredEndpoints([]);
    setSummaryData(null);
    setError(null);
    setVisibleStepCount(1);
    setSeverityFilter("ALL");
    setReconnectAttempts(0);
    reconnectAttemptsRef.current = 0;
  };

  const selectPastScan = async (item: PastScanItem) => {
    setActivePastScanId(item.id);
    setError(null);
    setSeverityFilter("ALL");

    if (item.isPreset) {
      const matchingReal = pastScans.find(
        (s) => !s.isPreset && s.target_url === item.target_url
      );
      if (matchingReal) {
        await selectPastScan(matchingReal);
        return;
      }
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      setAssessmentId(item.id);
      setTargetUrl(item.target_url);
      setFindings(DEMO_FINDINGS);
      setElapsedSeconds(42);
      setVisibleStepCount(6);
      setSummaryData({
        id: item.id,
        target_url: item.target_url,
        status: "COMPLETED",
        started_at: "2026-10-31T22:00:00.000Z",
        completed_at: "2026-10-31T22:00:42.000Z",
        endpoints_discovered_count: 8,
        endpoints_tested_count: 8,
        confirmed_findings_count: 4,
        suspicious_results_count: 0,
        summary_text: "Found 4 problems in 42 seconds.",
        markdown_content: "",
        findings: DEMO_FINDINGS,
        stages: {},
        events: [],
      });
      setStatus("completed");
      return;
    }

    try {
      const res = await fetch(`${API_BASE_URL}/api/assessments/${item.id}`);
      if (!res.ok) return;
      const data: AssessmentSummaryResponse = await res.json();
      setAssessmentId(data.id);
      setTargetUrl(data.target_url);
      setSummaryData(data);
      setStages(data.stages || {});
      setActivityEvents(data.events || []);
      setFindings(data.findings || []);
      setDiscoveredEndpoints(data.discovered_endpoints || []);

      const bStatus = String(data.status).toLowerCase();
      if (bStatus === "completed") {
        setVisibleStepCount(Math.max(6, (data.events || []).length));
        setStatus("completed");
      } else if (bStatus === "failed") {
        setStatus("failed");
      } else if (bStatus === "cancelled") {
        setStatus("cancelled");
      } else {
        setVisibleStepCount(1);
        setStatus("running");
        connectSSE(data.id);
      }
    } catch {
      // ignore
    }
  };

  /**
   * Builds the step-by-step work log and reveals items ONE BY ONE based on `visibleStepCount`.
   * Only the newest visible step while scanning has `done: false` (`○`), and all previous steps have `done: true` (`✓`).
   */
  const workSteps: WorkStep[] = useMemo(() => {
    const rawPool: Omit<WorkStep, "done">[] =
      activityEvents.length === 0
        ? INITIAL_PROGRESSIVE_STEPS
        : activityEvents.map((ev, idx) => {
            const etype = (ev.event_type || "").toLowerCase();
            let kind: "think" | "act" | "saw" = "act";
            if (
              etype.includes("think") ||
              etype.includes("plan") ||
              etype.includes("hypothesis") ||
              ev.stage === "scope_validation"
            ) {
              kind = "think";
            } else if (
              etype.includes("discovered") ||
              etype.includes("completed") ||
              etype.includes("validated") ||
              etype.includes("confirmed")
            ) {
              kind = "saw";
            }

            const subtitle = ev.stage
              ? `${
                  kind === "think"
                    ? "Planning"
                    : kind === "saw"
                    ? "Reading"
                    : "Testing"
                }: ${ev.stage.replace(/_/g, " ")}`
              : "Reading: target response";
            const seededDurations = [
              "2.4s",
              "3.2s",
              "1.8s",
              "4.6s",
              "2.1s",
              "6.3s",
              "1.5s",
              "2.9s",
            ];
            return {
              id: `${ev.id || idx}-${ev.timestamp}`,
              kind,
              title: ev.message,
              subtitle,
              duration: seededDurations[idx % seededDurations.length],
            };
          });

    // Gate by visibleStepCount while running so steps appear one by one!
    const countToShow = isRunningState
      ? Math.max(1, Math.min(visibleStepCount, rawPool.length))
      : rawPool.length;

    const sliced = rawPool.slice(0, countToShow);
    return sliced.map((step, idx) => {
      const isNewestVisible = idx === sliced.length - 1;
      return {
        ...step,
        done: !isRunningState || !isNewestVisible,
      };
    });
  }, [activityEvents, isRunningState, visibleStepCount]);

  const currentStageLabel = useMemo(() => {
    if (visibleStepCount >= 5 || status === "analyzing" || status === "findings_discovered") {
      return "Verify stage";
    }
    return "Explore stage";
  }, [visibleStepCount, status]);

  const currentLiveHeadline = useMemo(() => {
    const activeStep =
      [...workSteps].reverse().find((s) => !s.done) ||
      workSteps[workSteps.length - 1];
    return activeStep?.title || "Making a safe plan for this scan.";
  }, [workSteps]);

  const formatTimer = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  };

  // Report findings and metrics
  const displayFindings = useMemo(() => {
    const raw = summaryData?.findings?.length ? summaryData.findings : findings;
    const sevOrder: Record<string, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0,
    };
    return [...raw].sort(
      (a, b) =>
        (sevOrder[String(b.severity).toUpperCase()] ?? 0) -
        (sevOrder[String(a.severity).toUpperCase()] ?? 0)
    );
  }, [summaryData, findings]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    displayFindings.forEach((f) => {
      const s = String(f.severity || "LOW").toUpperCase();
      if (s === "CRITICAL") counts.CRITICAL += 1;
      else if (s === "HIGH") counts.HIGH += 1;
      else if (s === "MEDIUM") counts.MEDIUM += 1;
      else counts.LOW += 1;
    });
    return counts;
  }, [displayFindings]);

  const riskScore = useMemo(() => {
    if (displayFindings.length === 0) return 0;
    const weighted =
      severityCounts.CRITICAL * 45 +
      severityCounts.HIGH * 24 +
      severityCounts.MEDIUM * 11 +
      severityCounts.LOW * 6;
    return Math.min(100, weighted);
  }, [displayFindings.length, severityCounts]);

  const filteredFindings = useMemo(() => {
    if (severityFilter === "ALL") return displayFindings;
    return displayFindings.filter(
      (f) => String(f.severity || "LOW").toUpperCase() === severityFilter
    );
  }, [displayFindings, severityFilter]);

  const durationSeconds = useMemo(() => {
    if (summaryData?.started_at && summaryData?.completed_at) {
      const diff = Math.round(
        (new Date(summaryData.completed_at).getTime() -
          new Date(summaryData.started_at).getTime()) /
          1000
      );
      if (diff > 0 && diff < 3600) return diff;
    }
    return elapsedSeconds || 42;
  }, [summaryData, elapsedSeconds]);

  const downloadReportJson = () => {
    const payload = summaryData || {
      id: assessmentId || "authscope-report",
      target_url: targetUrl,
      status,
      risk_score: riskScore,
      findings: displayFindings,
      discovered_endpoints: discoveredEndpoints,
      stages,
      events: activityEvents,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `authscope-report-${assessmentId || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const parsedTarget = validateWebsiteUrlSyntax(
    normalizeUserWebsiteInput(summaryData?.target_url || targetUrl || "http://localhost:3000")
  );

  const cvssForSeverity = (sev: string, idx: number): string => {
    const s = sev.toUpperCase();
    if (s === "CRITICAL") return "9.8";
    if (s === "HIGH") return idx === 1 ? "8.2" : "7.8";
    if (s === "MEDIUM") return "5.4";
    return "3.7";
  };

  const formatRequestProof = (f: FindingItem): string => {
    const ev = f.evidence;
    const method = ev?.request_method || f.http_method || "GET";
    const path = f.target_endpoint || f.endpoint || ev?.endpoint || "/";
    if (path === "/rest/user/login" && method === "POST") {
      return `POST /rest/user/login\nContent-Type: application/json\n\n{"email":"' OR 1=1--","password":"[hidden]"}`;
    }
    const headersLines = ev?.request_headers
      ? Object.entries(ev.request_headers)
          .slice(0, 3)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n")
      : "";
    return [`${method} ${path}`, headersLines].filter(Boolean).join("\n");
  };

  const formatResponseProof = (f: FindingItem): string => {
    const ev = f.evidence;
    const statusNum = ev?.response_status || 200;
    const statusLabel =
      statusNum === 200
        ? "200 OK"
        : statusNum === 302
        ? "302 Found"
        : statusNum === 401
        ? "401 Unauthorized"
        : statusNum === 403
        ? "403 Forbidden"
        : `${statusNum}`;
    const body =
      ev?.sanitized_response_body ||
      f.actual_behavior ||
      `{"status":"success"}`;
    return `HTTP/1.1 ${statusLabel}\n\n${body}`;
  };

  const extractFixBullets = (f: FindingItem, enriched?: BugAIEnrichment): string[] => {
    if (enriched?.how_to_resolve?.length) {
      return enriched.how_to_resolve;
    }
    if (f.beginner_explanation?.how_to_fix?.length) {
      return f.beginner_explanation.how_to_fix;
    }
    const raw = f.remediation_recommendation || f.recommended_fix || "";
    const split = raw
      .split(/\r?\n|(?<=\.)\s+/)
      .map((s) => s.replace(/^[-*•\d.)\s]+/, "").trim())
      .filter(Boolean);
    return split.length > 0
      ? split.slice(0, 3)
      : [
          "Enforce server-side authorization and ownership checks on this route.",
          "Reject unauthenticated or cross-account requests with HTTP 403.",
        ];
  };

  const resolveFullUrlFound = (f: FindingItem): string => {
    if (f.website_location?.full_url) return f.website_location.full_url;
    if (f.full_url) return f.full_url;
    if (f.evidence?.request_url) return f.evidence.request_url;
    const base = (summaryData?.target_url || targetUrl || "http://localhost:3000").replace(/\/$/, "");
    const path = f.target_endpoint || f.endpoint || "/";
    return `${base}${path.startsWith("/") ? "" : "/"}${path}`;
  };

  /**
   * Gemini API #1: Interactive Question & Answer about a specific bug.
   */
  const askGeminiQuestionAboutBug = async (finding: FindingItem, customQuestion?: string) => {
    const fid = finding.id;
    const questionText = (customQuestion ?? bugQuestions[fid] ?? "").trim();
    if (!questionText || bugChatLoading[fid]) return;

    const currentHistory = bugChatHistory[fid] || [];
    setBugChatLoading((prev) => ({ ...prev, [fid]: true }));
    setBugChatError((prev) => ({ ...prev, [fid]: "" }));

    try {
      const fullUrl = resolveFullUrlFound(finding);
      const res = await fetch(`${API_BASE_URL}/api/ai/finding-qa`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: finding.beginner_explanation?.simple_title || finding.title,
          category:
            finding.beginner_explanation?.technical_name ||
            finding.vulnerability_category ||
            finding.vulnerability_type,
          severity: String(finding.severity || "MEDIUM"),
          endpoint: fullUrl,
          http_method: finding.http_method || finding.evidence?.request_method || "GET",
          description:
            finding.beginner_explanation?.what_is_the_problem ||
            finding.description ||
            finding.actual_behavior,
          what_could_happen:
            finding.beginner_explanation?.what_attacker_can_do ||
            finding.impact_explanation ||
            "",
          request_proof: formatRequestProof(finding),
          response_proof: formatResponseProof(finding),
          how_to_fix: extractFixBullets(finding, bugAiEnrichment[fid]),
          question: questionText,
          history: currentHistory.slice(-6).map((m) => ({
            role: m.role,
            content: m.content,
          })),
        }),
      });

      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.detail || "Gemini Q&A could not answer right now.");
      }

      setBugChatHistory((prev) => ({
        ...prev,
        [fid]: [
          ...currentHistory,
          { role: "user", content: questionText },
          {
            role: "assistant",
            content: String(payload.answer || ""),
            model: payload.model,
          },
        ],
      }));
      if (!customQuestion) {
        setBugQuestions((prev) => ({ ...prev, [fid]: "" }));
      }
    } catch (err: unknown) {
      setBugChatError((prev) => ({
        ...prev,
        [fid]: err instanceof Error ? err.message : "Could not reach Gemini Q&A.",
      }));
    } finally {
      setBugChatLoading((prev) => ({ ...prev, [fid]: false }));
    }
  };

  /**
   * Gemini API #2: Generates what the bug can do, how to resolve it, and secure remediation code.
   */
  const generateBugImpactAndFixWithGemini2 = async (finding: FindingItem) => {
    const fid = finding.id;
    if (bugAiLoading[fid]) return;

    setBugAiLoading((prev) => ({ ...prev, [fid]: true }));
    try {
      const fullUrl = resolveFullUrlFound(finding);
      const res = await fetch(`${API_BASE_URL}/api/ai/explain-bug`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: finding.beginner_explanation?.simple_title || finding.title,
          category:
            finding.beginner_explanation?.technical_name ||
            finding.vulnerability_category ||
            finding.vulnerability_type,
          severity: String(finding.severity || "MEDIUM"),
          endpoint: fullUrl,
          http_method: finding.http_method || finding.evidence?.request_method || "GET",
          description:
            finding.beginner_explanation?.what_is_the_problem ||
            finding.description ||
            finding.actual_behavior,
          request_proof: formatRequestProof(finding),
          response_proof: formatResponseProof(finding),
          code_snippet: finding.vulnerable_snippet || finding.vulnerable_code || "",
          language: "Node.js / Express / TypeScript",
        }),
      });

      const payload = await res.json();
      if (res.ok) {
        setBugAiEnrichment((prev) => ({
          ...prev,
          [fid]: {
            what_bug_can_do: payload.what_bug_can_do,
            root_cause: payload.root_cause,
            how_to_resolve: payload.how_to_resolve || [],
            secure_code_fix: payload.secure_code_fix || "",
            verification_steps: payload.verification_steps || [],
            model: payload.model,
          },
        }));
      }
    } catch {
      // ignore
    } finally {
      setBugAiLoading((prev) => ({ ...prev, [fid]: false }));
    }
  };

  const copySecureCode = async (fid: string, code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCodeId(fid);
      window.setTimeout(() => setCopiedCodeId(null), 1600);
    } catch {
      // ignore
    }
  };

  return (
    <div className={`workspace ${lightMode ? "workspace-light" : ""}`}>
      {/* =================================================================== */}
      {/* LEFT THIN SIDEBAR (Clean, Deduplicated, Max 5 Past Scans)           */}
      {/* =================================================================== */}
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="brand">
          <span className="brand-mark">A</span>
          <span>AuthScope</span>
        </div>

        <button
          type="button"
          onClick={resetAssessment}
          className="new-scan-btn"
        >
          <Plus size={14} />
          <span>New scan</span>
        </button>

        <div className="past-scans-heading">PAST SCANS</div>
        <div className="past-scans-list">
          {pastScans.map((scan) => {
            const isActive = activePastScanId === scan.id;
            return (
              <button
                key={scan.id}
                type="button"
                onClick={() => void selectPastScan(scan)}
                className={`past-scan-item ${isActive ? "active" : ""}`}
              >
                <span className="truncate">{scan.label}</span>
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={() => setLightMode((prev) => !prev)}
          className="theme-toggle-btn"
        >
          {lightMode ? <Moon size={14} /> : <Sun size={14} />}
          <span>{lightMode ? "Dark mode" : "Light mode"}</span>
        </button>
      </aside>

      {/* =================================================================== */}
      {/* MAIN WORKSPACE CANVAS                                               */}
      {/* =================================================================== */}
      <main className="main-canvas">
        {/* ================================================================= */}
        {/* SCREEN 1: START SCREEN (Image 1)                                  */}
        {/* ================================================================= */}
        {status === "ready" && (
          <div className="start-screen">
            <div className="start-hero">
              <h1 className="start-title">Break it before they do.</h1>
              <p className="start-subtitle">
                AI that tests your app like an attacker would.
              </p>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void startAssessment();
                }}
                className="start-form"
              >
                <div className="github-pill-row">
                  <button
                    type="button"
                    onClick={() => setShowGitHubModal(true)}
                    className="link-github-btn"
                  >
                    <GitBranch size={13} />
                    <span>Link GitHub project</span>
                  </button>

                  {targetUrl.trim() && (
                    <button
                      type="button"
                      onClick={() => {
                        setShowAuthModal(true);
                        setAuthActionMessage(null);
                      }}
                      className="text-xs text-[#aaa8a1] hover:text-[#f4f2ec] underline underline-offset-2"
                    >
                      {isCheckingAuth
                        ? "Checking scope..."
                        : targetAuth?.is_authorized
                        ? "Authorized target"
                        : "Authorize target"}
                    </button>
                  )}
                </div>

                <div className="address-box">
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => {
                      setTargetUrl(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder="Paste a website address"
                    aria-label="Website address"
                  />
                  <button
                    type="submit"
                    disabled={!targetUrl.trim()}
                    aria-label="Start scan"
                    className="address-submit-btn"
                  >
                    <ArrowUp size={16} />
                  </button>
                </div>

                <p className="address-hint">
                  Enter a full address or a website name.
                </p>

                {error && (
                  <div
                    role="alert"
                    className="mt-4 p-3.5 rounded-lg border border-[#713e3e] bg-[#362020] text-[#f4d2d2] text-xs flex items-center justify-between gap-3"
                  >
                    <div className="leading-relaxed">{error}</div>
                    <div className="flex items-center gap-2 shrink-0">
                      {(error.toLowerCase().includes("authorized") ||
                        error.toLowerCase().includes("scope")) && (
                        <button
                          type="button"
                          onClick={() => {
                            setShowAuthModal(true);
                            setAuthActionMessage(null);
                          }}
                          className="px-2.5 py-1.5 rounded-md border border-[#965454] bg-[#4a2828] hover:bg-[#5c3232] text-white font-medium text-xs"
                        >
                          Authorize target
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => void startAssessment()}
                        className="px-2.5 py-1.5 rounded-md border border-[#5a5a55] bg-[#2d2d2a] hover:bg-[#373733] text-[#f4f2ec] text-xs"
                      >
                        Try again
                      </button>
                    </div>
                  </div>
                )}
              </form>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* SCREEN 2 & 4: ACTIVE SCANNING VIEW (Step-by-Step One-by-One)      */}
        {/* ================================================================= */}
        {status !== "ready" && isRunningState && (
          <div className="scan-workspace">
            <div className="target-url-pill-row">
              <div className="target-url-pill">
                {summaryData?.target_url || targetUrl || "http://localhost:3000"}
              </div>
            </div>

            <div className="scan-status-meta">
              <span className="scan-status-dot" />
              <span>
                Scanning · {currentStageLabel} · {formatTimer(elapsedSeconds)}
              </span>
            </div>

            <h1 className="scan-live-headline">{currentLiveHeadline}</h1>

            <div className="work-log-header">
              <button
                type="button"
                onClick={() => setHideWork((prev) => !prev)}
                className="hide-work-btn"
              >
                <span>{hideWork ? "Show work" : "Hide work"}</span>
                {hideWork ? <ChevronDown size={13} /> : <ChevronUp size={13} />}
              </button>
            </div>

            {!hideWork && (
              <div className="work-steps-list">
                {workSteps.map((step) => (
                  <div
                    key={step.id}
                    className={`work-step-row ${!step.done ? "is-current" : ""}`}
                  >
                    <div className="work-step-icon">
                      {step.done ? (
                        <Check size={13} />
                      ) : (
                        <span className="work-step-active-circle" />
                      )}
                    </div>
                    <div className="work-step-main">
                      <div className="work-step-line1">
                        <span className="work-step-tag">{step.kind}</span>
                        <span>{step.title}</span>
                      </div>
                      <div className="work-step-sub">{step.subtitle}</div>
                    </div>
                    <div className="work-step-duration">{step.duration}</div>
                  </div>
                ))}
              </div>
            )}

            <button
              type="button"
              onClick={() => void stopAssessment()}
              className="stop-scan-btn"
            >
              <Square size={11} />
              <span>Stop scan</span>
            </button>
          </div>
        )}

        {/* ================================================================= */}
        {/* SCREEN 3 & 5: COMPLETED REPORT VIEW                               */}
        {/* ================================================================= */}
        {status !== "ready" && !isRunningState && (
          <div className="scan-workspace" data-testid="final-assessment-summary">
            <div className="target-url-pill-row">
              <div className="target-url-pill">
                {summaryData?.target_url || targetUrl || "http://localhost:3000"}
              </div>
            </div>

            <div className="report-check-mark">
              <Check size={16} />
            </div>

            <h1 className="report-headline">
              {status === "failed"
                ? "Could not finish scanning this site."
                : `Found ${displayFindings.length} problem${
                    displayFindings.length === 1 ? "" : "s"
                  } in ${durationSeconds} seconds.`}
            </h1>

            <p className="report-lead">
              {status === "failed"
                ? error ||
                  summaryData?.failure_reason ||
                  "The site could not be reached or stopped responding during the test."
                : displayFindings.length > 0
                ? `Start with the ${
                    displayFindings[0].target_endpoint?.includes("login")
                      ? "sign-in problem"
                      : "first critical problem"
                  }. ${
                    displayFindings[0].beginner_explanation?.what_attacker_can_do ||
                    displayFindings[0].impact_explanation ||
                    "It could let someone access protected accounts or data."
                  }`
                : "No confirmed authorization or security problems were triggered during this scan."}
            </p>

            {status === "failed" && (
              <div className="mt-5">
                <button
                  type="button"
                  onClick={() => void startAssessment(summaryData?.target_url || targetUrl)}
                  className="scan-another-btn"
                >
                  <RefreshCw size={13} />
                  <span>Try again</span>
                </button>
              </div>
            )}

            {status !== "failed" && (
              <>
                <div className="risk-score-strip">
                  <div className="risk-score-block">
                    <span className="risk-score-number">{riskScore}</span>
                    <span className="risk-score-label">
                      Risk score
                      <br />
                      out of 100
                    </span>
                  </div>

                  <div className="severity-counts-row">
                    <div className="severity-count-item">
                      <span className="severity-dot critical" />
                      <span className="severity-name critical">Critical</span>
                      <strong>{severityCounts.CRITICAL}</strong>
                    </div>
                    <div className="severity-count-item">
                      <span className="severity-dot high" />
                      <span className="severity-name high">High</span>
                      <strong>{severityCounts.HIGH}</strong>
                    </div>
                    <div className="severity-count-item">
                      <span className="severity-dot medium" />
                      <span className="severity-name medium">Medium</span>
                      <strong>{severityCounts.MEDIUM}</strong>
                    </div>
                    <div className="severity-count-item">
                      <span className="severity-dot low" />
                      <span className="severity-name low">Low</span>
                      <strong>{severityCounts.LOW}</strong>
                    </div>
                  </div>
                </div>

                {/* Filter Pills */}
                <div className="filter-pills-row">
                  {[
                    { key: "ALL", label: "All", count: displayFindings.length },
                    { key: "CRITICAL", label: "Critical", count: severityCounts.CRITICAL },
                    { key: "HIGH", label: "High", count: severityCounts.HIGH },
                    { key: "MEDIUM", label: "Medium", count: severityCounts.MEDIUM },
                    { key: "LOW", label: "Low", count: severityCounts.LOW },
                  ].map((pill) => (
                    <button
                      key={pill.key}
                      type="button"
                      onClick={() => setSeverityFilter(pill.key)}
                      className={`filter-pill ${
                        severityFilter === pill.key ? "active" : ""
                      }`}
                    >
                      <span>{pill.label}</span>
                      <span>{pill.count}</span>
                    </button>
                  ))}
                </div>

                {/* Numbered Problem List */}
                <div>
                  {filteredFindings.map((finding, idx) => {
                    const fid = finding.id || `finding-${idx}`;
                    const sevKey = String(finding.severity || "LOW").toLowerCase();
                    const sevClass =
                      sevKey === "critical" ||
                      sevKey === "high" ||
                      sevKey === "medium"
                        ? sevKey
                        : "low";
                    const sevTitle =
                      sevClass.charAt(0).toUpperCase() + sevClass.slice(1);
                    const plainTitle =
                      finding.beginner_explanation?.simple_title ||
                      finding.title ||
                      "Security problem detected";
                    const categoryLabel =
                      finding.beginner_explanation?.technical_name ||
                      finding.vulnerability_name ||
                      finding.vulnerability_category ||
                      "Authorization issue";
                    const plainProblem =
                      finding.beginner_explanation?.what_is_the_problem ||
                      finding.description ||
                      finding.actual_behavior;
                    const routePath =
                      finding.target_endpoint ||
                      finding.endpoint ||
                      finding.affected_endpoint ||
                      "/";
                    const fullUrlFound = resolveFullUrlFound(finding);
                    const httpMethod =
                      finding.http_method ||
                      finding.evidence?.request_method ||
                      "GET";

                    const enriched = bugAiEnrichment[fid];
                    const whatBugCanDo =
                      enriched?.what_bug_can_do ||
                      finding.beginner_explanation?.what_attacker_can_do ||
                      finding.impact_explanation ||
                      finding.description;
                    const fixBullets = extractFixBullets(finding, enriched);
                    const secureCodeFix =
                      enriched?.secure_code_fix ||
                      finding.beginner_explanation?.secure_code_example ||
                      finding.proposed_code_fix ||
                      "";
                    const chatMessages = bugChatHistory[fid] || [];

                    return (
                      <section
                        key={fid}
                        id={`problem-${fid}`}
                        className="problem-section"
                      >
                        <div className="problem-header">
                          <div className="problem-title-group">
                            <span className="problem-index-badge">{idx + 1}</span>
                            <h2 className="problem-title">{plainTitle}</h2>
                          </div>
                          <div className="problem-severity-score">
                            <span className={`severity-dot ${sevClass}`} />
                            <span className={`severity-name ${sevClass}`}>
                              {sevTitle}
                            </span>
                            <span className="text-[#aaa8a1] font-mono">
                              {cvssForSeverity(sevClass, idx)}
                            </span>
                          </div>
                        </div>

                        <div className="problem-body">
                          <p className="problem-category-line">
                            <strong>{categoryLabel}:</strong> {plainProblem}
                          </p>

                          {/* Which URL it found */}
                          <div className="found-url-row">
                            <span className="found-method-badge">
                              {httpMethod}
                            </span>
                            <span className="found-url-text">
                              {fullUrlFound}
                            </span>
                            <span className="text-[#85837c] text-[11px]">
                              (route: {routePath})
                            </span>
                          </div>

                          {/* Proof */}
                          <h3 className="proof-heading">Proof</h3>
                          <p className="proof-sub">
                            Private values have been hidden.
                          </p>

                          <div className="proof-box">
                            <div className="proof-col">
                              <div className="proof-col-header">REQUEST SENT</div>
                              <pre className="proof-col-pre">
                                {formatRequestProof(finding)}
                              </pre>
                            </div>
                            <div className="proof-col">
                              <div className="proof-col-header">
                                RESPONSE RECEIVED
                              </div>
                              <pre className="proof-col-pre">
                                {formatResponseProof(finding)}
                              </pre>
                            </div>
                          </div>

                          {/* What this bug can do & How to resolve it (Gemini API #2) */}
                          <div className="impact-fix-callout">
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                              <h4 className="callout-heading" style={{ margin: 0 }}>
                                What could happen (What this bug can do)
                              </h4>
                              <button
                                type="button"
                                disabled={bugAiLoading[fid]}
                                onClick={() =>
                                  void generateBugImpactAndFixWithGemini2(finding)
                                }
                                className="inline-flex items-center gap-1.5 rounded-md border border-[#41413d] bg-[#2d2d2a] hover:bg-[#373733] px-2.5 py-1 text-[11px] text-[#5fa37f] disabled:opacity-50"
                              >
                                {bugAiLoading[fid] ? (
                                  <Loader2 size={12} className="animate-spin" />
                                ) : (
                                  <Sparkles size={12} />
                                )}
                                <span>
                                  {bugAiLoading[fid]
                                    ? "Analyzing with Gemini API #2..."
                                    : enriched
                                    ? "Refresh AI Fix & Code (Gemini API #2)"
                                    : "Generate AI Fix & Code (Gemini API #2)"}
                                </span>
                              </button>
                            </div>

                            <p className="callout-text">{whatBugCanDo}</p>

                            <h4 className="callout-heading">How to fix it (How to resolve)</h4>
                            <ul className="fix-checklist">
                              {fixBullets.map((step, sIdx) => (
                                <li key={sIdx}>
                                  <Check size={13} className="fix-check-icon" />
                                  <span>{step}</span>
                                </li>
                              ))}
                            </ul>

                            {/* Secure Code Fix Block (Gemini API #2) */}
                            {secureCodeFix && (
                              <div className="secure-code-container">
                                <div className="secure-code-header">
                                  <span>
                                    SECURE CODE FIX{" "}
                                    {enriched?.model
                                      ? `· Generated by Gemini API #2 (${enriched.model})`
                                      : ""}
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      void copySecureCode(fid, secureCodeFix)
                                    }
                                    className="inline-flex items-center gap-1 text-[#d0cec8] hover:text-white"
                                  >
                                    {copiedCodeId === fid ? (
                                      <Check size={12} />
                                    ) : (
                                      <Copy size={12} />
                                    )}
                                    <span>
                                      {copiedCodeId === fid ? "Copied" : "Copy code"}
                                    </span>
                                  </button>
                                </div>
                                <pre className="secure-code-pre">
                                  {secureCodeFix}
                                </pre>
                              </div>
                            )}

                            {assessmentId && !assessmentId.startsWith("preset-") && (
                              <div className="mt-3 flex items-center gap-3">
                                <button
                                  type="button"
                                  disabled={verifyingFindingId === finding.id}
                                  onClick={() => void verifyFix(finding.id)}
                                  className="text-xs text-[#5fa37f] hover:underline disabled:opacity-50"
                                >
                                  {verifyingFindingId === finding.id
                                    ? "Re-testing fix..."
                                    : finding.retest_status
                                    ? `Fix verification: ${finding.retest_status}`
                                    : "Verify fix against live target"}
                                </button>
                                {verificationErrors[finding.id] && (
                                  <span className="text-xs text-[#d2675f]">
                                    {verificationErrors[finding.id]}
                                  </span>
                                )}
                              </div>
                            )}
                          </div>

                          {/* Interactive Question & Answer Text Field (Gemini API #1) */}
                          <div className="bug-qa-section">
                            <div className="bug-qa-header">
                              <span>
                                Ask a question about this bug (Gemini API #1 · Text &amp; Q&amp;A)
                              </span>
                            </div>

                            <div className="bug-qa-chips">
                              {[
                                "What can an attacker do with this bug?",
                                "How do I fix this step by step?",
                                "How can I test that this bug is resolved?",
                              ].map((chip) => (
                                <button
                                  key={chip}
                                  type="button"
                                  disabled={bugChatLoading[fid]}
                                  onClick={() =>
                                    void askGeminiQuestionAboutBug(finding, chip)
                                  }
                                  className="bug-qa-chip"
                                >
                                  {chip}
                                </button>
                              ))}
                            </div>

                            {chatMessages.length > 0 && (
                              <div className="bug-qa-messages">
                                {chatMessages.map((msg, mIdx) => (
                                  <div
                                    key={mIdx}
                                    className={`bug-qa-bubble ${msg.role}`}
                                  >
                                    {msg.content}
                                  </div>
                                ))}
                              </div>
                            )}

                            {bugChatError[fid] && (
                              <p className="text-xs text-[#d2675f] mb-2">
                                {bugChatError[fid]}
                              </p>
                            )}

                            <div className="bug-qa-input-box">
                              <input
                                type="text"
                                value={bugQuestions[fid] || ""}
                                onChange={(e) =>
                                  setBugQuestions((prev) => ({
                                    ...prev,
                                    [fid]: e.target.value,
                                  }))
                                }
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") {
                                    e.preventDefault();
                                    void askGeminiQuestionAboutBug(finding);
                                  }
                                }}
                                placeholder={`Ask a question about ${routePath}...`}
                                aria-label={`Ask a question about ${plainTitle}`}
                              />
                              <button
                                type="button"
                                disabled={
                                  bugChatLoading[fid] ||
                                  !(bugQuestions[fid] || "").trim()
                                }
                                onClick={() =>
                                  void askGeminiQuestionAboutBug(finding)
                                }
                                className="bug-qa-send-btn"
                                aria-label="Send question"
                              >
                                {bugChatLoading[fid] ? (
                                  <Loader2 size={14} className="animate-spin" />
                                ) : (
                                  <ArrowUp size={15} />
                                )}
                              </button>
                            </div>
                          </div>
                        </div>
                      </section>
                    );
                  })}
                </div>

                {/* How these problems can join together (Image 5) */}
                {displayFindings.length > 1 && (
                  <section className="join-together-section">
                    <h2 className="join-together-title">
                      How these problems can join together
                    </h2>
                    <p className="join-together-sub">
                      Choose a step to jump to the matching problem.
                    </p>

                    <div className="join-chain-row">
                      {displayFindings.slice(0, 3).map((f, idx) => {
                        const fid = f.id || `finding-${idx}`;
                        const sev = String(f.severity || "LOW").toLowerCase();
                        const sevClass =
                          sev === "critical" || sev === "high" || sev === "medium"
                            ? sev
                            : "low";
                        const rawRoute =
                          f.target_endpoint || f.endpoint || "/endpoint";
                        const shortRoute = rawRoute.split("?")[0];
                        return (
                          <React.Fragment key={fid}>
                            <button
                              type="button"
                              onClick={() => {
                                const el = document.getElementById(
                                  `problem-${fid}`
                                );
                                el?.scrollIntoView({ behavior: "smooth" });
                              }}
                              className="join-step-card"
                            >
                              <div className="join-step-top">
                                <span className={`severity-dot ${sevClass}`} />
                                <span>{sevClass.toUpperCase()}</span>
                              </div>
                              <div className="join-step-route">{shortRoute}</div>
                            </button>
                            <span className="join-arrow">→</span>
                          </React.Fragment>
                        );
                      })}

                      <div className="join-step-card">
                        <div className="join-step-top">
                          <span className="severity-dot critical" />
                          <span>POSSIBLE RESULT</span>
                        </div>
                        <div
                          className="join-step-route"
                          style={{ fontFamily: "inherit" }}
                        >
                          Full account takeover
                        </div>
                      </div>
                    </div>
                  </section>
                )}

                {/* How the AI found these (Image 5) */}
                <div className="ai-how-found-row">
                  <button
                    type="button"
                    onClick={() => setShowHowAiFound((prev) => !prev)}
                    className="ai-how-found-trigger"
                  >
                    <span>How the AI found these</span>
                    {showHowAiFound ? (
                      <ChevronDown size={16} className="text-[#aaa8a1]" />
                    ) : (
                      <ChevronRight size={16} className="text-[#aaa8a1]" />
                    )}
                  </button>

                  {showHowAiFound && (
                    <div className="pb-4">
                      <div className="work-steps-list">
                        {workSteps.map((step) => (
                          <div key={step.id} className="work-step-row">
                            <div className="work-step-icon">
                              <Check size={13} />
                            </div>
                            <div className="work-step-main">
                              <div className="work-step-line1">
                                <span className="work-step-tag">{step.kind}</span>
                                <span>{step.title}</span>
                              </div>
                              <div className="work-step-sub">{step.subtitle}</div>
                            </div>
                            <div className="work-step-duration">
                              {step.duration}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Bottom Report Action Buttons (Image 5) */}
                <div className="report-bottom-actions">
                  <button
                    type="button"
                    onClick={downloadReportJson}
                    className="download-report-btn"
                  >
                    <Download size={14} />
                    <span>Download report</span>
                  </button>
                  <button
                    type="button"
                    onClick={resetAssessment}
                    className="scan-another-btn"
                  >
                    <span>Scan another site</span>
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* Bottom-right floating ? button */}
        <button
          type="button"
          onClick={() => {
            setShowAuthModal(true);
            setAuthActionMessage(null);
          }}
          title="Target scope & authorization settings"
          aria-label="Help and scope authorization"
          className="floating-help-btn"
        >
          ?
        </button>
      </main>

      {/* =================================================================== */}
      {/* GITHUB PROJECT LINKING & AI SOURCE SCAN MODAL                       */}
      {/* =================================================================== */}
      {showGitHubModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
          <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl bg-[#262624] border border-[#41413d] shadow-2xl p-6 text-left">
            <div className="flex items-center justify-between pb-3 border-b border-[#333330]">
              <div className="flex items-center gap-2.5">
                <GitBranch className="w-4 h-4 text-[#5fa37f]" />
                <h3 className="text-sm font-semibold text-[#f4f2ec]">
                  Link GitHub project &amp; AI Source Code Scan
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowGitHubModal(false)}
                className="p-1 rounded-md text-[#aaa8a1] hover:text-[#f4f2ec] hover:bg-[#373733]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-3">
              <label className="block text-xs text-[#aaa8a1] mb-1.5">
                Optional repository URL for runtime-to-source mapping
              </label>
              <input
                type="text"
                value={githubRepo}
                onChange={(e) => setGithubRepo(e.target.value)}
                placeholder="https://github.com/juice-shop/juice-shop"
                className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] placeholder-[#85837c] focus:outline-none focus:border-[#5fa37f] font-mono"
              />
            </div>

            <GitHubCodeScanPanel apiBaseUrl={API_BASE_URL} />
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TARGET AUTHORIZATION & SCOPE REVIEW MODAL                           */}
      {/* =================================================================== */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
          <div className="relative w-full max-w-xl max-h-[90vh] overflow-y-auto rounded-xl bg-[#262624] border border-[#41413d] shadow-2xl p-6 text-left">
            <div className="flex items-center justify-between pb-4 border-b border-[#333330]">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-[#5fa37f]">
                  <Shield className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-[#f4f2ec]">
                    Target Website Authorization Review
                  </h3>
                  <p className="text-xs text-[#aaa8a1]">
                    Server-Side Authorized Scope &amp; Boundary Approval
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowAuthModal(false)}
                className="p-1 rounded-lg text-[#aaa8a1] hover:text-[#f4f2ec] hover:bg-[#373733]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 p-3.5 rounded-lg bg-[#20201e] border border-[#41413d] space-y-2">
              <div className="text-xs font-semibold text-[#d0cec8]">
                Target Parameters (Exact Scope Boundaries)
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <div>
                  <div className="text-[10px] text-[#85837c]">EXACT HOST</div>
                  <div className="text-[#5fa37f] truncate">
                    {targetAuth?.hostname || parsedTarget.host || "localhost"}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-[#85837c]">SCHEME</div>
                  <div className="text-[#f4f2ec]">
                    {(parsedTarget.scheme || "http").toUpperCase()}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-[#85837c]">PORT</div>
                  <div className="text-[#f4f2ec]">
                    {parsedTarget.port || 3000}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <div className="p-3 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {targetAuth?.is_authorized ? (
                    <CheckCircle2 className="w-4 h-4 text-[#5fa37f] shrink-0" />
                  ) : targetAuth?.status === "PENDING" ? (
                    <AlertTriangle className="w-4 h-4 text-[#c5aa54] shrink-0" />
                  ) : (
                    <Lock className="w-4 h-4 text-[#aaa8a1] shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold text-[#f4f2ec]">
                      Status: {targetAuth?.status || "UNREGISTERED"}
                    </div>
                    <div className="text-[11px] text-[#aaa8a1]">
                      {targetAuth?.reason || "Target requires review and approval."}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <label className="block text-xs font-semibold text-[#d0cec8] mb-1">
                  Authorization Grounds / Basis
                </label>
                <select
                  value={authBasis}
                  onChange={(e) => setAuthBasis(e.target.value as AuthorizationBasis)}
                  className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] focus:outline-none focus:border-[#5fa37f]"
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
                <label className="block text-xs font-semibold text-[#d0cec8] mb-1">
                  Permission Evidence / Reference
                </label>
                <input
                  type="text"
                  value={permissionRef}
                  onChange={(e) => setPermissionRef(e.target.value)}
                  placeholder="Ticket #, SOW document ID, or Bug Bounty policy link"
                  className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] placeholder-[#85837c] focus:outline-none focus:border-[#5fa37f] font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs font-semibold text-[#d0cec8] mb-1">
                    Approver Identifier
                  </label>
                  <input
                    type="text"
                    value={adminApprover}
                    onChange={(e) => setAdminApprover(e.target.value)}
                    placeholder="security_admin"
                    className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] focus:outline-none focus:border-[#5fa37f] font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#d0cec8] mb-1">
                    Validity (Days)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={approvalDays}
                    onChange={(e) => setApprovalDays(Number(e.target.value) || 30)}
                    className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] focus:outline-none focus:border-[#5fa37f] font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-[#d0cec8] mb-1">
                  Operator Notes (Optional)
                </label>
                <input
                  type="text"
                  value={authNotes}
                  onChange={(e) => setAuthNotes(e.target.value)}
                  placeholder="Notes regarding scope constraints or testing window"
                  className="w-full px-3 py-2 rounded-lg bg-[#2d2d2a] border border-[#41413d] text-xs text-[#f4f2ec] placeholder-[#85837c] focus:outline-none focus:border-[#5fa37f] font-mono"
                />
              </div>

              {authBasis === "domain_ownership_challenge" && (
                <div className="p-3 rounded-lg bg-[#20201e] border border-[#41413d] text-xs text-[#d0cec8] space-y-1.5">
                  <div className="font-semibold flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-[#5fa37f]" />
                    Domain Challenge Verification
                  </div>
                  <div className="p-1.5 rounded bg-black/40 font-mono text-[11px] text-[#5fa37f] break-all select-all">
                    {targetAuth?.profile?.verification_token
                      ? targetAuth.profile.verification_token
                      : "Submit target first to generate verification challenge token"}
                  </div>
                  {targetAuth?.profile?.verification_token && (
                    <button
                      type="button"
                      disabled={isSubmittingAuth}
                      onClick={() => verifyDomainChallengeAction(targetAuth.profile!.id)}
                      className="mt-2 px-3 py-1.5 rounded-lg bg-[#5fa37f] text-[#102218] font-medium text-xs"
                    >
                      Verify Challenge Now
                    </button>
                  )}
                </div>
              )}

              {authActionMessage && (
                <div className="p-2.5 rounded-lg bg-[#2d2d2a] border border-[#5fa37f]/40 text-[#d0cec8] text-xs">
                  {authActionMessage}
                </div>
              )}

              <div className="pt-3 flex flex-wrap items-center justify-between gap-2 border-t border-[#333330]">
                <button
                  type="button"
                  disabled={isSubmittingAuth}
                  onClick={() => void submitTargetForAuth()}
                  className="px-3.5 py-2 rounded-lg bg-[#2d2d2a] hover:bg-[#373733] border border-[#41413d] text-[#f4f2ec] font-medium text-xs"
                >
                  {isSubmittingAuth ? "Submitting..." : "1. Submit for Approval"}
                </button>

                <div className="flex items-center gap-2">
                  {targetAuth?.profile &&
                    targetAuth.profile.approval_status !== "APPROVED" && (
                      <button
                        type="button"
                        disabled={isSubmittingAuth}
                        onClick={() => void approveTargetAction(targetAuth.profile!.id)}
                        className="px-3.5 py-2 rounded-lg bg-[#5fa37f] text-[#102218] font-medium text-xs flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        2. Admin Approve
                      </button>
                    )}

                  {targetAuth?.profile &&
                    targetAuth.profile.approval_status === "APPROVED" && (
                      <button
                        type="button"
                        disabled={isSubmittingAuth}
                        onClick={() => void revokeTargetAction(targetAuth.profile!.id)}
                        className="px-3 py-2 rounded-lg bg-[#402424] border border-[#713e3e] text-[#f0b9b9] font-medium text-xs"
                      >
                        Revoke
                      </button>
                    )}

                  <button
                    type="button"
                    onClick={() => {
                      setShowAuthModal(false);
                      if (targetAuth?.is_authorized && status === "ready") {
                        void startAssessment();
                      }
                    }}
                    className="px-4 py-2 rounded-lg bg-[#5fa37f] text-[#102218] font-medium text-xs"
                  >
                    {targetAuth?.is_authorized ? "Start Scan" : "Done"}
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
