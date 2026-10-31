"use client";

import React, { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Code,
  FileText,
  FileCode,
  HelpCircle,
  MinusCircle,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import { FindingItem, FindingStatus } from "@/types/assessment";

interface FindingCardProps {
  finding: FindingItem;
  index: number;
}

/**
 * Normalizes raw finding status / validation_status into one of the 5 canonical
 * statuses required by AuthScope:
 * CONFIRMED | SUSPICIOUS | NOT_CONFIRMED | INCONCLUSIVE | NOT_TESTED
 */
export function resolveFindingStatus(finding: FindingItem): FindingStatus {
  const raw = String(
    finding.finding_status || finding.validation_status || finding.confidence || ""
  )
    .trim()
    .toUpperCase();

  if (raw === "CONFIRMED" || raw === "CONFIRMED_RUNTIME_VULNERABILITY" || raw === "VALIDATED") {
    return "CONFIRMED";
  }
  if (raw === "INCONCLUSIVE") {
    return "INCONCLUSIVE";
  }
  if (raw === "NOT_TESTED" || raw === "SKIPPED" || raw === "UNTESTED") {
    return "NOT_TESTED";
  }
  if (
    raw === "NOT_CONFIRMED" ||
    raw === "UNVALIDATED" ||
    raw === "FALSE_POSITIVE" ||
    raw === "REJECTED_FALSE_POSITIVE" ||
    raw === "NOT_REPRODUCIBLE"
  ) {
    return "NOT_CONFIRMED";
  }
  return "SUSPICIOUS";
}

export function FindingCard({ finding, index }: FindingCardProps) {
  // 4 Expandable section states
  const [showVulnerableCode, setShowVulnerableCode] = useState(false);
  const [showSuggestedFix, setShowSuggestedFix] = useState(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);

  // Copy feedback state
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(label);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  // Severity indicator color mapping
  const severityUpper = (finding.severity || "MEDIUM").toUpperCase();
  const severityColors: Record<string, { bg: string; text: string; border: string }> = {
    CRITICAL: { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/40" },
    HIGH: { bg: "bg-orange-500/15", text: "text-orange-400", border: "border-orange-500/40" },
    MEDIUM: { bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/40" },
    LOW: { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/40" },
    INFO: { bg: "bg-gray-500/15", text: "text-gray-400", border: "border-gray-500/40" },
  };
  const sevStyle = severityColors[severityUpper] || severityColors.MEDIUM;

  const canonicalStatus = resolveFindingStatus(finding);

  const statusStyles: Record<
    FindingStatus,
    { bg: string; text: string; border: string; icon: React.ReactNode }
  > = {
    CONFIRMED: {
      bg: "bg-emerald-950/40",
      text: "text-emerald-300",
      border: "border-emerald-600/40",
      icon: <CheckCircle2 className="w-3 h-3 text-emerald-400" />,
    },
    SUSPICIOUS: {
      bg: "bg-amber-950/40",
      text: "text-amber-300",
      border: "border-amber-600/40",
      icon: <AlertTriangle className="w-3 h-3 text-amber-400" />,
    },
    NOT_CONFIRMED: {
      bg: "bg-orange-950/40",
      text: "text-orange-300",
      border: "border-orange-600/40",
      icon: <AlertTriangle className="w-3 h-3 text-orange-400" />,
    },
    INCONCLUSIVE: {
      bg: "bg-purple-950/40",
      text: "text-purple-300",
      border: "border-purple-600/40",
      icon: <HelpCircle className="w-3 h-3 text-purple-400" />,
    },
    NOT_TESTED: {
      bg: "bg-gray-900/60",
      text: "text-gray-400",
      border: "border-gray-700/50",
      icon: <MinusCircle className="w-3 h-3 text-gray-400" />,
    },
  };
  const statusStyle = statusStyles[canonicalStatus];

  // Only treat source code as available when provided by the source-analysis engine
  const hasSourceCode =
    !finding.black_box_only &&
    Boolean(finding.source_file || finding.vulnerable_code);

  const actualEvidenceSummary =
    finding.evidence_summary ||
    finding.actual_behavior ||
    (finding.evidence
      ? `HTTP ${finding.evidence.response_status || 200} response captured for ${
          finding.evidence.testing_role || finding.evidence.test_role || "test role"
        }${
          finding.evidence.evidence_sha256
            ? ` (SHA-256: ${finding.evidence.evidence_sha256.slice(0, 12)}...)`
            : ""
        }`
      : "Empirical runtime HTTP comparison recorded.");

  const impactText =
    finding.impact ||
    finding.explanation ||
    "Unauthorized access to protected application resources or functionality.";

  return (
    <div className="w-full my-4 rounded-2xl border border-[#263248] bg-[#0E1420] overflow-hidden shadow-xl shadow-black/30 transition-all hover:border-[#384a68]">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 bg-[#141C2C] border-b border-[#263248]">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 rounded-xl bg-red-500/15 border border-red-500/30 text-red-400 flex items-center justify-center shrink-0 mt-0.5">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono text-gray-400">
                Finding #{index + 1}
              </span>
              <span className="text-gray-600">·</span>
              <span className="text-xs font-mono text-gray-400">
                {finding.vulnerability_category}
              </span>
            </div>
            <h3 className="text-base sm:text-lg font-semibold text-white tracking-tight mt-0.5">
              {finding.title}
            </h3>
          </div>
        </div>

        {/* Severity, Confidence & Canonical Status Badges */}
        <div className="flex items-center gap-2 shrink-0 flex-wrap">
          <span
            className={`px-2.5 py-1 rounded-lg text-xs font-bold font-mono border ${sevStyle.bg} ${sevStyle.text} ${sevStyle.border}`}
          >
            {severityUpper}
          </span>

          <span className="px-2.5 py-1 rounded-lg text-xs font-mono font-medium bg-[#1A2338] text-gray-300 border border-[#2E3C58]">
            Conf: {finding.confidence}
          </span>

          <span
            className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium flex items-center gap-1 border ${statusStyle.bg} ${statusStyle.text} ${statusStyle.border}`}
          >
            {statusStyle.icon}
            {canonicalStatus}
          </span>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Simple English Explanation */}
        <div>
          <div className="text-xs font-medium uppercase tracking-wider text-gray-400 mb-1">
            Explanation
          </div>
          <p className="text-sm text-gray-200 leading-relaxed">
            {finding.explanation}
          </p>
        </div>

        {/* Impact & Actual Evidence Summary */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="p-3 rounded-xl bg-[#0B101B] border border-[#1E293B]">
            <div className="text-[11px] font-mono uppercase tracking-wider text-gray-400 mb-1">
              Actual Evidence Summary
            </div>
            <p className="text-xs text-gray-300 leading-relaxed font-mono">
              {actualEvidenceSummary}
            </p>
          </div>

          <div className="p-3 rounded-xl bg-[#0B101B] border border-[#1E293B]">
            <div className="text-[11px] font-mono uppercase tracking-wider text-gray-400 mb-1">
              Security Impact
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              {impactText}
            </p>
          </div>
        </div>

        {/* Key Attributes Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 p-3 rounded-xl bg-[#090D15] border border-[#1E293B] text-xs font-mono">
          <div>
            <span className="text-gray-500 block">Affected Endpoint:</span>
            <span className="text-blue-300 font-semibold break-all">
              {finding.http_method} {finding.affected_endpoint}
            </span>
          </div>

          <div>
            <span className="text-gray-500 block">Source File:</span>
            <span className="text-gray-300 break-all">
              {hasSourceCode && finding.source_file
                ? finding.source_file
                : "Black-box only (unavailable)"}
            </span>
          </div>

          <div>
            <span className="text-gray-500 block">Function Name:</span>
            <span className="text-gray-300">
              {hasSourceCode && finding.function_name
                ? finding.function_name
                : "N/A (Black-box runtime)"}
            </span>
          </div>

          <div>
            <span className="text-gray-500 block">Line Numbers:</span>
            <span className="text-gray-300">
              {hasSourceCode && finding.line_numbers
                ? finding.line_numbers
                : "N/A (Black-box runtime)"}
            </span>
          </div>
        </div>

        {/* Source Code Location Banner (if unavailable) */}
        {!hasSourceCode && (
          <div className="flex items-center gap-2 p-2.5 rounded-xl bg-[#161F30]/70 border border-blue-500/20 text-blue-300 text-xs">
            <FileCode className="w-4 h-4 text-blue-400 shrink-0" />
            <span>
              Black-box assessment only — source code location unavailable. Runtime evidence is available.
            </span>
          </div>
        )}

        {/* Remediation Summary */}
        {finding.how_to_fix && (
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-gray-400 mb-1">
              Remediation
            </div>
            <p className="text-sm text-gray-300 leading-relaxed bg-[#111827]/70 p-3 rounded-xl border border-[#1E293B]">
              {finding.how_to_fix}
            </p>
          </div>
        )}

        {/* ================================================================= */}
        {/* EXPANDABLE SECTIONS                                               */}
        {/* ================================================================= */}
        <div className="space-y-2 pt-2 border-t border-[#1E293B]/70">
          {/* 1. View Vulnerable Code Section */}
          <div className="rounded-xl border border-[#2E3C58] bg-[#0A0F1A] overflow-hidden">
            <button
              type="button"
              onClick={() => setShowVulnerableCode(!showVulnerableCode)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-xs text-amber-300 hover:bg-[#161F30] transition-colors"
            >
              <div className="flex items-center gap-2 font-medium">
                <Code className="w-3.5 h-3.5 text-amber-400" />
                <span>View vulnerable code</span>
                {hasSourceCode && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-300 border border-amber-800/40">
                    Source
                  </span>
                )}
              </div>
              {showVulnerableCode ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showVulnerableCode && (
              <div className="p-3 bg-[#080C14] border-t border-[#1E293B] text-xs">
                {hasSourceCode && finding.vulnerable_code ? (
                  <div className="relative group">
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(finding.vulnerable_code || "", "vuln")
                      }
                      className="absolute top-2 right-2 flex items-center gap-1 px-2 py-1 text-[11px] rounded bg-[#1A2338] text-gray-300 hover:text-white border border-[#2E3C58]"
                    >
                      {copiedCode === "vuln" ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          Copy
                        </>
                      )}
                    </button>
                    <pre className="p-3 pt-6 rounded-lg bg-[#0F141F] text-amber-200/90 font-mono overflow-x-auto leading-relaxed border border-amber-900/30">
                      <code>{finding.vulnerable_code}</code>
                    </pre>
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-[#0F141F] text-gray-400 font-mono leading-relaxed border border-[#1E293B]">
                    <div className="text-amber-400 mb-1">
                      {"// Black-box assessment only — no source repository provided:"}
                    </div>
                    <div>
                      {finding.actual_behavior ||
                        "Endpoint allowed cross-user access without server-side owner assertion."}
                    </div>
                    <div className="text-gray-500 text-[11px] mt-2">
                      Source code location unavailable. Runtime evidence is available.
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 2. View Suggested Fix Section */}
          <div className="rounded-xl border border-[#2E3C58] bg-[#0A0F1A] overflow-hidden">
            <button
              type="button"
              onClick={() => setShowSuggestedFix(!showSuggestedFix)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-xs text-emerald-300 hover:bg-[#161F30] transition-colors"
            >
              <div className="flex items-center gap-2 font-medium">
                <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                <span>View suggested fix</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                  Patch
                </span>
              </div>
              {showSuggestedFix ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showSuggestedFix && (
              <div className="p-3 bg-[#080C14] border-t border-[#1E293B] text-xs">
                <div className="relative group">
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(
                        finding.suggested_code || finding.how_to_fix || "",
                        "fix"
                      )
                    }
                    className="absolute top-2 right-2 flex items-center gap-1 px-2 py-1 text-[11px] rounded bg-[#1A2338] text-gray-300 hover:text-white border border-[#2E3C58]"
                  >
                    {copiedCode === "fix" ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        Copy
                      </>
                    )}
                  </button>
                  <pre className="p-3 pt-6 rounded-lg bg-[#0F141F] text-emerald-300 font-mono overflow-x-auto leading-relaxed border border-emerald-900/30">
                    <code>
                      {finding.suggested_code ||
                        finding.how_to_fix ||
                        "// Enforce server-side authorization middleware\nrouter.use(verifyAuth, checkResourceOwnership);"}
                    </code>
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* 3. View Technical Details Section */}
          <div className="rounded-xl border border-[#2E3C58] bg-[#0A0F1A] overflow-hidden">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-xs text-blue-300 hover:bg-[#161F30] transition-colors"
            >
              <div className="flex items-center gap-2 font-medium">
                <FileText className="w-3.5 h-3.5 text-blue-400" />
                <span>View technical details</span>
              </div>
              {showTechnicalDetails ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showTechnicalDetails && (
              <div className="p-3.5 bg-[#080C14] border-t border-[#1E293B] text-xs space-y-2 font-mono">
                <div>
                  <span className="text-gray-500">Target Endpoint: </span>
                  <span className="text-gray-200">
                    {finding.http_method} {finding.affected_endpoint}
                  </span>
                </div>

                <div>
                  <span className="text-gray-500">Expected Behavior: </span>
                  <span className="text-blue-300">
                    {finding.expected_behavior ||
                      "Access denied (HTTP 401/403) for unauthorized role."}
                  </span>
                </div>

                <div>
                  <span className="text-gray-500">Observed Discrepancy: </span>
                  <span className="text-amber-300">
                    {finding.actual_behavior || finding.explanation}
                  </span>
                </div>

                {finding.evidence && (
                  <div className="pt-1 text-gray-400">
                    <span>Testing Persona: </span>
                    <span className="text-gray-200">
                      {finding.evidence.testing_role ||
                        finding.evidence.test_role ||
                        "User B"}
                    </span>
                    <span className="mx-2">·</span>
                    <span>Resource Owner: </span>
                    <span className="text-gray-200">
                      {finding.evidence.authorized_role || "User A"}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 4. View Evidence Section */}
          <div className="rounded-xl border border-[#2E3C58] bg-[#0A0F1A] overflow-hidden">
            <button
              type="button"
              onClick={() => setShowEvidence(!showEvidence)}
              className="w-full flex items-center justify-between px-4 py-2.5 text-xs text-gray-300 hover:bg-[#161F30] transition-colors"
            >
              <div className="flex items-center gap-2 font-medium">
                <Terminal className="w-3.5 h-3.5 text-gray-400" />
                <span>View evidence</span>
                {finding.evidence?.evidence_sha256 && (
                  <span className="text-[10px] text-gray-400 font-mono">
                    SHA-256: {finding.evidence.evidence_sha256.slice(0, 10)}...
                  </span>
                )}
              </div>
              {showEvidence ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            {showEvidence && (
              <div className="p-3.5 bg-[#080C14] border-t border-[#1E293B] text-xs font-mono space-y-2.5">
                {finding.evidence ? (
                  <>
                    <div className="flex items-center justify-between text-gray-400">
                      <span>Cryptographic Fingerprint:</span>
                      <code className="text-emerald-400 text-[11px]">
                        {finding.evidence.evidence_sha256 || "Signed"}
                      </code>
                    </div>

                    <div>
                      <span className="text-gray-500 block mb-1">
                        HTTP Request:
                      </span>
                      <pre className="p-2.5 rounded bg-[#0F141F] text-gray-300 overflow-x-auto border border-[#1E293B]">
                        <code>
                          {finding.evidence.request_method || finding.http_method}{" "}
                          {finding.evidence.request_url ||
                            finding.affected_endpoint}
                          {"\n"}
                          {finding.evidence.request_headers
                            ? Object.entries(finding.evidence.request_headers)
                                .map(([k, v]) => `${k}: ${v}`)
                                .join("\n")
                            : "Authorization: Bearer [REDACTED_TOKEN]\nAccept: application/json"}
                        </code>
                      </pre>
                    </div>

                    <div>
                      <span className="text-gray-500 block mb-1">
                        HTTP Response ({finding.evidence.response_status || 200}):
                      </span>
                      <pre className="p-2.5 rounded bg-[#0F141F] text-emerald-300 overflow-x-auto border border-[#1E293B]">
                        <code>
                          {finding.evidence.sanitized_response_evidence ||
                            finding.evidence.sanitized_response_body ||
                            finding.actual_behavior ||
                            "HTTP 200 OK with cross-user private data."}
                        </code>
                      </pre>
                    </div>
                  </>
                ) : (
                  <div className="text-gray-400 italic">
                    Runtime evidence attached to finding record ID: {finding.id}.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
