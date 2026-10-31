"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Code2,
  FileSearch,
  Lock,
  CheckCircle2,
  Globe,
  FileCode,
  Info,
  HelpCircle,
  MinusCircle,
} from "lucide-react";
import { FindingItem, FindingValidationStatus } from "@/types/assessment";

interface FindingCardProps {
  finding: FindingItem;
  index?: number;
}

export function resolveFindingStatus(finding: FindingItem): FindingValidationStatus {
  const raw = String(
    finding.finding_status || finding.validation_status || finding.confirmation_status || finding.status || ""
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

const UNAVAILABLE_SOURCE_TEXT =
  "Server-side source code was not available. This finding was detected through black-box HTTP testing.";

function getCategoryDisplay(rawCategory: string, explicitDisplay?: string): string {
  if (explicitDisplay && explicitDisplay.trim()) {
    return explicitDisplay;
  }
  const upper = (rawCategory || "BOLA_IDOR").toUpperCase();
  if (upper === "BOLA_IDOR" || upper === "IDOR") return "BOLA / IDOR";
  if (upper === "BFLA" || upper === "BROKEN_FUNCTION_LEVEL_AUTHORIZATION") {
    return "Broken Function Level Authorization";
  }
  if (upper === "HORIZONTAL_PRIVILEGE_ESCALATION") {
    return "Horizontal privilege escalation";
  }
  if (upper === "VERTICAL_PRIVILEGE_ESCALATION" || upper === "PRIVILEGE_ESCALATION") {
    return "Vertical privilege escalation";
  }
  if (upper === "MISSING_AUTH") return "Missing Authentication";
  return rawCategory;
}

function getStatusMeta(status: FindingValidationStatus): {
  badgeLabel: string;
  description: string;
  borderClass: string;
  badgeClass: string;
  icon: React.ReactNode;
} {
  switch (status) {
    case "CONFIRMED":
      return {
        badgeLabel: "CONFIRMED",
        description: "Security engine validated the evidence.",
        borderClass: "border-red-500/40 bg-red-950/15",
        badgeClass: "bg-red-500/20 text-red-300 border-red-500/40",
        icon: <ShieldAlert className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />,
      };
    case "SUSPICIOUS":
      return {
        badgeLabel: "SUSPICIOUS",
        description: "Potential issue, but evidence is incomplete.",
        borderClass: "border-amber-500/40 bg-amber-950/15",
        badgeClass: "bg-amber-500/20 text-amber-300 border-amber-500/40",
        icon: <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />,
      };
    case "NOT_CONFIRMED":
      return {
        badgeLabel: "NOT_CONFIRMED",
        description: "Testing did not establish the suspected vulnerability.",
        borderClass: "border-emerald-500/30 bg-emerald-950/10",
        badgeClass: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
        icon: <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />,
      };
    case "INCONCLUSIVE":
      return {
        badgeLabel: "INCONCLUSIVE",
        description: "The result could not be determined.",
        borderClass: "border-purple-500/30 bg-purple-950/10",
        badgeClass: "bg-purple-500/20 text-purple-300 border-purple-500/40",
        icon: <HelpCircle className="w-5 h-5 text-purple-400 mt-0.5 shrink-0" />,
      };
    case "NOT_TESTED":
    default:
      return {
        badgeLabel: "NOT_TESTED",
        description:
          "Required credentials, permissions or source information were unavailable.",
        borderClass: "border-zinc-700 bg-zinc-900/50",
        badgeClass: "bg-zinc-800 text-zinc-300 border-zinc-600",
        icon: <MinusCircle className="w-5 h-5 text-zinc-400 mt-0.5 shrink-0" />,
      };
  }
}

export function FindingCard({ finding }: FindingCardProps) {
  const [showRawEvidence, setShowRawEvidence] = useState(false);

  // Never display a suspicious finding as confirmed
  const rawStatus = (finding.validation_status || "SUSPICIOUS").toUpperCase();
  const normalizedStatus: FindingValidationStatus =
    finding.status === "suspected" ||
    finding.access_verdict === "SUSPICIOUS_ACCESS" ||
    rawStatus === "SUSPICIOUS"
      ? "SUSPICIOUS"
      : rawStatus === "CONFIRMED"
      ? "CONFIRMED"
      : rawStatus === "NOT_CONFIRMED"
      ? "NOT_CONFIRMED"
      : rawStatus === "INCONCLUSIVE"
      ? "INCONCLUSIVE"
      : rawStatus === "NOT_TESTED"
      ? "NOT_TESTED"
      : "SUSPICIOUS";

  const statusMeta = getStatusMeta(normalizedStatus);

  // A. Bug identity
  const bugName = finding.vulnerability_name || finding.title;
  const rawCategory =
    finding.vulnerability_category || finding.vulnerability_type || "BOLA_IDOR";
  const categoryDisplay = getCategoryDisplay(rawCategory, finding.category_display);
  const severity = finding.severity || "MEDIUM";

  const severityBadgeColor: Record<string, string> = {
    CRITICAL: "bg-red-600 text-white",
    HIGH: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    MEDIUM: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
    LOW: "bg-sky-500/20 text-sky-300 border border-sky-500/40",
    INFO: "bg-zinc-700 text-zinc-300",
  };

  // B. Website location
  const endpointPath =
    finding.website_location?.endpoint ||
    finding.target_endpoint ||
    finding.endpoint ||
    "/";
  const httpMethod =
    finding.website_location?.http_method || finding.http_method || "GET";
  const fullUrl =
    finding.website_location?.full_url ||
    finding.full_url ||
    finding.evidence?.request_url ||
    `http://localhost:3000${endpointPath.startsWith("/") ? "" : "/"}${endpointPath}`;
  const hostname =
    finding.website_location?.hostname || finding.hostname || "localhost";
  const parameterOrResourceId =
    finding.website_location?.parameter_or_resource_id ||
    finding.parameter_or_resource_id ||
    (finding.resource_id
      ? `resource_id=${finding.resource_id}`
      : endpointPath.includes("{id}")
      ? "Path parameter: {id} (redacted)"
      : "None (endpoint-level route)");

  // C. Source-code location (strictly verified; never invent files or line numbers)
  const techDetails = (finding.technical_details || {}) as Record<string, unknown>;
  const rawTechLoc = techDetails.source_location as Record<string, unknown> | undefined;

  const hasVerifiedSource = Boolean(
    (finding.source_code_available === true && finding.source_file) ||
      (finding.source_location?.available === true &&
        finding.source_location?.file_path) ||
      (rawTechLoc?.verified === true && rawTechLoc?.file_path)
  );

  const sourceRepository = hasVerifiedSource
    ? finding.source_location?.repository ||
      finding.source_repository ||
      (rawTechLoc?.repository_name as string) ||
      "target-repository"
    : null;
  const sourceFile = hasVerifiedSource
    ? finding.source_location?.file_path ||
      finding.source_file ||
      (rawTechLoc?.file_path as string) ||
      null
    : null;
  const sourceLine = hasVerifiedSource
    ? finding.source_location?.line_range ||
      finding.source_line ||
      (rawTechLoc?.start_line ? String(rawTechLoc.start_line) : null)
    : null;
  const sourceFunction = hasVerifiedSource
    ? finding.source_location?.function_name ||
      finding.source_function ||
      (rawTechLoc?.function_name as string) ||
      "handler"
    : null;
  const vulnerableSnippet = hasVerifiedSource
    ? finding.source_location?.vulnerable_snippet ||
      finding.vulnerable_snippet ||
      (rawTechLoc?.code_snippet as string) ||
      null
    : null;

  // D. What the bug can affect
  const exposedData =
    finding.impact_details?.exposed_data_or_functionality ||
    finding.exposed_data_or_functionality ||
    `Protected application data or privileged functionality at ${httpMethod} ${endpointPath}.`;
  const affectedRolesList =
    finding.impact_details?.affected_roles ||
    (finding.affected_roles && finding.affected_roles.length > 0
      ? finding.affected_roles
      : [finding.affected_role || "user_b"]);
  const attackerCapabilities =
    finding.impact_details?.attacker_capabilities ||
    finding.attacker_capabilities ||
    finding.actual_behavior ||
    `Invoke ${httpMethod} ${endpointPath} under role ${affectedRolesList.join(", ")} without proper authorization enforcement.`;
  const whyItMatters =
    finding.impact_details?.why_it_matters ||
    finding.why_it_matters ||
    finding.impact_explanation ||
    finding.description ||
    "Missing server-side access control compromises tenant data isolation and authorization boundaries.";

  // E. How to resolve it
  const rootCause =
    finding.resolution_details?.root_cause ||
    finding.root_cause ||
    (techDetails.root_cause as string) ||
    `Server-side handler for ${httpMethod} ${endpointPath} does not verify caller role or resource ownership before returning data.`;
  const recommendedFix =
    finding.resolution_details?.recommended_fix ||
    finding.recommended_fix ||
    finding.remediation_recommendation ||
    "Enforce server-side session authentication and explicit ownership/role checks in the route controller.";
  const proposedCodeFix =
    finding.resolution_details?.proposed_code_fix ||
    finding.proposed_code_fix ||
    finding.remediation_guidance ||
    finding.remediation_recommendation;
  const proposedFixLabel =
    finding.resolution_details?.proposed_fix_label ||
    finding.proposed_fix_label ||
    "Proposed Fix — Not automatically applied to the website";
  const verificationProcedure =
    finding.resolution_details?.verification_procedure ||
    finding.verification_procedure ||
    `Re-send ${httpMethod} ${endpointPath} using an unauthenticated or non-owner session (${affectedRolesList.join(
      ", "
    )}) and confirm the server responds with HTTP 401 Unauthorized or HTTP 403 Forbidden.`;

  // F. Sanitized Evidence Summary
  const baselineBehavior =
    finding.evidence_summary?.baseline_behavior ||
    finding.baseline_behavior ||
    finding.expected_behavior ||
    finding.evidence?.expected_behavior ||
    "Unauthorized requests must be denied with HTTP 401/403.";
  const unauthorizedBehavior =
    finding.evidence_summary?.unauthorized_behavior ||
    finding.unauthorized_behavior ||
    finding.actual_behavior ||
    finding.evidence?.actual_behavior ||
    "Observed discrepant response from target endpoint.";
  const responseDifference =
    finding.evidence_summary?.response_difference ||
    finding.response_difference ||
    `Expected access denial (${baselineBehavior}), but observed HTTP ${
      finding.evidence?.response_status ?? 200
    } (${unauthorizedBehavior}).`;
  const evidenceStatus =
    finding.evidence_summary?.validation_status ||
    finding.evidence_validation_status ||
    normalizedStatus;
  const evidenceSha =
    finding.evidence_summary?.evidence_sha256 ||
    finding.evidence?.evidence_sha256 ||
    "";

  return (
    <div
      className={`my-3 rounded-xl border p-4 transition-all ${statusMeta.borderClass}`}
      data-testid={`finding-card-${normalizedStatus.toLowerCase()}`}
    >
      {/* ====================================================================
          A. BUG IDENTITY
      ==================================================================== */}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-start gap-2.5">
          {statusMeta.icon}
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${statusMeta.badgeClass}`}
              >
                {statusMeta.badgeLabel}
              </span>
              <span
                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  severityBadgeColor[severity] || severityBadgeColor.MEDIUM
                }`}
              >
                {severity}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 border border-zinc-700">
                {categoryDisplay}
              </span>
              <span className="text-[10px] font-mono text-zinc-500">
                ({rawCategory})
              </span>
            </div>
            <h4 className="text-sm font-semibold text-zinc-100 mt-1.5">
              {bugName}
            </h4>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              Status note: {statusMeta.description}
            </p>
          </div>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-zinc-800/80 space-y-3 text-xs">
        {/* ==================================================================
            B. WEBSITE LOCATION
        ================================================================== */}
        <div className="rounded-lg bg-zinc-900/90 border border-zinc-800 p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-sky-400 mb-2">
            <Globe className="w-3.5 h-3.5" />
            <span>B. Website Location</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
            <div className="sm:col-span-2">
              <span className="text-zinc-500">Full Affected URL: </span>
              <span className="text-zinc-100 break-all">{fullUrl}</span>
            </div>
            <div>
              <span className="text-zinc-500">Hostname: </span>
              <span className="text-zinc-200">{hostname}</span>
            </div>
            <div>
              <span className="text-zinc-500">HTTP Method &amp; Endpoint: </span>
              <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-emerald-300 font-bold mr-1">
                {httpMethod}
              </span>
              <span className="text-zinc-200">{endpointPath}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-zinc-500">
                Parameter / Resource Identifier (Redacted):{" "}
              </span>
              <span className="text-amber-300">{parameterOrResourceId}</span>
            </div>
          </div>
        </div>

        {/* ==================================================================
            C. SOURCE-CODE LOCATION
        ================================================================== */}
        <div className="rounded-lg bg-zinc-900/90 border border-zinc-800 p-3">
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-purple-400">
              <FileCode className="w-3.5 h-3.5" />
              <span>C. Source-Code Location</span>
            </div>
            {hasVerifiedSource && sourceFile && (
              <span className="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-200 font-mono text-[11px] font-semibold">
                {sourceFile}
                {sourceLine ? `:${sourceLine}` : ""}
              </span>
            )}
          </div>

          {hasVerifiedSource && sourceFile ? (
            <div className="space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]">
                <div>
                  <span className="text-zinc-500">Repository: </span>
                  <span className="text-zinc-200">{sourceRepository}</span>
                </div>
                <div>
                  <span className="text-zinc-500">File Path: </span>
                  <span className="text-purple-300 font-semibold">
                    {sourceFile}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500">Line Number / Range: </span>
                  <span className="text-amber-300 font-semibold">
                    {sourceLine || "1"}
                  </span>
                </div>
                <div>
                  <span className="text-zinc-500">Function / Handler: </span>
                  <span className="text-sky-300">{sourceFunction}</span>
                </div>
              </div>
              {vulnerableSnippet && (
                <div className="mt-2">
                  <div className="text-[11px] text-zinc-400 mb-1">
                    Vulnerable Code Snippet:
                  </div>
                  <pre className="p-2.5 rounded bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-rose-300 overflow-x-auto whitespace-pre-wrap">
                    {vulnerableSnippet}
                  </pre>
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-start gap-2 rounded bg-zinc-950/80 border border-zinc-800/80 p-2.5 text-zinc-300">
              <Info className="w-4 h-4 text-zinc-400 shrink-0 mt-0.5" />
              <p className="text-xs leading-relaxed">
                {UNAVAILABLE_SOURCE_TEXT}
              </p>
            </div>
          )}
        </div>

        {/* ==================================================================
            D. WHAT THE BUG CAN AFFECT
        ================================================================== */}
        <div className="rounded-lg bg-zinc-900/90 border border-zinc-800 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-amber-400">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>D. What the Bug Can Affect</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/70">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Exposed Data or Functionality
              </div>
              <p className="text-zinc-200 leading-relaxed">{exposedData}</p>
            </div>
            <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/70">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Affected User Roles
              </div>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {affectedRolesList.map((r) => (
                  <span
                    key={r}
                    className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 font-mono text-[11px] text-zinc-200"
                  >
                    {r}
                  </span>
                ))}
              </div>
            </div>
            <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/70">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                What an Attacker Could Do
              </div>
              <p className="text-zinc-200 leading-relaxed">
                {attackerCapabilities}
              </p>
            </div>
            <div className="p-2 rounded bg-zinc-950/60 border border-zinc-800/70">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Why the Issue Matters
              </div>
              <p className="text-zinc-200 leading-relaxed">{whyItMatters}</p>
            </div>
          </div>
        </div>

        {/* ==================================================================
            E. HOW TO RESOLVE IT
        ================================================================== */}
        <div className="rounded-lg bg-zinc-900/90 border border-zinc-800 p-3 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
              <Code2 className="w-3.5 h-3.5" />
              <span>E. How to Resolve It</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px] font-medium">
              {proposedFixLabel}
            </span>
          </div>

          <div className="space-y-1.5">
            <div>
              <span className="text-zinc-400 font-semibold">Root Cause: </span>
              <span className="text-zinc-200">{rootCause}</span>
            </div>
            <div>
              <span className="text-zinc-400 font-semibold">
                Recommended Fix:{" "}
              </span>
              <span className="text-zinc-200">{recommendedFix}</span>
            </div>
          </div>

          {proposedCodeFix && (
            <div>
              <div className="flex items-center justify-between text-[11px] text-zinc-400 mb-1">
                <span>Proposed Corrected Server-Side Code:</span>
                <span className="text-[10px] text-amber-400/90 italic">
                  Proposal only — not applied to target website
                </span>
              </div>
              <pre className="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                {proposedCodeFix}
              </pre>
            </div>
          )}

          <div className="p-2.5 rounded bg-emerald-950/20 border border-emerald-500/30">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-300 mb-0.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Safe Verification Procedure</span>
            </div>
            <p className="text-zinc-300 text-[11px] leading-relaxed">
              {verificationProcedure}
            </p>
          </div>
        </div>

        {/* ==================================================================
            F. SANITIZED EVIDENCE SUMMARY
        ================================================================== */}
        <div className="rounded-lg bg-zinc-900/90 border border-zinc-800 p-3 space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-zinc-300">
              <FileSearch className="w-3.5 h-3.5 text-sky-400" />
              <span>F. Sanitized Evidence Summary</span>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${statusMeta.badgeClass}`}
              >
                Validation: {evidenceStatus}
              </span>
              {evidenceSha && (
                <span className="text-[10px] font-mono text-zinc-400 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-emerald-400" />
                  SHA-256: {evidenceSha.slice(0, 16)}...
                </span>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="p-2 rounded bg-zinc-950/70 border border-zinc-800">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Baseline / Expected Behavior
              </div>
              <p className="text-zinc-200 leading-relaxed">{baselineBehavior}</p>
            </div>
            <div className="p-2 rounded bg-zinc-950/70 border border-zinc-800">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Observed Unauthorized Behavior
              </div>
              <p className="text-zinc-200 leading-relaxed">
                {unauthorizedBehavior}
              </p>
            </div>
            <div className="sm:col-span-2 p-2 rounded bg-zinc-950/70 border border-zinc-800">
              <div className="text-[10px] uppercase font-semibold text-zinc-500 mb-0.5">
                Relevant Response Difference
              </div>
              <p className="text-zinc-200 leading-relaxed">
                {responseDifference}
              </p>
            </div>
          </div>

          {finding.evidence && (
            <div className="pt-1">
              <button
                type="button"
                onClick={() => setShowRawEvidence((prev) => !prev)}
                className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                {showRawEvidence ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5" />
                )}
                <span>
                  {showRawEvidence ? "Hide" : "Inspect"} Redacted HTTP Request
                  &amp; Response Artifact
                </span>
              </button>

              {showRawEvidence && (
                <div className="mt-2 p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2 font-mono text-[11px]">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-zinc-400 border-b border-zinc-800 pb-1.5">
                    <span>
                      Role:{" "}
                      <strong className="text-zinc-200">
                        {finding.evidence.testing_role}
                      </strong>{" "}
                      | Status:{" "}
                      <strong className="text-zinc-200">
                        HTTP {finding.evidence.response_status}
                      </strong>
                    </span>
                    <span className="flex items-center gap-1 text-emerald-400">
                      <Lock className="w-3 h-3" />
                      SHA-256: {finding.evidence.evidence_sha256.slice(0, 20)}...
                    </span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Request URL: </span>
                    <span className="text-zinc-300">
                      {finding.evidence.request_method}{" "}
                      {finding.evidence.request_url}
                    </span>
                  </div>
                  {finding.evidence.redacted_fields &&
                    finding.evidence.redacted_fields.length > 0 && (
                      <div>
                        <span className="text-zinc-500">
                          Sanitized / Redacted Fields:{" "}
                        </span>
                        <span className="text-amber-300">
                          {finding.evidence.redacted_fields.join(", ")}
                        </span>
                      </div>
                    )}
                  {finding.evidence.sanitized_response_body && (
                    <div>
                      <div className="text-zinc-500 mb-1">
                        Sanitized Response Excerpt (Secrets &amp; Tokens
                        Redacted):
                      </div>
                      <pre className="p-2 rounded bg-zinc-900 text-zinc-300 overflow-x-auto max-h-40">
                        {finding.evidence.sanitized_response_body}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
