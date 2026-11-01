"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  GitFork,
  Play,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  Code2,
  ListOrdered,
  ChevronRight,
  ShieldCheck,
  Link2,
  X,
} from "lucide-react";
import { api } from "@/api/client";
import type {
  AttackChainCandidateData,
  AttackChainExecutionData,
  EndpointGraphData,
} from "@/types/assessment";

interface Props {
  assessmentId: string;
  targetUrl: string;
  onFindingConfirmed?: () => void;
  onClose?: () => void;
}

export function AttackChainPanel({ assessmentId, targetUrl, onFindingConfirmed, onClose }: Props) {
  const [activeTab, setActiveTab] = useState<"candidates" | "graph" | "execution">("candidates");
  const [candidates, setCandidates] = useState<AttackChainCandidateData[]>([]);
  const [graphData, setGraphData] = useState<EndpointGraphData | null>(null);
  const [selectedCandidate, setSelectedCandidate] = useState<AttackChainCandidateData | null>(null);
  const [executionResult, setExecutionResult] = useState<AttackChainExecutionData | null>(null);
  const [planning, setPlanning] = useState<boolean>(false);
  const [executing, setExecuting] = useState<boolean>(false);
  const [validating, setValidating] = useState<boolean>(false);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [retesting, setRetesting] = useState<boolean>(false);
  const [retestResult, setRetestResult] = useState<{ status: string; notes: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const nodeLabelById = useMemo(() => {
    const map: Record<string, string> = {};
    for (const node of graphData?.nodes || []) {
      const id = String(node.endpoint_id || "");
      const method = String(node.method || "GET");
      const path = String(node.path || "");
      if (id) {
        map[id] = `${method} ${path}`.trim();
      }
    }
    return map;
  }, [graphData]);

  const loadData = async () => {
    if (!assessmentId) return;
    try {
      setError(null);
      const [chainsRes, graphRes] = await Promise.all([
        api.getAttackChains(assessmentId).catch(() => ({ candidates: [] })),
        api.getEndpointGraph(assessmentId).catch(() => null),
      ]);
      let loadedCandidates = chainsRes.candidates || [];
      if (loadedCandidates.length === 0) {
        const planned = await api
          .planAttackChains(assessmentId, { max_steps: 5, max_candidates: 25 })
          .catch(() => ({ candidates: [] }));
        loadedCandidates = planned.candidates || [];
      }
      setCandidates(loadedCandidates);
      setGraphData(graphRes);
      if (loadedCandidates.length > 0 && !selectedCandidate) {
        setSelectedCandidate(loadedCandidates[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load attack chain data.");
    }
  };

  useEffect(() => {
    const timer = window.setTimeout(() => void loadData(), 0);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assessmentId]);

  const handlePlanChains = async () => {
    try {
      setPlanning(true);
      setError(null);
      const [res, graphRes] = await Promise.all([
        api.planAttackChains(assessmentId, { max_steps: 5, max_candidates: 25 }),
        api.getEndpointGraph(assessmentId).catch(() => graphData),
      ]);
      setCandidates(res.candidates || []);
      if (graphRes) setGraphData(graphRes);
      if (res.candidates?.length > 0) {
        setSelectedCandidate(res.candidates[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to plan attack chains.");
    } finally {
      setPlanning(false);
    }
  };

  const ensureRolesConfiguredForExecution = async () => {
    try {
      const status = await api.getRoles();
      if (!status.roles?.user_a?.authenticated) {
        await api.configureRole({
          role: "user_a",
          token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_uid_101_session",
          user_id: "101",
          owned_resources: { basket: "101", user: "101", card: "101", address: "101", order: "101" },
        });
      }
      if (!status.roles?.user_b?.authenticated) {
        await api.configureRole({
          role: "user_b",
          token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_uid_102_session",
          user_id: "102",
          owned_resources: { basket: "102", user: "102", order: "102" },
        });
      }
      if (!status.roles?.admin?.authenticated) {
        await api.configureRole({
          role: "admin",
          token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_uid_1_session",
          user_id: "1",
          owned_resources: { user: "1" },
        });
      }
    } catch {
      // Proceed even if role pre-check fails; backend will report exact status
    }
  };

  const handleExecuteChain = async (candidate: AttackChainCandidateData) => {
    try {
      setValidating(true);
      setError(null);
      setValidationMessage(null);
      const validation = await api.validateAttackChain(
        assessmentId,
        candidate as unknown as Record<string, unknown>
      );
      if (!validation.is_valid) {
        const reason =
          validation.rejection_reasons.join(" ") || "The candidate did not pass validation.";
        setValidationMessage(`Not executed: ${reason}`);
        return;
      }
      setValidationMessage(
        "Candidate passed deterministic scope & method validation. Executing across roles..."
      );
      await ensureRolesConfiguredForExecution();
      setValidating(false);
      setExecuting(true);
      setExecutionResult(null);
      setRetestResult(null);
      setActiveTab("execution");
      const res = await api.executeAttackChain(assessmentId, {
        candidate_id: candidate.candidate_id,
        chain: candidate as unknown as Record<string, unknown>,
        save_finding: true,
      });
      setExecutionResult(res);
      if (res.is_confirmed && onFindingConfirmed) {
        onFindingConfirmed();
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Execution failed.");
    } finally {
      setValidating(false);
      setExecuting(false);
    }
  };

  const handleRetestFinding = async (findingId: string) => {
    try {
      setRetesting(true);
      setError(null);
      await ensureRolesConfiguredForExecution();
      const res = await api.verifyFix(assessmentId, findingId);
      const v = res.verification as { new_status?: string; notes?: string; summary?: string };
      setRetestResult({
        status: v.new_status || "RETESTED",
        notes: v.notes || v.summary || "Retest completed.",
      });
      if (onFindingConfirmed) onFindingConfirmed();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Retest failed.");
    } finally {
      setRetesting(false);
    }
  };

  const getScenarioStyle = (scenario: string) => {
    const s = (scenario || "").toUpperCase();
    if (s.includes("PRIVILEGE") || s.includes("MIXED")) {
      return "bg-[#fdecea] text-[#b42318] border-[#f4c7c3]";
    }
    if (s.includes("BOLA") || s.includes("IDOR")) {
      return "bg-[#f5efe6] text-[#9a5b13] border-[#e6d5bc]";
    }
    return "bg-[#e8f3ec] text-[#2f6f4e] border-[#b8d8c5]";
  };

  const getHypothesisText = (cand: AttackChainCandidateData): string => {
    const s = (cand.scenario || "").toUpperCase();
    if (s.includes("BOLA") || s.includes("IDOR")) {
      return "Checks if private data (e.g. user profile or shopping cart) belonging to User A can be viewed or changed by User B without permission.";
    }
    if (s.includes("PRIVILEGE") || s.includes("MIXED")) {
      return "Checks if a normal user or visitor can access administrator endpoints discovered during scanning.";
    }
    if (cand.hypothesis && cand.hypothesis.trim()) {
      return cand.hypothesis;
    }
    return "Multi-step test verifying whether unauthorized users can access private resources discovered across endpoints.";
  };

  return (
    <div className="text-[var(--text)] space-y-4">
      {/* Aesthetic Header & Controls Toolbar (Never Wraps Title) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[var(--line-subtle)] pb-3">
        <div className="flex items-center gap-2.5 min-w-0 shrink-0">
          <div className="p-2 bg-[var(--panel)] border border-[var(--line)] rounded-lg text-[#2f6f4e]">
            <GitFork className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-semibold text-sm text-[var(--text)] whitespace-nowrap">
                Attack Chain Paths
              </h3>
              <span className="text-[11px] font-mono text-[var(--muted)] px-2 py-0.5 rounded bg-[var(--sidebar)] border border-[var(--line)] truncate max-w-[240px]">
                {targetUrl}
              </span>
            </div>
            <p className="text-[11px] text-[var(--muted)]">
              Multi-step dependency discovery and cross-role authorization paths.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 self-start md:self-auto">
          {/* Aesthetic Segmented Tabs */}
          <div className="flex bg-[var(--sidebar)] p-0.5 rounded-lg border border-[var(--line)] text-xs">
            <button
              type="button"
              onClick={() => setActiveTab("candidates")}
              className={`px-2.5 py-1 rounded-md transition cursor-pointer text-xs font-medium ${
                activeTab === "candidates"
                  ? "bg-[var(--panel)] text-[var(--text)] border border-[var(--line)] shadow-xs"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              Candidates ({candidates.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("graph")}
              className={`px-2.5 py-1 rounded-md transition cursor-pointer text-xs font-medium ${
                activeTab === "graph"
                  ? "bg-[var(--panel)] text-[var(--text)] border border-[var(--line)] shadow-xs"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              Graph ({graphData?.nodes_count || 0})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("execution")}
              className={`px-2.5 py-1 rounded-md transition cursor-pointer text-xs font-medium ${
                activeTab === "execution"
                  ? "bg-[var(--panel)] text-[var(--text)] border border-[var(--line)] shadow-xs"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
              }`}
            >
              Live Execution {executionResult ? "• 1" : ""}
            </button>
          </div>

          <button
            type="button"
            onClick={() => void handlePlanChains()}
            disabled={planning}
            className="px-2.5 py-1 bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] hover:border-[#2f6f4e] text-[var(--text)] text-xs font-medium rounded-md flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 shrink-0 whitespace-nowrap"
            title="Re-plan attack chain paths from endpoint graph"
          >
            <RefreshCw className={`w-3 h-3 text-[#2f6f4e] ${planning ? "animate-spin" : ""}`} />
            <span>{planning ? "Planning..." : "Plan Chains"}</span>
          </button>

          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="px-2.5 py-1 text-xs text-[var(--muted)] hover:text-[var(--text)] bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] rounded-md flex items-center gap-1 transition cursor-pointer shrink-0"
              title="Close modal"
            >
              <X className="w-3.5 h-3.5" />
              <span>Close</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[#d2675f]/12 border border-[#d2675f]/35 rounded-lg text-[#d2675f] text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* TAB 1: Candidates List & Inspector */}
      {activeTab === "candidates" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Candidate Cards List */}
          <div className="lg:col-span-5 space-y-2.5 max-h-[520px] overflow-y-auto pr-1">
            {candidates.length === 0 ? (
              <div className="p-8 text-center bg-[var(--sidebar)] border border-dashed border-[var(--line)] rounded-xl text-[var(--muted)] text-xs">
                <ListOrdered className="w-8 h-8 mx-auto mb-2 opacity-50 text-[#2f6f4e]" />
                <p className="font-medium text-[var(--text)]">No attack-chain candidates planned yet.</p>
                <p className="mt-1 text-[11px] text-[var(--muted)]">
                  Click &ldquo;Plan Chains&rdquo; above to build dependency-driven attack paths across discovered routes.
                </p>
              </div>
            ) : (
              candidates.map((c) => {
                const isSelected = selectedCandidate?.candidate_id === c.candidate_id;
                return (
                  <div
                    key={c.candidate_id}
                    onClick={() => setSelectedCandidate(c)}
                    className={`p-3.5 rounded-xl border text-left cursor-pointer transition ${
                      isSelected
                        ? "bg-[var(--panel)] border-[#2f6f4e] ring-1 ring-[#2f6f4e]/35"
                        : "bg-[var(--sidebar)] border-[var(--line)] hover:border-[var(--muted)] hover:bg-[var(--panel)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${getScenarioStyle(
                          c.scenario
                        )}`}
                      >
                        {c.scenario.replace(/_/g, " ")}
                      </span>
                      <span className="text-[11px] text-[var(--muted)] font-mono">
                        {c.steps.length} Steps • Risk {c.risk_score}/100
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-[var(--text)] line-clamp-1">
                      {c.chain_name || `${c.scenario.replace(/_/g, " ")} Attack Path`}
                    </h4>

                    {/* Step path preview */}
                    <div className="mt-2.5 text-[11px] font-mono text-[var(--muted)] flex flex-wrap items-center gap-1">
                      {c.steps.map((st, idx) => (
                        <React.Fragment key={st.step_id || idx}>
                          <span className="px-2 py-0.5 bg-[var(--canvas)] border border-[var(--line-subtle)] rounded text-[var(--soft)] text-[10px] truncate max-w-[145px]">
                            {st.method} {st.path}
                          </span>
                          {idx < c.steps.length - 1 && (
                            <ChevronRight className="w-3 h-3 text-[var(--faint)] shrink-0" />
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Candidate Detail & Execution Inspector */}
          <div className="lg:col-span-7">
            {selectedCandidate ? (
              <div className="p-4 bg-[var(--sidebar)] border border-[var(--line)] rounded-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--line-subtle)] pb-3.5">
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-semibold text-[var(--text)]">
                        {selectedCandidate.chain_name || selectedCandidate.scenario}
                      </h4>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${getScenarioStyle(
                          selectedCandidate.scenario
                        )}`}
                      >
                        Risk {selectedCandidate.risk_score}
                      </span>
                    </div>
                    <p className="text-[11px] font-mono text-[var(--faint)] mt-0.5">
                      ID: {selectedCandidate.candidate_id}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => void handleExecuteChain(selectedCandidate)}
                    disabled={executing || validating}
                    className="px-3 py-1.5 bg-[#2f6f4e] hover:bg-[#285e43] disabled:opacity-50 !text-white text-xs font-semibold rounded-md flex items-center gap-1.5 transition cursor-pointer shrink-0"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>
                      {validating
                        ? "Validating..."
                        : executing
                        ? "Executing..."
                        : "Validate & Execute"}
                    </span>
                  </button>
                </div>

                {validationMessage && (
                  <div
                    className="p-2.5 rounded-lg bg-[var(--panel)] border border-[#2f6f4e]/40 text-xs text-[var(--soft)] flex items-center gap-2"
                    role="status"
                  >
                    <ShieldCheck className="w-4 h-4 text-[#2f6f4e] shrink-0" />
                    <span>{validationMessage}</span>
                  </div>
                )}

                {/* Risk Hypothesis */}
                <div>
                  <h5 className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-1.5">
                    Authorization Hypothesis &amp; Rationale
                  </h5>
                  <p className="text-xs text-[var(--soft)] bg-[var(--panel)] p-3 rounded-lg border border-[var(--line)] leading-relaxed">
                    {getHypothesisText(selectedCandidate)}
                  </p>
                </div>

                {/* Step Sequence Details */}
                <div>
                  <h5 className="text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-2">
                    Ordered Step Sequence ({selectedCandidate.steps.length} Steps)
                  </h5>
                  <div className="space-y-2.5">
                    {selectedCandidate.steps.map((st, idx) => {
                      const stepRole =
                        st.role ||
                        (st as unknown as { expected_role?: string }).expected_role ||
                        (idx === 0 ? "user_a" : "user_b");
                      const stepPurpose = (st as unknown as { purpose?: string }).purpose;
                      return (
                        <div
                          key={st.step_id || idx}
                          className="p-3 bg-[var(--panel)] border border-[var(--line)] rounded-lg flex items-start gap-3 text-xs"
                        >
                          <span className="w-4 h-4 rounded-full bg-[#e8f3ec] text-[#2f6f4e] border border-[#b8d8c5] flex items-center justify-center font-mono font-bold text-[9px] shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <div className="flex-1 space-y-1.5">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-mono text-[var(--text)] font-semibold">
                                {st.method} {st.path}
                              </span>
                              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-[var(--sidebar)] border border-[var(--line)] text-[var(--soft)]">
                                Role: {stepRole}
                              </span>
                            </div>

                            {stepPurpose && (
                              <p className="text-[11px] text-[var(--muted)]">{stepPurpose}</p>
                            )}

                            {st.input_bindings && st.input_bindings.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                                <span className="text-[10px] text-[var(--muted)] flex items-center gap-1">
                                  <Link2 className="w-3 h-3 text-[#2f6f4e]" />
                                  Parameter Binding:
                                </span>
                                {st.input_bindings.map((b, bIdx) => (
                                  <span
                                    key={bIdx}
                                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#e8f3ec] text-[#2f6f4e] border border-[#b8d8c5]"
                                  >
                                    {b.parameter} &larr; {b.source_step_id}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-[var(--sidebar)] border border-[var(--line)] rounded-xl text-[var(--muted)] text-xs">
                Select a candidate attack chain from the list to inspect its steps and execute.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Endpoint Relationship Graph */}
      {activeTab === "graph" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[var(--muted)] bg-[var(--sidebar)] p-3 rounded-lg border border-[var(--line)]">
            <span>
              Graph Topology:{" "}
              <strong className="text-[var(--text)]">{graphData?.nodes_count || 0}</strong> Discovered Endpoints •{" "}
              <strong className="text-[var(--text)]">{graphData?.relationships_count || 0}</strong> Verified Relationships
            </span>
            <span className="text-[11px] font-mono text-[#2f6f4e]">Target: {targetUrl}</span>
          </div>

          {!graphData?.relationships?.length ? (
            <div className="p-8 text-center bg-[var(--sidebar)] border border-dashed border-[var(--line)] rounded-xl text-[var(--muted)] text-xs">
              No endpoint dependency edges mapped yet. Click &ldquo;Plan Chains&rdquo; to build the graph.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto pr-1">
              {graphData.relationships.map((rel, idx) => {
                const srcLabel =
                  nodeLabelById[rel.source_endpoint_id] ||
                  `${rel.source_endpoint_id.slice(0, 10)}...`;
                const dstLabel =
                  nodeLabelById[rel.target_endpoint_id] ||
                  `${rel.target_endpoint_id.slice(0, 10)}...`;
                return (
                  <div
                    key={idx}
                    className="p-3.5 bg-[var(--sidebar)] border border-[var(--line)] rounded-xl space-y-2.5 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#e8f3ec] text-[#2f6f4e] border border-[#b8d8c5] font-semibold">
                        {rel.relationship}
                      </span>
                      <span className="text-[10px] text-[var(--muted)] font-mono">
                        Confidence: {rel.confidence}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] bg-[var(--panel)] p-2 rounded-lg border border-[var(--line-subtle)]">
                      <span className="text-[var(--soft)] truncate max-w-[190px]" title={srcLabel}>
                        {srcLabel}
                      </span>
                      <ArrowRight className="w-3.5 h-3.5 text-[#2f6f4e] shrink-0" />
                      <span className="text-[#2f6f4e] font-semibold truncate max-w-[190px]" title={dstLabel}>
                        {dstLabel}
                      </span>
                    </div>

                    <p className="text-[11px] text-[var(--muted)] leading-relaxed">{rel.rationale}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Execution Timeline & Evidence */}
      {activeTab === "execution" && (
        <div className="space-y-5">
          {executing && (
            <div className="p-8 text-center bg-[var(--sidebar)] border border-[var(--line)] rounded-xl space-y-3">
              <RefreshCw className="w-7 h-7 text-[#2f6f4e] animate-spin mx-auto" />
              <p className="text-sm font-semibold text-[var(--text)]">
                Executing Multi-Step Attack Chain Safely...
              </p>
              <p className="text-xs text-[var(--muted)]">
                Applying non-destructive GET constraints, dynamic parameter binding, and cross-role authorization checks.
              </p>
            </div>
          )}

          {!executing && !executionResult && (
            <div className="p-8 text-center bg-[var(--sidebar)] border border-dashed border-[var(--line)] rounded-xl text-[var(--muted)] text-xs">
              <Play className="w-8 h-8 mx-auto mb-2 opacity-50 text-[#2f6f4e]" />
              <p className="font-medium text-[var(--text)]">No chain has been executed in this session yet.</p>
              <p className="mt-1 text-[11px] text-[var(--muted)]">
                Select a candidate in the &ldquo;Candidates&rdquo; tab and click &ldquo;Validate &amp; Execute&rdquo;.
              </p>
            </div>
          )}

          {executionResult && (
            <div className="space-y-5">
              {/* Outcome Banner */}
              <div
                className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  executionResult.is_confirmed
                    ? "bg-[#d2675f]/12 border-[#d2675f]/40"
                    : "bg-[#2f6f4e]/12 border-[#2f6f4e]/40"
                }`}
              >
                <div className="flex items-center gap-3">
                  {executionResult.is_confirmed ? (
                    <ShieldAlert className="w-6 h-6 text-[#d2675f] shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-6 h-6 text-[#2f6f4e] shrink-0" />
                  )}
                  <div>
                    <h4 className="text-sm font-semibold text-[var(--text)]">
                      Status: {executionResult.status} (
                      {executionResult.is_confirmed
                        ? "Confirmed Multi-Step Authorization Vulnerability"
                        : "Access Boundaries Enforced"}
                      )
                    </h4>
                    <p className="text-xs text-[var(--soft)] mt-0.5">{executionResult.summary}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs shrink-0">
                  <span className="px-2.5 py-1 rounded-lg bg-[var(--panel)] border border-[var(--line)] text-[var(--text)]">
                    Severity: {executionResult.severity}
                  </span>
                  <span className="px-2.5 py-1 rounded-lg bg-[var(--panel)] border border-[var(--line)] text-[var(--text)]">
                    Confidence: {executionResult.confidence}
                  </span>
                </div>
              </div>

              {/* Step Execution Telemetry */}
              <div className="space-y-3">
                <h5 className="text-xs font-semibold text-[var(--muted)] uppercase tracking-wider">
                  Step-by-Step Execution Telemetry ({executionResult.step_results.length} Steps)
                </h5>
                <div className="space-y-2.5">
                  {executionResult.step_results.map((st, idx) => {
                    const isViolation = st.verdict === "CONFIRMED_UNAUTHORIZED_ACCESS";
                    return (
                      <div
                        key={st.step_id || idx}
                        className={`p-3.5 rounded-xl border text-xs space-y-2 ${
                          isViolation
                            ? "bg-[#d2675f]/10 border-[#d2675f]/45"
                            : "bg-[var(--sidebar)] border-[var(--line)]"
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-[var(--muted)]">Step {idx + 1}:</span>
                            <span className="font-mono text-[var(--text)] font-semibold">
                              {st.method} {st.endpoint_path}
                            </span>
                            {st.resolved_url && (
                              <span className="font-mono text-[11px] text-[#2f6f4e]">
                                ({st.resolved_url})
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-[var(--panel)] border border-[var(--line)] text-[var(--soft)] uppercase">
                              Role: {st.role_used}
                            </span>
                            <span
                              className={`font-mono text-[10px] px-2 py-0.5 rounded-full font-bold border ${
                                st.status_code >= 200 && st.status_code < 300
                                  ? "bg-[#e8f3ec] text-[#2f6f4e] border-[#b8d8c5]"
                                  : "bg-[var(--panel)] text-[var(--muted)] border-[var(--line)]"
                              }`}
                            >
                              HTTP {st.status_code}
                            </span>
                          </div>
                        </div>

                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-[var(--muted)]">
                          <span>
                            Verdict:{" "}
                            <strong className={isViolation ? "text-[#d2675f]" : "text-[#2f6f4e]"}>
                              {st.verdict}
                            </strong>
                          </span>
                          {st.evidence_sha256 && (
                            <span className="font-mono text-[10px] text-[var(--soft)]">
                              Evidence SHA-256: {st.evidence_sha256.slice(0, 16)}...
                            </span>
                          )}
                        </div>

                        <p className="text-[11px] text-[var(--soft)] bg-[var(--panel)] p-2.5 rounded-lg border border-[var(--line-subtle)]">
                          {st.actual_behavior}
                        </p>

                        {st.error_message && (
                          <p className="text-[11px] text-[#d2675f] font-mono">
                            Note: {st.error_message}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Remediation & Retesting Controls */}
              {executionResult.finding_id && (
                <div className="p-4 bg-[var(--sidebar)] border border-[var(--line)] rounded-xl space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h5 className="text-xs font-semibold text-[var(--text)] flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-[#2f6f4e]" />
                      <span>Remediation Guidance &amp; Automated Fix Retesting</span>
                    </h5>
                    <button
                      type="button"
                      onClick={() => void handleRetestFinding(executionResult.finding_id!)}
                      disabled={retesting}
                      className="px-2.5 py-1 bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] hover:border-[#2f6f4e] text-[var(--text)] text-xs font-medium rounded-md flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 text-[#2f6f4e] ${retesting ? "animate-spin" : ""}`} />
                      <span>{retesting ? "Retesting..." : "Retest Attack Chain"}</span>
                    </button>
                  </div>

                  {retestResult && (
                    <div className="p-3 bg-[var(--panel)] border border-[#2f6f4e]/40 rounded-lg text-xs space-y-1">
                      <p className="font-semibold text-[#2f6f4e]">
                        Verification Outcome: {retestResult.status}
                      </p>
                      <p className="text-[var(--soft)]">{retestResult.notes}</p>
                    </div>
                  )}

                  {executionResult.remediation_code_patch && (
                    <pre className="p-3 bg-[var(--panel)] rounded-lg border border-[var(--line)] font-mono text-[11px] text-[#2f6f4e] overflow-x-auto">
                      {executionResult.remediation_code_patch}
                    </pre>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
