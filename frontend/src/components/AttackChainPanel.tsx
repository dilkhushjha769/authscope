"use client";

import React, { useState, useEffect, useCallback } from "react";
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
} from "lucide-react";
import { api } from "@/lib/api";
import type {
  AttackChainCandidateData,
  AttackChainExecutionData,
  EndpointGraphData,
  EndpointNodeInfo,
  EndpointRelationshipInfo,
} from "@/types/assessment";

interface Props {
  assessmentId: string;
  targetUrl: string;
  onFindingConfirmed?: () => void;
}

export function AttackChainPanel({ assessmentId, targetUrl, onFindingConfirmed }: Props) {
  const [activeTab, setActiveTab] = useState<"candidates" | "graph" | "execution">("candidates");
  const [candidates, setCandidates] = useState<AttackChainCandidateData[]>([]);
  const [graphData, setGraphData] = useState<EndpointGraphData | null>(null);
  const [selectedCandidate, setSelectedCandidate] = useState<AttackChainCandidateData | null>(null);
  const [executionResult, setExecutionResult] = useState<AttackChainExecutionData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [planning, setPlanning] = useState<boolean>(false);
  const [executing, setExecuting] = useState<boolean>(false);
  const [validating, setValidating] = useState<boolean>(false);
  const [validationMessage, setValidationMessage] = useState<string | null>(null);
  const [retesting, setRetesting] = useState<boolean>(false);
  const [retestResult, setRetestResult] = useState<{ status: string; notes: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!assessmentId) return;
    try {
      setLoading(true);
      setError(null);
      const [chainsRes, graphRes] = await Promise.all([
        api.getAttackChains(assessmentId).catch(() => ({ candidates: [] })),
        api.getEndpointGraph(assessmentId).catch(() => null),
      ]);
      setCandidates(chainsRes.candidates || []);
      setGraphData(graphRes);
      if (chainsRes.candidates?.length > 0) {
        setSelectedCandidate((prev) => prev || chainsRes.candidates[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load attack chain data.");
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    const timer = setTimeout(() => {
      void loadData();
    }, 0);
    return () => clearTimeout(timer);
  }, [loadData]);

  const handlePlanChains = async () => {
    try {
      setPlanning(true);
      setError(null);
      const res = await api.planAttackChains(assessmentId, { max_steps: 5, max_candidates: 25 });
      setCandidates(res.candidates || []);
      if (res.candidates?.length > 0) {
        setSelectedCandidate(res.candidates[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to plan attack chains.");
    } finally {
      setPlanning(false);
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
        const reason = validation.rejection_reasons.join(" ") || "The candidate did not pass validation.";
        setValidationMessage(`Not executed: ${reason}`);
        return;
      }
      setValidationMessage("Candidate passed deterministic validation. Starting the approved execution.");
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

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/10 rounded-lg text-purple-400">
            <GitFork className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Autonomous Multi-Endpoint Attack-Chain Engine</h3>
            <p className="text-xs text-zinc-400">
              Graph-assisted path generation, parameter binding, four-role sequential execution & retesting for {targetUrl}.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handlePlanChains}
            disabled={planning || executing}
            className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${planning ? "animate-spin" : ""}`} />
            {planning ? "Planning Chains..." : "Plan Attack Chains"}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-zinc-800">
        <button
          type="button"
          onClick={() => setActiveTab("candidates")}
          className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition flex items-center gap-1.5 ${
            activeTab === "candidates"
              ? "border-purple-500 text-purple-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <ListOrdered className="w-3.5 h-3.5" />
          <span>Candidate Chains ({candidates.length})</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("graph")}
          className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition flex items-center gap-1.5 ${
            activeTab === "graph"
              ? "border-purple-500 text-purple-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <GitFork className="w-3.5 h-3.5" />
          <span>Endpoint Relationships ({graphData?.relationships_count ?? 0})</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("execution")}
          className={`px-3 py-2 text-xs font-medium border-b-2 -mb-px transition flex items-center gap-1.5 ${
            activeTab === "execution"
              ? "border-purple-500 text-purple-300"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          <Play className="w-3.5 h-3.5" />
          <span>Execution & Evidence</span>
          {executionResult && (
            <span
              className={`px-1.5 py-0.2 rounded text-[10px] ${
                executionResult.is_confirmed
                  ? "bg-rose-500/20 text-rose-300"
                  : "bg-zinc-800 text-zinc-400"
              }`}
            >
              {executionResult.status}
            </span>
          )}
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {validationMessage && (
        <div className="p-3 bg-purple-950/40 border border-purple-500/40 rounded-lg text-xs text-purple-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-purple-400 shrink-0" />
          <span>{validationMessage}</span>
        </div>
      )}

      {/* TAB 1: CANDIDATES */}
      {activeTab === "candidates" && (
        <div className="space-y-4">
          {loading ? (
            <div className="p-8 text-center text-xs text-zinc-400">Loading candidate attack chains...</div>
          ) : candidates.length === 0 ? (
            <div className="p-8 text-center bg-zinc-950/40 border border-zinc-800 rounded-lg space-y-2">
              <p className="text-xs text-zinc-300">No attack-chain candidates planned yet.</p>
              <p className="text-[11px] text-zinc-500">
                Click &quot;Plan Attack Chains&quot; to build multi-endpoint sequences from discovered endpoints.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Candidates List */}
              <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
                {candidates.map((c) => {
                  const isSel = selectedCandidate?.candidate_id === c.candidate_id;
                  return (
                    <div
                      key={c.candidate_id}
                      onClick={() => {
                        setSelectedCandidate(c);
                        setValidationMessage(null);
                      }}
                      className={`p-3 rounded-lg border cursor-pointer transition text-left ${
                        isSel
                          ? "bg-zinc-800/90 border-purple-500 shadow-md ring-1 ring-purple-500/40"
                          : "bg-zinc-950/50 border-zinc-800 hover:border-zinc-700"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-semibold text-xs text-purple-300 font-mono">
                          {c.scenario}
                        </span>
                        <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 text-[10px] font-mono">
                          {c.steps.length} steps
                        </span>
                      </div>
                      <p className="text-[11px] text-zinc-300 line-clamp-2 mb-2">{c.hypothesis}</p>
                      <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono">
                        <span>Risk: {c.risk_score}/100</span>
                        <span>{c.safety_classification}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Selected Candidate Details */}
              <div className="lg:col-span-2 bg-zinc-950/60 border border-zinc-800 rounded-lg p-4 space-y-4">
                {selectedCandidate ? (
                  <>
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                      <div>
                        <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                          {selectedCandidate.chain_name || selectedCandidate.scenario}
                        </h4>
                        <p className="text-[11px] text-zinc-400 font-mono mt-0.5">
                          ID: {selectedCandidate.candidate_id} · Safety: {selectedCandidate.safety_classification}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleExecuteChain(selectedCandidate)}
                        disabled={executing || validating}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition shadow"
                      >
                        <Play className="w-3.5 h-3.5 fill-current" />
                        {validating ? "Validating..." : executing ? "Executing..." : "Validate & Execute Chain"}
                      </button>
                    </div>

                    <div>
                      <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider block mb-1">
                        Risk Hypothesis
                      </span>
                      <p className="text-xs text-zinc-200 leading-relaxed bg-zinc-900/80 p-3 rounded-lg border border-zinc-800/80">
                        {selectedCandidate.hypothesis}
                      </p>
                    </div>

                    <div>
                      <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider block mb-2">
                        Ordered Execution Steps ({selectedCandidate.steps.length})
                      </span>
                      <div className="space-y-2">
                        {selectedCandidate.steps.map((st, i) => (
                          <div
                            key={st.step_id || i}
                            className="p-3 bg-zinc-900 border border-zinc-800 rounded-lg flex items-start gap-3 text-xs"
                          >
                            <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[11px] font-bold shrink-0">
                              #{i + 1}
                            </span>
                            <div className="flex-1 space-y-1">
                              <div className="flex items-center gap-2 font-mono">
                                <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-emerald-400 font-bold text-[10px]">
                                  {st.method}
                                </span>
                                <span className="text-zinc-200">{st.path}</span>
                              </div>
                              <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-400">
                                <span>Role: <strong className="text-zinc-300 font-mono">{st.role || st.testing_role || "user_a"}</strong></span>
                                {st.depends_on_step_ids && st.depends_on_step_ids.length > 0 && (
                                  <span>Depends on: <strong className="text-indigo-300 font-mono">{st.depends_on_step_ids.join(", ")}</strong></span>
                                )}
                              </div>
                              {st.input_bindings && st.input_bindings.length > 0 && (
                                <div className="text-[10px] font-mono text-zinc-500">
                                  Bindings: {st.input_bindings.map((b) => `${b.parameter} ← ${b.source_step_id}.${b.source_field || "id"}`).join(", ")}
                                </div>
                              )}
                            </div>
                            <ChevronRight className="w-4 h-4 text-zinc-600 shrink-0 self-center" />
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="p-8 text-center text-xs text-zinc-500">Select a candidate chain to view steps</div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: ENDPOINT RELATIONSHIPS */}
      {activeTab === "graph" && (
        <div className="space-y-4">
          <div className="p-3 bg-zinc-950/60 border border-zinc-800 rounded-lg flex items-center justify-between text-xs text-zinc-300">
            <span>
              Discovered Nodes: <strong>{graphData?.nodes_count ?? 0}</strong> · Inferred Relationships: <strong>{graphData?.relationships_count ?? 0}</strong>
            </span>
            <span className="text-zinc-500">{graphData?.summary || "Target endpoint graph."}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Discovered Endpoints list */}
            <div className="bg-zinc-950/40 border border-zinc-800 rounded-lg p-3 space-y-2 max-h-[420px] overflow-y-auto">
              <span className="text-xs font-semibold text-zinc-300 block mb-1">Endpoints & Resource Types</span>
              {(graphData?.nodes || []).map((node: EndpointNodeInfo) => (
                <div key={node.endpoint_id} className="p-2.5 bg-zinc-900 border border-zinc-800/80 rounded-md text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-zinc-200">
                      <strong className="text-emerald-400 mr-1.5">{node.method}</strong>{node.path}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400 font-mono">
                      {node.resource_type || "resource"}
                    </span>
                  </div>
                  {node.parameters && node.parameters.length > 0 && (
                    <div className="text-[10px] text-zinc-500 font-mono">
                      Params: {node.parameters.join(", ")}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Relationship Bindings list */}
            <div className="bg-zinc-950/40 border border-zinc-800 rounded-lg p-3 space-y-2 max-h-[420px] overflow-y-auto">
              <span className="text-xs font-semibold text-zinc-300 block mb-1">Inferred Data-Flow & Relationships</span>
              {(graphData?.relationships || []).length === 0 ? (
                <p className="text-xs text-zinc-500 p-4 text-center">No explicit relationships inferred yet.</p>
              ) : (
                (graphData?.relationships || []).map((rel: EndpointRelationshipInfo, idx: number) => (
                  <div key={idx} className="p-2.5 bg-zinc-900 border border-zinc-800/80 rounded-md text-xs space-y-1">
                    <div className="flex items-center gap-1.5 font-mono text-[11px] text-purple-300">
                      <span>{rel.source_endpoint_id}</span>
                      <ArrowRight className="w-3 h-3 text-zinc-500" />
                      <span>{rel.target_endpoint_id}</span>
                    </div>
                    <p className="text-[11px] text-zinc-400 leading-snug">{rel.rationale}</p>
                    <div className="flex items-center justify-between text-[10px] text-zinc-500 font-mono pt-1">
                      <span>Type: {rel.relationship}</span>
                      <span>Confidence: {rel.confidence}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: EXECUTION & EVIDENCE */}
      {activeTab === "execution" && (
        <div className="space-y-4">
          {!executionResult ? (
            <div className="p-12 text-center bg-zinc-950/40 border border-zinc-800 rounded-lg space-y-2">
              <Play className="w-6 h-6 text-zinc-600 mx-auto" />
              <p className="text-xs text-zinc-300">No attack chain execution active.</p>
              <p className="text-[11px] text-zinc-500">
                Go to the Candidate Chains tab and click &quot;Validate & Execute Chain&quot;.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Verdict Header */}
              <div
                className={`p-4 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  executionResult.is_confirmed
                    ? "bg-rose-950/30 border-rose-500/40 text-rose-200"
                    : "bg-zinc-950/60 border-zinc-800 text-zinc-200"
                }`}
              >
                <div className="flex items-start gap-3">
                  {executionResult.is_confirmed ? (
                    <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  ) : (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <h4 className="text-sm font-semibold text-white">
                      {executionResult.chain_name || executionResult.scenario}: {executionResult.status}
                    </h4>
                    <p className="text-xs text-zinc-300 mt-0.5">{executionResult.summary}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-1 rounded text-xs font-mono font-bold border ${
                      executionResult.is_confirmed
                        ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                        : "bg-zinc-800 text-zinc-400 border-zinc-700"
                    }`}
                  >
                    {executionResult.is_confirmed ? "CONFIRMED VULNERABILITY" : "NOT CONFIRMED"}
                  </span>
                </div>
              </div>

              {/* Step By Step Execution Results */}
              <div className="space-y-2">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider block">
                  Sequential Multi-Role Execution Evidence
                </span>
                {executionResult.step_results.map((sr, idx) => (
                  <div
                    key={sr.step_id || idx}
                    className="p-3 bg-zinc-950 border border-zinc-800 rounded-lg space-y-2 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-emerald-400 font-bold text-[10px]">
                          {sr.method}
                        </span>
                        <span className="text-zinc-200 font-semibold">{sr.endpoint_path}</span>
                        <span className="text-zinc-500">as</span>
                        <span className="px-1.5 py-0.2 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 font-bold text-[11px]">
                          {sr.role_used}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-zinc-400">HTTP {sr.status_code}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            sr.verdict.includes("UNAUTHORIZED") || sr.verdict.includes("CONFIRMED")
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                              : "bg-zinc-800 text-zinc-400"
                          }`}
                        >
                          {sr.verdict}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-zinc-400 bg-zinc-900/60 p-2 rounded border border-zinc-850">
                      <div>Expected: <span className="text-zinc-300">{sr.expected_behavior}</span></div>
                      <div>Observed: <span className="text-zinc-300">{sr.actual_behavior}</span></div>
                    </div>

                    {sr.response_excerpt && (
                      <div>
                        <div className="text-[10px] text-zinc-500 mb-0.5">Sanitized Response Excerpt:</div>
                        <pre className="p-2 bg-zinc-900 rounded border border-zinc-800/80 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-24">
                          {sr.response_excerpt}
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Remediation & Retesting */}
              {executionResult.finding_id && (
                <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-lg space-y-3">
                  <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                    <div className="flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-emerald-400" />
                      <span className="text-xs font-semibold text-zinc-200">
                        Remediation &amp; Automated Retesting
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleRetestFinding(executionResult.finding_id!)}
                      disabled={retesting}
                      className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${retesting ? "animate-spin" : ""}`} />
                      {retesting ? "Retesting..." : "Retest Attack Chain"}
                    </button>
                  </div>

                  {retestResult && (
                    <div className="p-3 bg-indigo-950/30 border border-indigo-500/40 rounded-lg text-xs space-y-1">
                      <p className="font-semibold text-indigo-300">Retest Result: {retestResult.status}</p>
                      <p className="text-zinc-300">{retestResult.notes}</p>
                    </div>
                  )}

                  {executionResult.remediation_code_patch && (
                    <pre className="p-3 bg-zinc-900 rounded-lg border border-zinc-800 font-mono text-[11px] text-emerald-300 overflow-x-auto">
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
