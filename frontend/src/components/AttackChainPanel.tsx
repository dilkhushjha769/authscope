"use client";

import React, { useState, useEffect } from "react";
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
}

export function AttackChainPanel({ assessmentId, targetUrl, onFindingConfirmed }: Props) {
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

  const loadData = async () => {
    if (!assessmentId) return;
    try {
      setError(null);
      const [chainsRes, graphRes] = await Promise.all([
        api.getAttackChains(assessmentId).catch(() => ({ candidates: [] })),
        api.getEndpointGraph(assessmentId).catch(() => null),
      ]);
      setCandidates(chainsRes.candidates || []);
      setGraphData(graphRes);
      if (chainsRes.candidates?.length > 0 && !selectedCandidate) {
        setSelectedCandidate(chainsRes.candidates[0]);
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
              Graph-assisted path generation, parameter binding, four-role sequential execution & retesting.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Tab Selector */}
          <div className="flex bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs">
            <button
              onClick={() => setActiveTab("candidates")}
              className={`px-3 py-1 rounded-md transition ${
                activeTab === "candidates" ? "bg-zinc-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Candidates ({candidates.length})
            </button>
            <button
              onClick={() => setActiveTab("graph")}
              className={`px-3 py-1 rounded-md transition ${
                activeTab === "graph" ? "bg-zinc-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Graph ({graphData?.nodes_count || 0})
            </button>
            <button
              onClick={() => setActiveTab("execution")}
              className={`px-3 py-1 rounded-md transition ${
                activeTab === "execution" ? "bg-zinc-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Live Execution
            </button>
          </div>

          <button
            onClick={handlePlanChains}
            disabled={planning}
            className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 shadow-lg shadow-purple-600/20 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${planning ? "animate-spin" : ""}`} />
            {planning ? "Planning..." : "Plan Chains"}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* TAB 1: Candidates List & Inspector */}
      {activeTab === "candidates" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Candidate Cards List */}
          <div className="lg:col-span-5 space-y-2.5 max-h-[500px] overflow-y-auto pr-1">
            {candidates.length === 0 ? (
              <div className="p-8 text-center bg-zinc-950/40 border border-dashed border-zinc-800 rounded-xl text-zinc-500 text-xs">
                <ListOrdered className="w-8 h-8 mx-auto mb-2 opacity-40 text-purple-400" />
                <p>No attack-chain candidates planned yet.</p>
                <p className="mt-1 text-[11px] text-zinc-600">
                  Click &apos;Plan Chains&apos; to build dependency-driven attack paths across discovered routes.
                </p>
              </div>
            ) : (
              candidates.map((c) => {
                const isSelected = selectedCandidate?.candidate_id === c.candidate_id;
                return (
                  <div
                    key={c.candidate_id}
                    onClick={() => setSelectedCandidate(c)}
                    className={`p-3.5 rounded-lg border text-left cursor-pointer transition ${
                      isSelected
                        ? "bg-purple-950/20 border-purple-500/60 ring-1 ring-purple-500/30"
                        : "bg-zinc-950/40 border-zinc-800 hover:border-zinc-700"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                        {c.scenario}
                      </span>
                      <span className="text-[11px] text-zinc-400 font-mono">
                        {c.steps.length} Steps • Risk Score: {c.risk_score}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-zinc-200 line-clamp-1">
                      {c.chain_name || `${c.scenario} Chain (${c.candidate_id.slice(0, 8)})`}
                    </h4>

                    {/* Step path preview */}
                    <div className="mt-2 text-[11px] font-mono text-zinc-400 flex items-center gap-1.5 overflow-hidden">
                      {c.steps.map((st, idx) => (
                        <React.Fragment key={st.step_id || idx}>
                          <span className="px-1.5 py-0.5 bg-zinc-900 rounded text-zinc-300 text-[10px] truncate max-w-[120px]">
                            {st.method} {st.path}
                          </span>
                          {idx < c.steps.length - 1 && <ChevronRight className="w-3 h-3 text-zinc-600 shrink-0" />}
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
              <div className="p-4 bg-zinc-950/70 border border-zinc-800 rounded-xl space-y-4">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div>
                    <h4 className="text-sm font-semibold text-white">
                      {selectedCandidate.chain_name || selectedCandidate.scenario}
                    </h4>
                    <p className="text-[11px] font-mono text-zinc-500">ID: {selectedCandidate.candidate_id}</p>
                  </div>
                  <button
                    onClick={() => handleExecuteChain(selectedCandidate)}
                    disabled={executing || validating}
                    className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 shadow-lg shadow-emerald-600/20 transition"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {validating ? "Validating..." : executing ? "Executing Safe Chain..." : "Validate & Execute"}
                  </button>
                </div>
                {validationMessage && (
                  <p className="text-xs text-zinc-300" role="status">{validationMessage}</p>
                )}

                {/* Risk Hypothesis */}
                <div>
                  <h5 className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider mb-1">
                    Risk Hypothesis
                  </h5>
                  <p className="text-xs text-zinc-300 bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800/80">
                    {selectedCandidate.hypothesis}
                  </p>
                </div>

                {/* Step Sequence Details */}
                <div>
                  <h5 className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider mb-2">
                    Ordered Step Sequence ({selectedCandidate.steps.length} Steps)
                  </h5>
                  <div className="space-y-2">
                    {selectedCandidate.steps.map((st, idx) => (
                      <div
                        key={st.step_id || idx}
                        className="p-3 bg-zinc-900/50 border border-zinc-800 rounded-lg flex items-start gap-3 text-xs"
                      >
                        <span className="w-5 h-5 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-mono font-bold text-[10px] shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <div className="flex-1 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-white font-semibold">
                              {st.method} {st.path}
                            </span>
                            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                              Role: {st.role || (idx === 0 ? "user_a" : "user_b")}
                            </span>
                          </div>
                          {st.input_bindings && st.input_bindings.length > 0 && (
                            <p className="text-[11px] font-mono text-purple-400">
                              Parameter Binding: {st.input_bindings.map((b) => `${b.parameter} $\\leftarrow$ ${b.source_step_id}`).join(", ")}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center bg-zinc-950/40 border border-zinc-800 rounded-xl text-zinc-500 text-xs">
                Select a candidate attack chain from the list to inspect details.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Endpoint Relationship Graph */}
      {activeTab === "graph" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span>
              Graph Topology: {graphData?.nodes_count || 0} Endpoints • {graphData?.relationships_count || 0} Relationships
            </span>
            <span className="text-[11px] font-mono text-purple-400">Target: {targetUrl}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[500px] overflow-y-auto">
            {graphData?.relationships?.map((rel, idx) => (
              <div key={idx} className="p-3 bg-zinc-950/60 border border-zinc-800 rounded-lg space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 font-semibold">
                    {rel.relationship}
                  </span>
                  <span className="text-[10px] text-zinc-500 font-mono">Confidence: {rel.confidence}</span>
                </div>
                <div className="flex items-center gap-2 font-mono text-zinc-300 text-[11px]">
                  <span className="truncate max-w-[140px] text-zinc-400">{rel.source_endpoint_id.slice(0, 8)}...</span>
                  <ArrowRight className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                  <span className="truncate max-w-[140px] text-indigo-300">{rel.target_endpoint_id.slice(0, 8)}...</span>
                </div>
                <p className="text-[11px] text-zinc-400">{rel.rationale}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: Execution Timeline & Evidence */}
      {activeTab === "execution" && (
        <div className="space-y-5">
          {executing && (
            <div className="p-8 text-center bg-zinc-950/60 border border-zinc-800 rounded-xl space-y-3">
              <RefreshCw className="w-8 h-8 text-purple-400 animate-spin mx-auto" />
              <p className="text-sm font-semibold text-white">Executing Multi-Step Attack Chain Safely...</p>
              <p className="text-xs text-zinc-400">
                Applying non-destructive request constraints, dynamic parameter binding, and cross-role authorization checks.
              </p>
            </div>
          )}

          {!executing && !executionResult && (
            <div className="p-8 text-center bg-zinc-950/40 border border-dashed border-zinc-800 rounded-xl text-zinc-500 text-xs">
              <Play className="w-8 h-8 mx-auto mb-2 opacity-40 text-emerald-400" />
              <p>No chain has been executed yet.</p>
              <p className="mt-1 text-[11px] text-zinc-600">
                Select a candidate from the &apos;Candidates&apos; tab and click &apos;Execute Chain&apos; to run.
              </p>
            </div>
          )}

          {executionResult && (
            <div className="space-y-5">
              {/* Outcome Banner */}
              <div
                className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  executionResult.is_confirmed
                    ? "bg-rose-950/20 border-rose-500/40"
                    : "bg-emerald-950/20 border-emerald-500/40"
                }`}
              >
                <div className="flex items-center gap-3">
                  {executionResult.is_confirmed ? (
                    <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                  )}
                  <div>
                    <h4 className="text-sm font-semibold text-white">
                      Status: {executionResult.status} (
                      {executionResult.is_confirmed ? "Confirmed Vulnerability" : "Not Vulnerable"})
                    </h4>
                    <p className="text-xs text-zinc-300">{executionResult.summary}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                    Severity: {executionResult.severity}
                  </span>
                  <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                    Confidence: {executionResult.confidence}
                  </span>
                </div>
              </div>

              {/* Step Execution Telemetry */}
              <div className="space-y-3">
                <h5 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                  Step-by-Step Execution Telemetry ({executionResult.step_results.length} Executed)
                </h5>
                <div className="space-y-2.5">
                  {executionResult.step_results.map((st, idx) => {
                    const isViolation = st.verdict === "CONFIRMED_UNAUTHORIZED_ACCESS";
                    return (
                      <div
                        key={st.step_id || idx}
                        className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                          isViolation
                            ? "bg-rose-950/20 border-rose-500/40 ring-1 ring-rose-500/20"
                            : "bg-zinc-950/60 border-zinc-800"
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-zinc-400">Step {idx + 1}:</span>
                            <span className="font-mono text-white font-semibold">
                              {st.method} {st.endpoint_path}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 uppercase">
                              Role: {st.role_used}
                            </span>
                            <span
                              className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold ${
                                st.status_code >= 200 && st.status_code < 300
                                  ? "bg-emerald-500/10 text-emerald-400"
                                  : "bg-zinc-800 text-zinc-400"
                              }`}
                            >
                              HTTP {st.status_code}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-zinc-400">
                          <span>Verdict: <strong className={isViolation ? "text-rose-400" : "text-emerald-400"}>{st.verdict}</strong></span>
                          {st.evidence_sha256 && (
                            <span className="font-mono text-[10px] text-purple-400">
                              SHA-256: {st.evidence_sha256.slice(0, 16)}...
                            </span>
                          )}
                        </div>

                        <p className="text-[11px] text-zinc-300 bg-zinc-900/60 p-2 rounded border border-zinc-800/80">
                          {st.actual_behavior}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Remediation & Retesting Controls */}
              {executionResult.finding_id && (
                <div className="p-4 bg-zinc-950/80 border border-zinc-800 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <h5 className="text-xs font-semibold text-zinc-200 flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-emerald-400" />
                      Remediation Guidance & Automated Retesting
                    </h5>
                    <button
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

