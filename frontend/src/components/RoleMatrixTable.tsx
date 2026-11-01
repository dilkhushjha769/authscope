"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Users,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  MinusCircle,
  HelpCircle,
  RefreshCw,
  Search,
} from "lucide-react";
import { api } from "@/lib/api";
import type { RoleMatrixItem } from "@/types/assessment";

interface Props {
  assessmentId: string;
}

export function RoleMatrixTable({ assessmentId }: Props) {
  const [matrix, setMatrix] = useState<RoleMatrixItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState<string>("");
  const [filter, setFilter] = useState<"ALL" | "CONFIRMED" | "TESTED">("ALL");

  const loadMatrix = useCallback(async () => {
    if (!assessmentId) return;
    try {
      setLoading(true);
      setError(null);
      const res = await api.getRoleMatrix(assessmentId);
      setMatrix(res.matrix || []);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load role matrix.");
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    const timer = setTimeout(() => {
      void loadMatrix();
    }, 0);
    return () => clearTimeout(timer);
  }, [loadMatrix]);

  const filteredMatrix = matrix.filter((item) => {
    const matchesSearch =
      item.endpoint.toLowerCase().includes(search.toLowerCase()) ||
      item.method.toLowerCase().includes(search.toLowerCase()) ||
      item.category.toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (filter === "CONFIRMED") return item.has_confirmed_vulnerability;
    if (filter === "TESTED") return item.test_status === "TESTED";
    return true;
  });

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-2xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Four-Role Authorization Matrix</h3>
            <p className="text-xs text-zinc-400">
              Endpoint-level comparative access verdicts across Anonymous, User A, User B, and Admin.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => void loadMatrix()}
          disabled={loading}
          className="p-1.5 self-start sm:self-center rounded-lg border border-zinc-800 hover:bg-zinc-800 text-zinc-400 hover:text-white transition disabled:opacity-50"
          title="Refresh matrix"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2.5">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search endpoint or category..."
            className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setFilter("ALL")}
            className={`px-2.5 py-1 rounded text-xs transition ${
              filter === "ALL" ? "bg-zinc-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            All ({matrix.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("CONFIRMED")}
            className={`px-2.5 py-1 rounded text-xs transition ${
              filter === "CONFIRMED" ? "bg-rose-950/60 text-rose-300 border border-rose-800/60 font-medium" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Confirmed Bugs ({matrix.filter((m) => m.has_confirmed_vulnerability).length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("TESTED")}
            className={`px-2.5 py-1 rounded text-xs transition ${
              filter === "TESTED" ? "bg-zinc-800 text-white font-medium" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Tested ({matrix.filter((m) => m.test_status === "TESTED").length})
          </button>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="p-8 text-center text-xs text-zinc-500">Loading four-role matrix...</div>
      ) : filteredMatrix.length === 0 ? (
        <div className="p-8 text-center bg-zinc-950/40 border border-zinc-800 rounded-lg text-xs text-zinc-500">
          No endpoints match the current filter or search criteria.
        </div>
      ) : (
        <div className="overflow-x-auto border border-zinc-800 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950/80 border-b border-zinc-800 text-[11px] font-mono text-zinc-400 uppercase">
              <tr>
                <th className="py-2 px-3">Method &amp; Endpoint</th>
                <th className="py-2 px-3">Auth Required</th>
                <th className="py-2 px-3">Test Status</th>
                <th className="py-2 px-3">Access Verdict</th>
                <th className="py-2 px-3">Comparative Outcome</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-mono text-[11px]">
              {filteredMatrix.map((row, idx) => (
                <tr key={idx} className="hover:bg-zinc-850/40 transition">
                  <td className="py-2.5 px-3">
                    <span className="font-bold text-emerald-400 mr-2">{row.method}</span>
                    <span className="text-zinc-200">{row.endpoint}</span>
                    {row.category && (
                      <span className="ml-2 text-[10px] text-zinc-500 uppercase">({row.category})</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-zinc-400">
                    {row.requires_auth ? "Yes (Protected)" : "No (Public)"}
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] ${
                        row.test_status === "TESTED"
                          ? "bg-indigo-500/10 text-indigo-300 border border-indigo-500/30"
                          : "bg-zinc-800 text-zinc-400"
                      }`}
                    >
                      {row.test_status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    {row.verdict ? (
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] ${
                          row.verdict.includes("DENIED") || row.verdict.includes("ALLOWED")
                            ? "text-emerald-300 bg-emerald-950/30 border border-emerald-800/40"
                            : row.verdict.includes("SUSPICIOUS") || row.verdict.includes("UNAUTHORIZED")
                            ? "text-amber-300 bg-amber-950/30 border border-amber-800/40"
                            : "text-zinc-400"
                        }`}
                      >
                        {row.verdict}
                      </span>
                    ) : (
                      <span className="text-zinc-600">—</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    {row.has_confirmed_vulnerability ? (
                      <span className="inline-flex items-center gap-1 text-rose-300 font-bold bg-rose-950/40 border border-rose-800/50 px-2 py-0.5 rounded text-[10px]">
                        <ShieldAlert className="w-3 h-3 text-rose-400" />
                        CONFIRMED BUG ({row.severity || "HIGH"})
                      </span>
                    ) : row.test_status === "TESTED" ? (
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-[10px]">
                        <CheckCircle2 className="w-3 h-3" />
                        Baseline Enforced
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-zinc-500 text-[10px]">
                        <MinusCircle className="w-3 h-3" />
                        Unchecked
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 text-[11px] text-zinc-500 pt-1">
        <span className="flex items-center gap-1">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Legitimate / Denied
        </span>
        <span className="flex items-center gap-1">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> Suspicious Discrepancy
        </span>
        <span className="flex items-center gap-1">
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> Confirmed Multi-Role Bypass
        </span>
        <span className="flex items-center gap-1">
          <HelpCircle className="w-3.5 h-3.5 text-zinc-500" /> Untested / Baseline Only
        </span>
      </div>
    </div>
  );
}
