"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Users,
  Shield,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  Save,
  RefreshCw,
} from "lucide-react";
import { api } from "@/lib/api";
import type { FourRolesStatusResponse, RoleSessionStatus } from "@/types/assessment";

interface Props {
  onClose?: () => void;
  onRolesUpdated?: (status: FourRolesStatusResponse) => void;
}

export function FourRoleConfigPanel({ onClose, onRolesUpdated }: Props) {
  const [data, setData] = useState<FourRolesStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<string>("user_a");
  const [tokenInput, setTokenInput] = useState<string>("");
  const [userIdInput, setUserIdInput] = useState<string>("");
  const [resourceType, setResourceType] = useState<string>("order");
  const [resourceId, setResourceId] = useState<string>("101");
  const [saving, setSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);

  const fetchRoles = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getRoles();
      setData(res);
      if (onRolesUpdated) onRolesUpdated(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load role status.");
    } finally {
      setLoading(false);
    }
  }, [onRolesUpdated]);

  useEffect(() => {
    const timer = setTimeout(() => {
      void fetchRoles();
    }, 0);
    return () => clearTimeout(timer);
  }, [fetchRoles]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedRole === "anonymous") return;
    try {
      setSaving(true);
      setSaveSuccess(null);
      setError(null);

      const owned_resources: Record<string, string> = {};
      if (resourceType.trim() && resourceId.trim()) {
        owned_resources[resourceType.trim()] = resourceId.trim();
      }

      const res = await api.configureRole({
        role: selectedRole,
        token: tokenInput.trim() || undefined,
        user_id: userIdInput.trim() || undefined,
        owned_resources: Object.keys(owned_resources).length > 0 ? owned_resources : undefined,
      });

      setData(res);
      setSaveSuccess(`Role '${selectedRole}' configuration saved successfully.`);
      setTokenInput("");
      if (onRolesUpdated) onRolesUpdated(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save role configuration.");
    } finally {
      setSaving(false);
    }
  };

  const rolesList: Array<{ id: string; name: string; desc: string }> = [
    { id: "anonymous", name: "Anonymous", desc: "Baseline unauthenticated client. Probes endpoints with zero session tokens." },
    { id: "user_a", name: "User A (Primary)", desc: "Standard authenticated tenant/owner. Seeds legitimate resource ownership." },
    { id: "user_b", name: "User B (Cross-User)", desc: "Secondary authenticated tenant. Used to prove BOLA/IDOR horizontal bypasses." },
    { id: "admin", name: "Admin (Privileged)", desc: "Elevated administrative role. Used to probe BFLA & vertical escalation." },
  ];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Four-Role Testing Configuration</h3>
            <p className="text-xs text-zinc-400">
              Deterministic multi-role access control testing across Anonymous, User A, User B, and Admin.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void fetchRoles()}
            disabled={loading}
            className="p-1.5 rounded-lg border border-zinc-800 hover:bg-zinc-800 text-zinc-400 hover:text-white transition disabled:opacity-50"
            title="Refresh status"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-xs font-medium text-zinc-200 rounded-lg transition"
            >
              Close
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-lg text-xs text-red-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {/* Role Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {rolesList.map((r) => {
          const roleStatus: RoleSessionStatus | undefined = data?.roles?.[r.id];
          const isConfigured = roleStatus?.configured ?? false;
          const isAuthenticated = roleStatus?.authenticated ?? false;
          const isSelected = selectedRole === r.id;

          return (
            <div
              key={r.id}
              onClick={() => {
                setSelectedRole(r.id);
                setSaveSuccess(null);
              }}
              className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                isSelected
                  ? "bg-zinc-800/90 border-indigo-500/80 shadow-md ring-1 ring-indigo-500/40"
                  : "bg-zinc-950/50 border-zinc-800 hover:border-zinc-700"
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-medium text-xs text-zinc-200">{r.name}</span>
                {r.id === "anonymous" ? (
                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] border border-emerald-500/20 font-mono">
                    BASELINE
                  </span>
                ) : isAuthenticated ? (
                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] border border-emerald-500/20 flex items-center gap-1 font-mono">
                    <CheckCircle2 className="w-3 h-3" /> READY
                  </span>
                ) : isConfigured ? (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px] border border-amber-500/20 flex items-center gap-1 font-mono">
                    <AlertCircle className="w-3 h-3" /> INVALID
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 text-[10px] border border-zinc-700 font-mono">
                    UNSET
                  </span>
                )}
              </div>

              <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed mb-2.5">
                {roleStatus?.description || r.desc}
              </p>

              <div className="text-[10px] font-mono text-zinc-400 space-y-0.5 border-t border-zinc-800/80 pt-2">
                <div>User ID: <span className="text-zinc-300">{roleStatus?.user_id || "default"}</span></div>
                <div>Auth Token: <span className="text-zinc-300">{roleStatus?.token_preview || "(none)"}</span></div>
                <div>Owned items: <span className="text-zinc-300">{roleStatus?.owned_resources_count || 0}</span></div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Configuration Form for Selected Role */}
      {selectedRole !== "anonymous" ? (
        <form onSubmit={handleSave} className="bg-zinc-950/60 border border-zinc-800 rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-semibold text-zinc-200 uppercase tracking-wider">
                Configure Credentials for {selectedRole.replace("_", " ").toUpperCase()}
              </span>
            </div>
            <span className="text-[11px] text-zinc-400">
              Tokens are kept in volatile memory and redacted in telemetry.
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Bearer Token / Session Cookie
              </label>
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="eyJhbGciOi... or auth cookie value"
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-xs text-white placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500 font-mono"
              />
              <p className="text-[10px] text-zinc-400 mt-1">
                Leave empty to retain existing environment / default token.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Account / User Identifier
              </label>
              <input
                type="text"
                value={userIdInput}
                onChange={(e) => setUserIdInput(e.target.value)}
                placeholder={selectedRole === "user_a" ? "user_a_1001" : selectedRole === "user_b" ? "user_b_2002" : "admin_001"}
                className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-xs text-white placeholder-zinc-500 focus:outline-hidden focus:border-indigo-500 font-mono"
              />
              <p className="text-[10px] text-zinc-400 mt-1">
                Canonical identity used for ownership baselines and access differential proofs.
              </p>
            </div>
          </div>

          <div className="border-t border-zinc-800/80 pt-3">
            <label className="block text-xs font-medium text-zinc-300 mb-1.5">
              Register Test Resource Ownership (BOLA / IDOR baseline)
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <span className="block text-[11px] text-zinc-400 mb-1">Resource Type</span>
                <input
                  type="text"
                  value={resourceType}
                  onChange={(e) => setResourceType(e.target.value)}
                  placeholder="order, basket, profile, invoice"
                  className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-zinc-500 font-mono"
                />
              </div>
              <div>
                <span className="block text-[11px] text-zinc-400 mb-1">Resource ID</span>
                <input
                  type="text"
                  value={resourceId}
                  onChange={(e) => setResourceId(e.target.value)}
                  placeholder="101, basket_uuid_a, 42"
                  className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-zinc-500 font-mono"
                />
              </div>
            </div>
            <p className="text-[10px] text-zinc-400 mt-1.5">
              If {selectedRole} owns resource ID {resourceId || "101"}, User B accessing it confirms a horizontal BOLA vulnerability.
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 transition"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "Saving..." : "Save Role Credentials"}
            </button>
          </div>
        </form>
      ) : (
        <div className="p-4 bg-zinc-950/60 border border-zinc-800 rounded-lg text-xs text-zinc-400 flex items-start gap-2.5">
          <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-zinc-200">Anonymous Role is automatically configured</p>
            <p className="mt-0.5 text-zinc-400">
              The Anonymous baseline sends requests without credentials to detect Missing Authentication and verify whether endpoints require session verification.
            </p>
          </div>
        </div>
      )}

      {/* Summary Footer */}
      <div className="p-3 bg-zinc-950 border border-zinc-800/80 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-zinc-400" />
          <span className="text-zinc-300 font-medium">Readiness Status:</span>
          <span className="text-zinc-400">{data?.summary || "Checking active session manager..."}</span>
        </div>
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className={data?.four_role_ready ? "text-emerald-400" : "text-amber-400"}>
            {data?.four_role_ready ? "✓ 4-Role Ready" : "⚠ Partial Roles"}
          </span>
          <span className={data?.anonymous_baseline_ready ? "text-emerald-400" : "text-zinc-500"}>
            ✓ Anonymous Active
          </span>
        </div>
      </div>
    </div>
  );
}
