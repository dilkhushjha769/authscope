"use client";

import React, { useState, useEffect } from "react";
import {
  Users,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  Save,
  RefreshCw,
} from "lucide-react";
import { api } from "@/api/client";
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

  const fetchRoles = async () => {
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
  };

  useEffect(() => {
    const timer = window.setTimeout(() => void fetchRoles(), 0);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedRole === "anonymous") return;
    try {
      setSaving(true);
      setSaveSuccess(null);
      setError(null);
      const owned = resourceType && resourceId ? { [resourceType.trim()]: resourceId.trim() } : undefined;
      const res = await api.configureRole({
        role: selectedRole,
        token: tokenInput.trim() || undefined,
        user_id: userIdInput.trim() || undefined,
        owned_resources: owned,
      });
      setData(res);
      if (onRolesUpdated) onRolesUpdated(res);
      setSaveSuccess(`Role '${selectedRole.toUpperCase()}' successfully updated!`);
      setTokenInput("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update role configuration.");
    } finally {
      setSaving(false);
    }
  };

  const roles = data?.roles || {};

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/10 rounded-lg text-indigo-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Four-Role Authorization Testing</h3>
            <p className="text-xs text-zinc-400">
              Configure independent identity sessions for differential authorization analysis.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void fetchRoles()}
            disabled={loading}
            className="p-1.5 text-zinc-400 hover:text-white rounded-lg hover:bg-zinc-800 transition"
            title="Refresh Role Readiness"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="px-2.5 py-1 text-xs text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg"
            >
              Close
            </button>
          )}
        </div>
      </div>

      {/* Global Readiness Banner */}
      {data && (
        <div className="p-3 bg-zinc-950/60 rounded-lg border border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                data.four_role_ready
                  ? "bg-emerald-500 ring-4 ring-emerald-500/20"
                  : data.multi_role_ready
                  ? "bg-amber-500 ring-4 ring-amber-500/20"
                  : "bg-rose-500 ring-4 ring-rose-500/20"
              }`}
            />
            <div>
              <p className="text-xs font-medium text-zinc-200">
                {data.four_role_ready
                  ? "Four-Role System Ready (Anonymous, User A, User B, Admin)"
                  : data.multi_role_ready
                  ? "Two-User Testing Ready (User A, User B)"
                  : "Authentication Required for Multi-Role Testing"}
              </p>
              <p className="text-[11px] text-zinc-400">{data.summary}</p>
            </div>
          </div>
          <div className="flex gap-1.5">
            <span
              className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                data.multi_role_ready ? "bg-emerald-500/10 text-emerald-400" : "bg-zinc-800 text-zinc-500"
              }`}
            >
              BOLA Ready
            </span>
            <span
              className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                data.four_role_ready ? "bg-indigo-500/10 text-indigo-400" : "bg-zinc-800 text-zinc-500"
              }`}
            >
              BFLA Ready
            </span>
          </div>
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {/* Role Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {(["anonymous", "user_a", "user_b", "admin"] as const).map((r) => {
          const roleInfo: RoleSessionStatus | undefined = roles[r];
          const isSelected = selectedRole === r;
          const isAuth = roleInfo?.authenticated ?? false;
          const isAnon = r === "anonymous";

          return (
            <div
              key={r}
              onClick={() => !isAnon && setSelectedRole(r)}
              className={`p-3.5 rounded-lg border transition text-left ${
                isAnon
                  ? "bg-zinc-950/40 border-zinc-800/80 cursor-default"
                  : isSelected
                  ? "bg-indigo-950/20 border-indigo-500/60 ring-1 ring-indigo-500/30 cursor-pointer"
                  : "bg-zinc-950/40 border-zinc-800 hover:border-zinc-700 cursor-pointer"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
                  {r.replace("_", " ")}
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full font-mono ${
                    isAnon
                      ? "bg-zinc-800 text-zinc-400"
                      : isAuth
                      ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                      : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                  }`}
                >
                  {isAnon ? "BASELINE" : isAuth ? "AUTHENTICATED" : "NOT SET"}
                </span>
              </div>

              <p className="text-[11px] text-zinc-400 line-clamp-2 mb-2.5">
                {roleInfo?.description || "Testing role definition."}
              </p>

              <div className="space-y-1 text-[11px] font-mono border-t border-zinc-800/60 pt-2 text-zinc-400">
                <div className="flex justify-between">
                  <span>User ID:</span>
                  <span className="text-zinc-300 font-semibold">{roleInfo?.user_id || (isAnon ? "None" : "—")}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span>Token:</span>
                  <span className="text-zinc-300 truncate max-w-[110px]">
                    {roleInfo?.token_preview || (isAnon ? "None" : "Not configured")}
                  </span>
                </div>
                {!isAnon && (
                  <div className="flex justify-between">
                    <span>Owned Items:</span>
                    <span className="text-zinc-300">{roleInfo?.owned_resources_count || 0}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Role Configuration Form */}
      {selectedRole !== "anonymous" && (
        <form onSubmit={handleSave} className="p-4 bg-zinc-950/70 rounded-xl border border-zinc-800 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-zinc-200 flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-indigo-400" />
              Configure Credentials for {selectedRole.toUpperCase().replace("_", " ")}
            </h4>
            <span className="text-[10px] text-zinc-500">
              Tokens are stored securely in memory. Raw credentials are never logged.
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Bearer Token / JWT or Session Token
              </label>
              <input
                type="password"
                placeholder="eyJhbGciOiJIUzI1NiJ9..."
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                User ID / Account Number (e.g. 101)
              </label>
              <input
                type="text"
                placeholder="101"
                value={userIdInput}
                onChange={(e) => setUserIdInput(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Owned Resource Type (for BOLA ownership baseline)
              </label>
              <input
                type="text"
                placeholder="order, basket, profile"
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-zinc-400 mb-1">
                Owned Resource ID
              </label>
              <input
                type="text"
                placeholder="101"
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                className="w-full px-3 py-1.5 text-xs bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg flex items-center gap-1.5 shadow-lg shadow-indigo-600/20 transition"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? "Saving..." : "Save Role Configuration"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}

