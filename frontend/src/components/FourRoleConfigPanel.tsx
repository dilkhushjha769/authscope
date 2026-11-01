"use client";

import React, { useState, useEffect } from "react";
import {
  Users,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  Save,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  X,
  Lock,
} from "lucide-react";
import { api } from "@/api/client";
import type { FourRolesStatusResponse, RoleSessionStatus } from "@/types/assessment";

interface Props {
  onClose?: () => void;
  onRolesUpdated?: (status: FourRolesStatusResponse) => void;
}

const ROLE_DEFAULTS: Record<
  string,
  { label: string; badge: string; userId: string; resourceType: string; resourceId: string }
> = {
  anonymous: {
    label: "Anonymous",
    badge: "Unauthenticated caller",
    userId: "None",
    resourceType: "",
    resourceId: "",
  },
  user_a: {
    label: "User A (Owner)",
    badge: "Primary resource owner",
    userId: "101",
    resourceType: "basket",
    resourceId: "101",
  },
  user_b: {
    label: "User B (Peer)",
    badge: "Cross-tenant test user",
    userId: "102",
    resourceType: "basket",
    resourceId: "102",
  },
  admin: {
    label: "Admin",
    badge: "Privileged role baseline",
    userId: "1",
    resourceType: "user",
    resourceId: "1",
  },
};

export function FourRoleConfigPanel({ onClose, onRolesUpdated }: Props) {
  const [data, setData] = useState<FourRolesStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedRole, setSelectedRole] = useState<string>("user_a");
  const [tokenInput, setTokenInput] = useState<string>("");
  const [userIdInput, setUserIdInput] = useState<string>("101");
  const [resourceType, setResourceType] = useState<string>("basket");
  const [resourceId, setResourceId] = useState<string>("101");
  const [saving, setSaving] = useState<boolean>(false);
  const [quickConfiguring, setQuickConfiguring] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);

  const syncFormWithRole = (roleKey: string, rolesMap?: Record<string, RoleSessionStatus>) => {
    const defaults = ROLE_DEFAULTS[roleKey] || ROLE_DEFAULTS.user_a;
    const existing = rolesMap?.[roleKey];
    setUserIdInput(existing?.user_id || defaults.userId);
    const existingOwnedEntries = existing?.owned_resources
      ? Object.entries(existing.owned_resources)
      : [];
    if (existingOwnedEntries.length > 0 && existingOwnedEntries[0][1]?.length > 0) {
      setResourceType(existingOwnedEntries[0][0]);
      setResourceId(existingOwnedEntries[0][1][0]);
    } else {
      setResourceType(defaults.resourceType);
      setResourceId(defaults.resourceId);
    }
    setTokenInput("");
  };

  const fetchRoles = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getRoles();
      setData(res);
      syncFormWithRole(selectedRole, res.roles);
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

  const handleSelectRole = (roleKey: string) => {
    if (roleKey === "anonymous") return;
    setSelectedRole(roleKey);
    setSaveSuccess(null);
    setError(null);
    syncFormWithRole(roleKey, data?.roles);
  };

  const handleGenerateToken = () => {
    const uid = userIdInput.trim() || ROLE_DEFAULTS[selectedRole]?.userId || "101";
    setTokenInput(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${selectedRole}_uid_${uid}_session`);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedRole === "anonymous") return;
    try {
      setSaving(true);
      setSaveSuccess(null);
      setError(null);
      const defaults = ROLE_DEFAULTS[selectedRole] || ROLE_DEFAULTS.user_a;
      const effectiveUid = userIdInput.trim() || defaults.userId;
      const effectiveToken =
        tokenInput.trim() ||
        (data?.roles?.[selectedRole]?.authenticated
          ? undefined
          : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${selectedRole}_uid_${effectiveUid}_session`);

      const owned =
        resourceType.trim() && resourceId.trim()
          ? { [resourceType.trim()]: resourceId.trim() }
          : undefined;

      const res = await api.configureRole({
        role: selectedRole,
        token: effectiveToken,
        user_id: effectiveUid,
        owned_resources: owned,
      });
      setData(res);
      if (onRolesUpdated) onRolesUpdated(res);
      setSaveSuccess(
        `${ROLE_DEFAULTS[selectedRole]?.label || selectedRole.toUpperCase()} session credentials & ownership saved.`
      );
      setTokenInput("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update role configuration.");
    } finally {
      setSaving(false);
    }
  };

  const handleQuickConfigureAll = async () => {
    try {
      setQuickConfiguring(true);
      setError(null);
      setSaveSuccess(null);

      await api.configureRole({
        role: "user_a",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_a_uid_101_session",
        user_id: "101",
        owned_resources: { basket: "101", user: "101", card: "101", address: "101", order: "101" },
      });
      await api.configureRole({
        role: "user_b",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_b_uid_102_session",
        user_id: "102",
        owned_resources: { basket: "102", user: "102", order: "102" },
      });
      const res = await api.configureRole({
        role: "admin",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin_uid_1_session",
        user_id: "1",
        owned_resources: { user: "1" },
      });

      setData(res);
      syncFormWithRole(selectedRole, res.roles);
      if (onRolesUpdated) onRolesUpdated(res);
      setSaveSuccess("All 4 roles (Anonymous, User A, User B, Admin) are now configured and ready for BOLA & BFLA testing.");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to quick-configure roles.");
    } finally {
      setQuickConfiguring(false);
    }
  };

  const roles = data?.roles || {};

  return (
    <div className="text-[var(--text)] space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--line-subtle)] pb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[var(--panel)] border border-[var(--line)] text-[#86efac]">
            <Users className="w-4 h-4" />
          </div>
          <div>
            <h3 className="serif-heading text-base text-[var(--text)]">
              Four-Role Authorization Testing
            </h3>
            <p className="text-xs text-[var(--muted)]">
              Configure independent identity sessions (Anonymous, User A, User B, Admin) to verify access boundaries.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            type="button"
            onClick={() => void handleQuickConfigureAll()}
            disabled={quickConfiguring || loading}
            className="px-2.5 py-1 text-xs font-medium rounded-md bg-[#2d2d2a] hover:bg-[#373733] border border-[#41413d] hover:border-[#5fa37f] text-[#86efac] flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
            title="Automatically populate test credentials and owned resources for all 4 personas"
          >
            <Sparkles className="w-3 h-3 text-[#86efac]" />
            <span>{quickConfiguring ? "Configuring..." : "Quick-Configure All 4 Roles"}</span>
          </button>

          <button
            type="button"
            onClick={() => void fetchRoles()}
            disabled={loading}
            className="p-1.5 text-[var(--muted)] hover:text-[var(--text)] rounded-lg bg-[var(--panel)] border border-[var(--line)] hover:bg-[var(--surface-hover)] transition cursor-pointer"
            title="Refresh Role Readiness"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          </button>

          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs text-[var(--muted)] hover:text-[var(--text)] bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg flex items-center gap-1 transition cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
              <span>Close</span>
            </button>
          )}
        </div>
      </div>

      {/* Global Readiness Banner */}
      {data && (
        <div className="p-3.5 bg-[var(--sidebar)] rounded-xl border border-[var(--line)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span
              className={`w-2.5 h-2.5 rounded-full shrink-0 ${
                data.four_role_ready
                  ? "bg-[#5fa37f] ring-4 ring-[#5fa37f]/20"
                  : data.multi_role_ready
                  ? "bg-[#c5aa54] ring-4 ring-[#c5aa54]/20"
                  : "bg-[#d2675f] ring-4 ring-[#d2675f]/20"
              }`}
            />
            <div>
              <p className="text-xs font-semibold text-[var(--text)]">
                {data.four_role_ready
                  ? "All Four Testing Personas Ready (Anonymous, User A, User B, Admin)"
                  : data.multi_role_ready
                  ? "Horizontal BOLA Testing Ready (User A & User B Configured)"
                  : "Session Credentials Needed for Multi-Role Testing"}
              </p>
              <p className="text-[11px] text-[var(--muted)] mt-0.5">{data.summary}</p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <span
              className={`text-[11px] px-2.5 py-0.5 rounded-full font-medium border flex items-center gap-1 ${
                data.multi_role_ready
                  ? "bg-[#132c1e] text-[#86efac] border-[#2b6443]"
                  : "bg-[var(--panel)] text-[var(--faint)] border-[var(--line)]"
              }`}
            >
              <ShieldCheck className="w-3 h-3 text-[#86efac]" />
              BOLA Ready
            </span>
            <span
              className={`text-[11px] px-2.5 py-0.5 rounded-full font-medium border flex items-center gap-1 ${
                data.four_role_ready
                  ? "bg-[#132c1e] text-[#86efac] border-[#2b6443]"
                  : "bg-[var(--panel)] text-[var(--faint)] border-[var(--line)]"
              }`}
            >
              <ShieldCheck className="w-3 h-3 text-[#86efac]" />
              BFLA Ready
            </span>
          </div>
        </div>
      )}

      {error && (
        <div className="p-3 bg-[#d2675f]/12 border border-[#d2675f]/35 rounded-lg text-[#d2675f] text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3 bg-[#5fa37f]/12 border border-[#5fa37f]/35 rounded-lg text-[#5fa37f] text-xs flex items-center gap-2">
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
          const meta = ROLE_DEFAULTS[r];
          const ownedMap = roleInfo?.owned_resources || {};
          const ownedSummary = Object.entries(ownedMap)
            .flatMap(([k, ids]) => ids.map((id) => `${k}:${id}`))
            .slice(0, 3)
            .join(", ");

          return (
            <div
              key={r}
              onClick={() => handleSelectRole(r)}
              className={`p-3.5 rounded-xl border transition text-left flex flex-col justify-between ${
                isAnon
                  ? "bg-[var(--sidebar)] border-[var(--line-subtle)] opacity-90 cursor-default"
                  : isSelected
                  ? "bg-[var(--panel)] border-[#5fa37f] ring-1 ring-[#5fa37f]/35 cursor-pointer"
                  : "bg-[var(--sidebar)] border-[var(--line)] hover:border-[var(--muted)] hover:bg-[var(--panel)] cursor-pointer"
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-[var(--text)]">
                    {r.replace("_", " ")}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-medium border ${
                      isAnon
                        ? "bg-[#262624] text-[#d0cec8] border-[#41413d]"
                        : isAuth
                        ? "bg-[#132c1e] text-[#86efac] border-[#2b6443]"
                        : "bg-[#2f2410] text-[#fde047] border-[#5d491f]"
                    }`}
                  >
                    {isAnon ? "BASELINE" : isAuth ? "AUTHENTICATED" : "NOT SET"}
                  </span>
                </div>

                <p className="text-[11px] text-[var(--muted)] line-clamp-2 mb-3 leading-relaxed">
                  {roleInfo?.description || meta?.badge}
                </p>
              </div>

              <div className="space-y-1.5 text-[11px] font-mono border-t border-[var(--line-subtle)] pt-2.5 text-[var(--muted)]">
                <div className="flex justify-between">
                  <span>User ID:</span>
                  <span className="text-[var(--text)] font-semibold">
                    {roleInfo?.user_id || (isAnon ? "None" : "—")}
                  </span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span>Token:</span>
                  <span className="text-[var(--soft)] truncate max-w-[115px]">
                    {roleInfo?.token_preview || (isAnon ? "None" : "Not configured")}
                  </span>
                </div>
                {!isAnon && (
                  <div className="flex justify-between items-center gap-2">
                    <span>Owned Items:</span>
                    <span
                      className="text-[var(--soft)] truncate max-w-[115px]"
                      title={ownedSummary || "0"}
                    >
                      {ownedSummary
                        ? `${roleInfo?.owned_resources_count} (${ownedSummary})`
                        : String(roleInfo?.owned_resources_count || 0)}
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Role Configuration Form */}
      {selectedRole !== "anonymous" && (
        <form
          onSubmit={handleSave}
          className="p-4 bg-[var(--sidebar)] rounded-xl border border-[var(--line)] space-y-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[var(--line-subtle)] pb-3">
            <h4 className="text-xs font-semibold text-[var(--text)] flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-[#5fa37f]" />
              <span>
                Configure Credentials for{" "}
                <span className="text-[#5fa37f]">
                  {ROLE_DEFAULTS[selectedRole]?.label || selectedRole.toUpperCase()}
                </span>
              </span>
            </h4>
            <span className="text-[11px] text-[var(--faint)] flex items-center gap-1">
              <Lock className="w-3 h-3 text-[#5fa37f]" />
              Stored in memory only; raw tokens are redacted from all logs &amp; evidence.
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-[11px] font-medium text-[var(--soft)]">
                  Bearer Token / JWT or Session Token
                </label>
                <button
                  type="button"
                  onClick={handleGenerateToken}
                  className="text-[10px] text-[#5fa37f] hover:underline font-medium cursor-pointer"
                >
                  Generate test token
                </button>
              </div>
              <input
                type="password"
                placeholder="Leave blank to auto-generate test token, or paste JWT..."
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--panel)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--faint)] focus:outline-none focus:border-[#5fa37f] font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-[var(--soft)] mb-1">
                User ID / Account Identifier (e.g. 101)
              </label>
              <input
                type="text"
                placeholder={ROLE_DEFAULTS[selectedRole]?.userId || "101"}
                value={userIdInput}
                onChange={(e) => setUserIdInput(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--panel)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--faint)] focus:outline-none focus:border-[#5fa37f] font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div>
              <label className="block text-[11px] font-medium text-[var(--soft)] mb-1">
                Owned Resource Type (for BOLA ownership baseline)
              </label>
              <input
                type="text"
                placeholder="basket, user, card, address, order"
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--panel)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--faint)] focus:outline-none focus:border-[#5fa37f] font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-[var(--soft)] mb-1">
                Owned Resource ID
              </label>
              <input
                type="text"
                placeholder={ROLE_DEFAULTS[selectedRole]?.resourceId || "101"}
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--panel)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--faint)] focus:outline-none focus:border-[#5fa37f] font-mono"
              />
            </div>
          </div>

          <div className="flex items-center justify-between gap-3 pt-1">
            <span className="text-[11px] text-[var(--faint)]">
              Tip: Click another persona card above to configure User B or Admin, or use{" "}
              <strong className="text-[var(--soft)]">Quick-Configure All 4 Roles</strong>.
            </span>
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 bg-[#5fa37f] hover:bg-[#529471] disabled:opacity-50 text-[#102218] text-xs font-semibold rounded-md flex items-center gap-1.5 transition cursor-pointer shrink-0"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? "Saving..." : "Save Role"}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
