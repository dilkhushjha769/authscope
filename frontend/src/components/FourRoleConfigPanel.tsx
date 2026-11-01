"use client";

import React, { useState, useEffect } from "react";
import {
  Users,
  KeyRound,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react";
import { api } from "@/api/client";
import type { FourRolesStatusResponse, RoleSessionStatus } from "@/types/assessment";

interface Props {
  onClose?: () => void;
  onRolesUpdated?: (status: FourRolesStatusResponse) => void;
}

const ROLE_DEFAULTS: Record<
  string,
  { label: string; shortTitle: string; badge: string; userId: string; resourceType: string; resourceId: string }
> = {
  anonymous: {
    label: "Anonymous",
    shortTitle: "ANONYMOUS",
    badge: "Unauthenticated baseline requests without session credentials.",
    userId: "None",
    resourceType: "",
    resourceId: "",
  },
  user_a: {
    label: "User A (Owner)",
    shortTitle: "USER A",
    badge: "Authenticated resource owner establishing baseline legitimate access.",
    userId: "101",
    resourceType: "basket",
    resourceId: "101",
  },
  user_b: {
    label: "User B (Peer)",
    shortTitle: "USER B",
    badge: "Separate authenticated user testing horizontal cross-tenant access.",
    userId: "102",
    resourceType: "basket",
    resourceId: "102",
  },
  admin: {
    label: "Admin",
    shortTitle: "ADMIN",
    badge: "Authenticated administrator testing vertical privilege escalation.",
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
    <div className="text-[var(--text)] space-y-4">
      {/* Header matching Figma Image 3 */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-[var(--panel)] border border-[var(--line)] text-[#3d825e] shrink-0 mt-0.5">
            <Users className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="serif-heading text-lg text-[var(--text)]">
                Four-Role Authorization Testing
              </h3>
              <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-[var(--sidebar)] border border-[var(--line)] text-[var(--muted)]">
                DEMO DATA
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Configure independent identity sessions (Anonymous, User A, User B, Admin) to verify access boundaries.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <button
            type="button"
            onClick={() => void handleQuickConfigureAll()}
            disabled={quickConfiguring || loading}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] hover:border-[var(--accent)] text-[var(--text)] flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 whitespace-nowrap"
            title="Automatically populate test credentials and owned resources for all 4 personas"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#3d825e] ${quickConfiguring ? "animate-spin" : ""}`} />
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
              className="px-3 py-1.5 text-xs font-medium text-[var(--text)] bg-[var(--panel)] hover:bg-[var(--surface-hover)] border border-[var(--line)] rounded-lg flex items-center gap-1.5 transition cursor-pointer"
            >
              <X className="w-3.5 h-3.5 text-[var(--muted)]" />
              <span>Close</span>
            </button>
          )}
        </div>
      </div>

      {/* Global Readiness Banner matching Figma Image 3 */}
      <div className="p-3.5 bg-[var(--panel)] rounded-xl border border-[var(--line)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              data?.four_role_ready
                ? "bg-[#3d825e]"
                : data?.multi_role_ready
                ? "bg-[#c2722c]"
                : "bg-[#c2722c]"
            }`}
          />
          <div>
            <p className="text-xs font-semibold text-[var(--text)]">
              {data?.four_role_ready
                ? "All Four Testing Personas Ready (Anonymous, User A, User B, Admin)"
                : data?.multi_role_ready
                ? "Horizontal BOLA Testing Ready (User A & User B Configured)"
                : "Session Credentials Needed for Multi-Role Testing"}
            </p>
            <p className="text-[11px] text-[var(--muted)] mt-0.5">
              {data?.summary || "User A & User B credentials not configured. Admin role not configured."}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span
            className={`text-[11px] px-2.5 py-1 rounded-full font-medium border flex items-center gap-1 ${
              data?.multi_role_ready
                ? "bg-[#ebf5ee] text-[#2b744a] border-[#b8e2c7]"
                : "bg-[var(--sidebar)] text-[var(--muted)] border-[var(--line)]"
            }`}
          >
            <ShieldCheck className="w-3 h-3 text-[#3d825e]" />
            BOLA Ready
          </span>
          <span
            className={`text-[11px] px-2.5 py-1 rounded-full font-medium border flex items-center gap-1 ${
              data?.four_role_ready
                ? "bg-[#ebf5ee] text-[#2b744a] border-[#b8e2c7]"
                : "bg-[var(--sidebar)] text-[var(--muted)] border-[var(--line)]"
            }`}
          >
            <ShieldCheck className="w-3 h-3 text-[#3d825e]" />
            BFLA Ready
          </span>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[#d2675f]/12 border border-[#d2675f]/35 rounded-lg text-[#c0433a] text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3 bg-[#3d825e]/12 border border-[#3d825e]/35 rounded-lg text-[#2b744a] text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {/* 4 Persona Cards Grid matching Figma Image 3 */}
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
              className={`p-4 rounded-xl border transition text-left flex flex-col justify-between bg-[var(--panel)] ${
                isAnon
                  ? "border-[var(--line)] cursor-default"
                  : isSelected
                  ? "border-[#2f6f4e] ring-1 ring-[#2f6f4e]/35 cursor-pointer shadow-xs"
                  : "border-[var(--line)] hover:border-[var(--muted)] cursor-pointer"
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-2.5">
                  <span className="text-xs font-bold uppercase tracking-wider text-[var(--text)]">
                    {meta.shortTitle}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-medium border ${
                      isAnon
                        ? "bg-[var(--sidebar)] text-[var(--muted)] border-[var(--line)]"
                        : isAuth
                        ? "bg-[#ebf5ee] text-[#2b744a] border-[#b8e2c7]"
                        : "bg-[var(--sidebar)] text-[var(--muted)] border-[var(--line)]"
                    }`}
                  >
                    {isAnon ? "BASELINE" : isAuth ? "READY" : "NOT SET"}
                  </span>
                </div>

                <p className="text-[11px] text-[var(--muted)] mb-4 leading-relaxed">
                  {roleInfo?.description || meta?.badge}
                </p>
              </div>

              <div className="space-y-1.5 text-[11px] font-mono border-t border-[var(--line-subtle)] pt-3 text-[var(--muted)]">
                <div className="flex justify-between">
                  <span>User ID:</span>
                  <span className="text-[var(--text)] font-medium">
                    {roleInfo?.user_id || (isAnon ? "None" : "—")}
                  </span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span>Token:</span>
                  <span className="text-[var(--text)] truncate max-w-[115px]">
                    {roleInfo?.token_preview || (isAnon ? "None" : "Not configured")}
                  </span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span>Owned Items:</span>
                  <span
                    className="text-[var(--text)] truncate max-w-[115px]"
                    title={ownedSummary || "0"}
                  >
                    {isAnon
                      ? "0"
                      : ownedSummary
                      ? `${roleInfo?.owned_resources_count} (${ownedSummary})`
                      : String(roleInfo?.owned_resources_count || 0)}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Role Configuration Form matching Figma Image 3 */}
      {selectedRole !== "anonymous" && (
        <form
          onSubmit={handleSave}
          className="p-4 sm:p-5 bg-[var(--panel)] rounded-xl border border-[var(--line)] space-y-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-1">
            <h4 className="text-xs font-semibold text-[var(--text)] flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-[#3d825e]" />
              <span>
                Configure Credentials for{" "}
                <span>
                  {ROLE_DEFAULTS[selectedRole]?.label || selectedRole.toUpperCase()}
                </span>
              </span>
            </h4>
            <span className="text-[11px] text-[var(--muted)] flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-[var(--muted)]" />
              Stored in memory only; raw tokens are redacted from all logs &amp; evidence.
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-[11px] font-medium text-[var(--muted)]">
                  Bearer Token / JWT or Session Token
                </label>
                <button
                  type="button"
                  onClick={handleGenerateToken}
                  className="text-[11px] text-[#2f6f4e] hover:underline font-medium cursor-pointer"
                >
                  Generate test token
                </button>
              </div>
              <input
                type="text"
                placeholder="Leave blank to auto-generate test token, or paste JWT"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--sidebar)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--muted)] focus:outline-none focus:border-[#2f6f4e] font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-[var(--muted)] mb-1.5">
                User ID / Account Identifier (e.g. 101)
              </label>
              <input
                type="text"
                placeholder={ROLE_DEFAULTS[selectedRole]?.userId || "101"}
                value={userIdInput}
                onChange={(e) => setUserIdInput(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--sidebar)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--muted)] focus:outline-none focus:border-[#2f6f4e] font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-medium text-[var(--muted)] mb-1.5">
                Owned Resource Type (for BOLA ownership baseline)
              </label>
              <input
                type="text"
                placeholder="basket"
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--sidebar)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--muted)] focus:outline-none focus:border-[#2f6f4e] font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-[var(--muted)] mb-1.5">
                Owned Resource ID
              </label>
              <input
                type="text"
                placeholder={ROLE_DEFAULTS[selectedRole]?.resourceId || "101"}
                value={resourceId}
                onChange={(e) => setResourceId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--sidebar)] border border-[var(--line)] rounded-lg text-[var(--text)] placeholder-[var(--muted)] focus:outline-none focus:border-[#2f6f4e] font-mono"
              />
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
            <span className="text-[11px] text-[var(--muted)]">
              Tip: Click another persona card above to configure User B or Admin, or use{" "}
              <strong className="text-[var(--text)]">Quick-Configure All 4 Roles</strong>.
            </span>
            <button
              type="submit"
              disabled={saving}
              style={{ backgroundColor: "#2f6f4e", color: "#ffffff" }}
              className="px-4 py-2 hover:brightness-105 disabled:opacity-50 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition cursor-pointer shrink-0 self-end sm:self-auto"
            >
              <span>{saving ? "Saving..." : "Save Role"}</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
