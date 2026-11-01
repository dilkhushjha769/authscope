"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  X,
  GitBranch,
  Globe,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ExternalLink,
  ShieldCheck,
  Server,
  Layers,
  ArrowRight,
  LogOut,
  Sparkles,
} from "lucide-react";
import {
  ProjectRecord,
  ValidateProjectUrlResponse,
} from "@/types/assessment";
import { api } from "@/lib/api";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

interface GitHubAccount {
  id: string;
  login: string;
  avatar_url: string;
}

interface GitHubInstallation {
  id: number;
  account_login: string;
  account_type: string;
}

interface GitHubRepositoryItem {
  id: number;
  name: string;
  full_name: string;
  owner: string;
  private: boolean;
  description?: string | null;
  default_branch: string;
  html_url: string;
}

interface GitHubBranch {
  name: string;
  commit_sha: string;
}

interface AddProjectModalProps {
  isOpen: boolean;
  onClose: () => void;
  onProjectCreated: (project: ProjectRecord, targetUrl?: string) => void;
}

export function AddProjectModal({ isOpen, onClose, onProjectCreated }: AddProjectModalProps) {
  const [activeTab, setActiveTab] = useState<"github" | "website">("github");

  // GitHub State
  const [ghLoading, setGhLoading] = useState<boolean>(true);
  const [ghConnected, setGhConnected] = useState<boolean>(false);
  const [ghAccount, setGhAccount] = useState<GitHubAccount | null>(null);
  const [installations, setInstallations] = useState<GitHubInstallation[]>([]);
  const [selectedInstallationId, setSelectedInstallationId] = useState<number | null>(null);
  const [repositories, setRepositories] = useState<GitHubRepositoryItem[]>([]);
  const [reposLoading, setReposLoading] = useState<boolean>(false);
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepositoryItem | null>(null);
  const [branches, setBranches] = useState<GitHubBranch[]>([]);
  const [branchesLoading, setBranchesLoading] = useState<boolean>(false);
  const [selectedBranch, setSelectedBranch] = useState<string>("main");
  const [repoSearch, setRepoSearch] = useState<string>("");
  const [ghError, setGhError] = useState<string | null>(null);

  // Website State
  const [webName, setWebName] = useState<string>("");
  const [webUrl, setWebUrl] = useState<string>("");
  const [authConfirmed, setAuthConfirmed] = useState<boolean>(false);
  const [authBasis, setAuthBasis] = useState<string>("admin_approved");
  const [isValidatingUrl, setIsValidatingUrl] = useState<boolean>(false);
  const [urlValidationResult, setUrlValidationResult] = useState<ValidateProjectUrlResponse | null>(null);
  const [webError, setWebError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Load GitHub Status
  const loadGitHubStatus = useCallback(async () => {
    setGhLoading(true);
    setGhError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/github/status`, {
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        setGhConnected(Boolean(data.connected));
        setGhAccount(data.account || null);
        setInstallations(data.installations || []);
        if (data.installations && data.installations.length > 0) {
          setSelectedInstallationId(data.installations[0].id);
        }
      } else {
        setGhConnected(false);
      }
    } catch {
      setGhConnected(false);
    } finally {
      setGhLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      void loadGitHubStatus();
    }
  }, [isOpen, loadGitHubStatus]);

  // Load Repositories for selected installation
  useEffect(() => {
    if (!ghConnected || !selectedInstallationId) return;
    let cancelled = false;
    async function fetchRepos() {
      setReposLoading(true);
      setGhError(null);
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/github/installations/${selectedInstallationId}/repositories`,
          { credentials: "include" }
        );
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) {
            setRepositories(data.repositories || []);
            if (data.repositories?.length > 0) {
              setSelectedRepo(data.repositories[0]);
              setSelectedBranch(data.repositories[0].default_branch || "main");
            }
          }
        } else {
          const err = await res.json().catch(() => ({}));
          if (!cancelled) setGhError(err.detail || "Failed to load repositories.");
        }
      } catch {
        if (!cancelled) setGhError("Could not connect to GitHub API.");
      } finally {
        if (!cancelled) setReposLoading(false);
      }
    }
    void fetchRepos();
    return () => {
      cancelled = true;
    };
  }, [ghConnected, selectedInstallationId]);

  // Load Branches for selected repo
  useEffect(() => {
    if (!ghConnected || !selectedInstallationId || !selectedRepo) return;
    const currentRepo = selectedRepo;
    const currentInstallId = selectedInstallationId;
    let cancelled = false;
    async function fetchBranches() {
      setBranchesLoading(true);
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/github/installations/${currentInstallId}/repositories/${encodeURIComponent(
            currentRepo.owner
          )}/${encodeURIComponent(currentRepo.name)}/branches`,
          { credentials: "include" }
        );
        if (res.ok) {
          const data = await res.json();
          if (!cancelled) {
            setBranches(data.branches || []);
            if (data.branches?.length > 0) {
              const hasDefault = data.branches.some(
                (b: GitHubBranch) => b.name === currentRepo.default_branch
              );
              setSelectedBranch(hasDefault ? currentRepo.default_branch : data.branches[0].name);
            }
          }
        }
      } catch {
        // Fallback silently to main
      } finally {
        if (!cancelled) setBranchesLoading(false);
      }
    }
    void fetchBranches();
    return () => {
      cancelled = true;
    };
  }, [ghConnected, selectedInstallationId, selectedRepo]);

  // Disconnect GitHub
  const handleDisconnect = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/github/disconnect`, {
        method: "DELETE",
        credentials: "include",
      });
      if (res.ok) {
        setGhConnected(false);
        setGhAccount(null);
        setRepositories([]);
        setSelectedRepo(null);
      }
    } catch {
      setGhError("Failed to disconnect GitHub.");
    }
  };

  // Validate Website URL
  const handleValidateUrl = async () => {
    const raw = webUrl.trim();
    if (!raw) {
      setWebError("Please enter a website URL.");
      return;
    }
    setIsValidatingUrl(true);
    setWebError(null);
    setUrlValidationResult(null);
    try {
      const result = await api.validateProjectUrl({
        target_url: raw,
        is_local_test: raw.includes("localhost") || raw.includes("127.0.0.1"),
      });
      setUrlValidationResult(result);
      if (!result.valid) {
        setWebError(result.error || "Target URL is outside authorized scope or failed SSRF check.");
      } else {
        if (!webName) {
          setWebName(result.hostname || "Website Project");
        }
      }
    } catch (err: unknown) {
      setWebError(err instanceof Error ? err.message : "Failed to validate target URL.");
    } finally {
      setIsValidatingUrl(false);
    }
  };

  // Submit Website Project
  const handleCreateWebsiteProject = async () => {
    if (!webUrl.trim()) {
      setWebError("Target URL is required.");
      return;
    }
    if (!authConfirmed) {
      setWebError("You must confirm explicit authorization before adding a website target.");
      return;
    }
    setIsSubmitting(true);
    setWebError(null);
    try {
      const name = webName.trim() || webUrl.trim();
      const project = await api.createProject({
        name,
        project_type: "website",
        target_url: urlValidationResult?.normalized_url || webUrl.trim(),
        authorization_basis: authBasis,
        authorization_confirmed: true,
      });
      onProjectCreated(project, project.target_url || webUrl.trim());
      onClose();
    } catch (err: unknown) {
      setWebError(err instanceof Error ? err.message : "Failed to create website project.");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Submit GitHub Project
  const handleCreateGitHubProject = async () => {
    if (!selectedRepo) {
      setGhError("Please select a repository.");
      return;
    }
    setIsSubmitting(true);
    setGhError(null);
    try {
      const project = await api.createProject({
        name: selectedRepo.name,
        project_type: "github",
        github_repo_full_name: selectedRepo.full_name,
        github_installation_id: selectedInstallationId || undefined,
        github_default_branch: selectedBranch || selectedRepo.default_branch || "main",
        is_private: selectedRepo.private,
      });
      onProjectCreated(project);
      onClose();
    } catch (err: unknown) {
      setGhError(err instanceof Error ? err.message : "Failed to connect GitHub project.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const filteredRepos = useMemo(() => {
    if (!repoSearch.trim()) return repositories;
    const q = repoSearch.toLowerCase();
    return repositories.filter(
      (r) => r.name.toLowerCase().includes(q) || r.full_name.toLowerCase().includes(q)
    );
  }, [repositories, repoSearch]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-xl bg-[#262624] border border-[#41413d] shadow-2xl p-6 text-left text-[#f4f2ec]">
        {/* Header */}
        <div className="flex items-center justify-between pb-3.5 border-b border-[#373733]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#5fa37f]/15 border border-[#5fa37f]/30 flex items-center justify-center text-[#5fa37f]">
              <Layers size={17} />
            </div>
            <div>
              <h2 className="text-base font-semibold text-[#f4f2ec]">Add Project</h2>
              <p className="text-xs text-[#aaa8a1]">
                Choose how you want to connect your application to AuthScope
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#aaa8a1] hover:text-[#f4f2ec] hover:bg-[#333330] transition-colors"
          >
            <X size={17} />
          </button>
        </div>

        {/* Two Connection Methods Selector */}
        <div className="grid grid-cols-2 gap-3 mt-4">
          <button
            type="button"
            onClick={() => setActiveTab("github")}
            className={`p-3.5 rounded-xl border text-left flex items-start gap-3 transition-all ${
              activeTab === "github"
                ? "bg-[#333330] border-[#5fa37f] ring-1 ring-[#5fa37f]"
                : "bg-[#1f1f1d] border-[#373733] hover:border-[#4d4d48]"
            }`}
          >
            <div
              className={`p-2 rounded-lg ${
                activeTab === "github"
                  ? "bg-[#5fa37f]/20 text-[#5fa37f]"
                  : "bg-[#292926] text-[#aaa8a1]"
              }`}
            >
              <GitBranch size={18} />
            </div>
            <div>
              <div className="text-sm font-medium text-[#f4f2ec] flex items-center gap-1.5">
                <span>Connect GitHub</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#3a3a36] text-[#c7c5bc]">
                  OAuth App
                </span>
              </div>
              <p className="text-xs text-[#aaa8a1] mt-0.5">
                Scan source code & test endpoints across user-authorized repositories.
              </p>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("website")}
            className={`p-3.5 rounded-xl border text-left flex items-start gap-3 transition-all ${
              activeTab === "website"
                ? "bg-[#333330] border-[#5fa37f] ring-1 ring-[#5fa37f]"
                : "bg-[#1f1f1d] border-[#373733] hover:border-[#4d4d48]"
            }`}
          >
            <div
              className={`p-2 rounded-lg ${
                activeTab === "website"
                  ? "bg-[#5fa37f]/20 text-[#5fa37f]"
                  : "bg-[#292926] text-[#aaa8a1]"
              }`}
            >
              <Globe size={18} />
            </div>
            <div>
              <div className="text-sm font-medium text-[#f4f2ec] flex items-center gap-1.5">
                <span>Add Website URL</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#3a3a36] text-[#c7c5bc]">
                  Direct URL
                </span>
              </div>
              <p className="text-xs text-[#aaa8a1] mt-0.5">
                Scan a deployed web app or staging API. No GitHub account required.
              </p>
            </div>
          </button>
        </div>

        {/* Tab 1: Connect GitHub */}
        {activeTab === "github" && (
          <div className="mt-5 space-y-4">
            {ghLoading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-2 text-xs text-[#aaa8a1]">
                <Loader2 size={20} className="animate-spin text-[#5fa37f]" />
                <span>Checking GitHub connection status...</span>
              </div>
            ) : !ghConnected ? (
              <div className="p-5 rounded-xl bg-[#1f1f1d] border border-[#373733] text-center space-y-3">
                <div className="w-12 h-12 mx-auto rounded-full bg-[#333330] flex items-center justify-center text-[#c7c5bc]">
                  <GitBranch size={24} />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-[#f4f2ec]">Authorize GitHub Account</h3>
                  <p className="text-xs text-[#aaa8a1] max-w-md mx-auto mt-1">
                    Connect your own GitHub account to authorize AuthScope to inspect public and
                    private repositories you grant access to.
                  </p>
                </div>

                <div className="text-[11px] text-[#8e8c85] bg-[#181816] p-3 rounded-lg max-w-md mx-auto text-left space-y-1 border border-[#2e2e2a]">
                  <div className="flex items-center gap-1.5 text-[#5fa37f]">
                    <ShieldCheck size={13} />
                    <span className="font-medium">Strict Credential Isolation</span>
                  </div>
                  <p>• Access tokens are encrypted server-side and never exposed to the frontend.</p>
                  <p>• AuthScope only requests read-only repository metadata and source contents.</p>
                  <p>• You can revoke authorization and disconnect at any time.</p>
                </div>

                <a
                  href={`${API_BASE_URL}/api/github/connect`}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#5fa37f] hover:bg-[#528f6e] text-white text-xs font-semibold shadow-md transition-colors"
                >
                  <span>Authorize with GitHub</span>
                  <ExternalLink size={13} />
                </a>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Connected Account Bar */}
                <div className="p-3 rounded-lg bg-[#1f1f1d] border border-[#373733] flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    {ghAccount?.avatar_url ? (
                      <img
                        src={ghAccount.avatar_url}
                        alt={ghAccount.login}
                        className="w-7 h-7 rounded-full border border-[#4d4d48]"
                      />
                    ) : (
                      <div className="w-7 h-7 rounded-full bg-[#373733] flex items-center justify-center text-xs">
                        GH
                      </div>
                    )}
                    <div>
                      <div className="text-xs font-medium text-[#f4f2ec] flex items-center gap-1.5">
                        <span>@{ghAccount?.login}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-[#203628] text-[#5fa37f] border border-[#3e684c]/50">
                          Connected
                        </span>
                      </div>
                      <div className="text-[10px] text-[#aaa8a1]">
                        {installations.length} installation(s) authorized
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleDisconnect}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs text-[#c96a6a] hover:bg-[#3a2020] border border-transparent hover:border-[#7a3434]/40 transition-colors"
                  >
                    <LogOut size={12} />
                    <span>Disconnect</span>
                  </button>
                </div>

                {/* Repository Selection */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-medium text-[#aaa8a1]">Select Repository</label>
                    <span className="text-[11px] text-[#8e8c85]">
                      {repositories.length} repository(ies) accessible
                    </span>
                  </div>

                  <input
                    type="text"
                    value={repoSearch}
                    onChange={(e) => setRepoSearch(e.target.value)}
                    placeholder="Search repositories..."
                    className="w-full px-3 py-1.5 text-xs rounded-lg bg-[#181816] border border-[#373733] text-[#f4f2ec] placeholder-[#706e68] focus:border-[#5fa37f] focus:outline-hidden"
                  />

                  {reposLoading ? (
                    <div className="py-6 flex items-center justify-center gap-2 text-xs text-[#aaa8a1]">
                      <Loader2 size={16} className="animate-spin text-[#5fa37f]" />
                      <span>Loading authorized repositories...</span>
                    </div>
                  ) : filteredRepos.length === 0 ? (
                    <div className="p-4 rounded-lg bg-[#181816] text-center text-xs text-[#aaa8a1]">
                      No repositories found. Ensure your GitHub App installation includes the repositories you want to test.
                    </div>
                  ) : (
                    <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                      {filteredRepos.map((repo) => {
                        const isSelected = selectedRepo?.id === repo.id;
                        return (
                          <button
                            key={repo.id}
                            type="button"
                            onClick={() => {
                              setSelectedRepo(repo);
                              setSelectedBranch(repo.default_branch || "main");
                            }}
                            className={`w-full p-2.5 rounded-lg border text-left flex items-center justify-between text-xs transition-colors ${
                              isSelected
                                ? "bg-[#333330] border-[#5fa37f] text-[#f4f2ec]"
                                : "bg-[#1c1c1a] border-[#2e2e2a] hover:border-[#41413d] text-[#c7c5bc]"
                            }`}
                          >
                            <div className="flex items-center gap-2 truncate">
                              {repo.private ? (
                                <Lock size={13} className="text-[#e0ac57] shrink-0" />
                              ) : (
                                <Globe size={13} className="text-[#8e8c85] shrink-0" />
                              )}
                              <span className="font-mono font-medium truncate">{repo.full_name}</span>
                            </div>
                            <span
                              className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${
                                repo.private
                                  ? "bg-[#3d321d] text-[#e0ac57]"
                                  : "bg-[#292926] text-[#aaa8a1]"
                              }`}
                            >
                              {repo.private ? "Private" : "Public"}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Branch Selection */}
                {selectedRepo && (
                  <div className="grid grid-cols-2 gap-3 pt-2">
                    <div>
                      <label className="text-xs font-medium text-[#aaa8a1] block mb-1">
                        Selected Branch
                      </label>
                      <select
                        value={selectedBranch}
                        onChange={(e) => setSelectedBranch(e.target.value)}
                        className="w-full px-3 py-1.5 text-xs rounded-lg bg-[#181816] border border-[#373733] text-[#f4f2ec] focus:border-[#5fa37f] focus:outline-hidden"
                      >
                        {branchesLoading ? (
                          <option>Loading branches...</option>
                        ) : branches.length > 0 ? (
                          branches.map((b) => (
                            <option key={b.name} value={b.name}>
                              {b.name}
                            </option>
                          ))
                        ) : (
                          <option value={selectedRepo.default_branch}>
                            {selectedRepo.default_branch}
                          </option>
                        )}
                      </select>
                    </div>

                    <div className="flex items-end">
                      <button
                        type="button"
                        onClick={handleCreateGitHubProject}
                        disabled={isSubmitting || !selectedRepo}
                        className="w-full py-2 px-3 rounded-lg bg-[#5fa37f] hover:bg-[#528f6e] disabled:opacity-50 text-white text-xs font-medium flex items-center justify-center gap-1.5 transition-colors shadow-sm"
                      >
                        {isSubmitting ? (
                          <Loader2 size={14} className="animate-spin" />
                        ) : (
                          <Sparkles size={14} />
                        )}
                        <span>Connect & Run Scan</span>
                      </button>
                    </div>
                  </div>
                )}

                {ghError && (
                  <div className="p-2.5 rounded-lg bg-[#3a2020] border border-[#7a3434] text-xs text-[#f5c2c2] flex items-center gap-2">
                    <AlertTriangle size={14} className="shrink-0 text-[#f08585]" />
                    <span>{ghError}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Add Website URL */}
        {activeTab === "website" && (
          <div className="mt-5 space-y-4">
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-[#aaa8a1] block mb-1">
                  Project Name (Optional)
                </label>
                <input
                  type="text"
                  value={webName}
                  onChange={(e) => setWebName(e.target.value)}
                  placeholder="e.g. Staging Auth API"
                  className="w-full px-3 py-2 text-xs rounded-lg bg-[#181816] border border-[#373733] text-[#f4f2ec] placeholder-[#706e68] focus:border-[#5fa37f] focus:outline-hidden"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-[#aaa8a1] block mb-1">
                  Target Website / API URL <span className="text-[#e0ac57]">*</span>
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={webUrl}
                    onChange={(e) => {
                      setWebUrl(e.target.value);
                      setUrlValidationResult(null);
                      setWebError(null);
                    }}
                    placeholder="https://app.example.com or http://localhost:3000"
                    className="flex-1 px-3 py-2 text-xs rounded-lg bg-[#181816] border border-[#373733] text-[#f4f2ec] placeholder-[#706e68] focus:border-[#5fa37f] focus:outline-hidden font-mono"
                  />
                  <button
                    type="button"
                    onClick={handleValidateUrl}
                    disabled={isValidatingUrl || !webUrl.trim()}
                    className="px-3 py-2 rounded-lg bg-[#373733] hover:bg-[#43433e] text-xs text-[#f4f2ec] flex items-center gap-1.5 transition-colors shrink-0"
                  >
                    {isValidatingUrl ? (
                      <Loader2 size={13} className="animate-spin text-[#5fa37f]" />
                    ) : (
                      <Server size={13} />
                    )}
                    <span>Verify Scope & DNS</span>
                  </button>
                </div>
                <p className="text-[11px] text-[#8e8c85] mt-1">
                  Protected by ScopeGuard: DNS is safely resolved and checked against cloud metadata and private IP boundaries.
                </p>
              </div>

              {/* Validation Result Box */}
              {urlValidationResult && urlValidationResult.valid && (
                <div className="p-3 rounded-lg bg-[#1c2e22] border border-[#3d694b] text-xs text-[#cbf0d7] space-y-1.5">
                  <div className="flex items-center gap-1.5 font-medium text-[#7ad49f]">
                    <CheckCircle2 size={14} />
                    <span>Target URL Verified & Scope Approved</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-[#a9dcbc]">
                    <div>Host: <span className="font-mono">{urlValidationResult.hostname}:{urlValidationResult.port}</span></div>
                    <div>Scheme: <span className="font-mono">{urlValidationResult.scheme?.toUpperCase()}</span></div>
                    <div className="col-span-2">
                      Resolved IPs: <span className="font-mono">{urlValidationResult.resolved_ips?.join(", ") || "Loopback"}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Explicit Authorization Grounds */}
              <div className="p-3.5 rounded-lg bg-[#1f1f1d] border border-[#373733] space-y-2.5">
                <div className="text-xs font-semibold text-[#f4f2ec] flex items-center gap-1.5">
                  <ShieldCheck size={14} className="text-[#5fa37f]" />
                  <span>Mandatory Security Authorization</span>
                </div>

                <div>
                  <label className="text-[11px] text-[#aaa8a1] block mb-1">
                    Authorization Grounds:
                  </label>
                  <select
                    value={authBasis}
                    onChange={(e) => setAuthBasis(e.target.value)}
                    className="w-full px-2.5 py-1.5 text-xs rounded bg-[#181816] border border-[#373733] text-[#f4f2ec] focus:outline-hidden"
                  >
                    <option value="admin_approved">Admin Approved (Internal or authorized test target)</option>
                    <option value="written_permission">Written Permission (Authorized assessment contract)</option>
                    <option value="domain_ownership_challenge">Domain Ownership (Owner-controlled asset)</option>
                    <option value="bug_bounty_scope">Bug Bounty Program Scope</option>
                  </select>
                </div>

                <label className="flex items-start gap-2 cursor-pointer pt-1">
                  <input
                    type="checkbox"
                    checked={authConfirmed}
                    onChange={(e) => setAuthConfirmed(e.target.checked)}
                    className="mt-0.5 rounded border-[#41413d] text-[#5fa37f] focus:ring-0 focus:outline-hidden bg-[#181816]"
                  />
                  <span className="text-xs text-[#c7c5bc] leading-relaxed">
                    I confirm that I own this target or have explicit, documented authorization to
                    perform security assessments against this URL.
                  </span>
                </label>
              </div>

              {webError && (
                <div className="p-2.5 rounded-lg bg-[#3a2020] border border-[#7a3434] text-xs text-[#f5c2c2] flex items-center gap-2">
                  <AlertTriangle size={14} className="shrink-0 text-[#f08585]" />
                  <span>{webError}</span>
                </div>
              )}

              <button
                type="button"
                onClick={handleCreateWebsiteProject}
                disabled={isSubmitting || !webUrl.trim() || !authConfirmed}
                className="w-full py-2.5 px-4 rounded-lg bg-[#5fa37f] hover:bg-[#528f6e] disabled:opacity-50 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-md"
              >
                {isSubmitting ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : (
                  <ArrowRight size={15} />
                )}
                <span>Add Project & Start Security Assessment</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
