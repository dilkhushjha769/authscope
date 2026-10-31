"use client";

import React, { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  MinusCircle,
  Terminal,
  Brain,
  Wrench,
  ShieldCheck,
  Search,
  AlertTriangle,
  FileCode,
  Sparkles,
} from "lucide-react";
import { AssessmentEventItem, AssessmentStageState } from "@/types/assessment";

interface AgentActivityPanelProps {
  stages: Record<string, AssessmentStageState>;
  events: AssessmentEventItem[];
  isRunning: boolean;
}

const STAGE_ORDER = [
  "scope_validation",
  "target_connection",
  "endpoint_discovery",
  "session_verification",
  "authorization_testing",
  "evidence_validation",
  "report_preparation",
];

function getEventBadgeStyle(eventType: string): {
  label: string;
  badgeClass: string;
  icon: React.ReactNode;
} {
  switch (eventType) {
    case "assessment_started":
      return {
        label: "assessment_started",
        badgeClass: "bg-sky-500/15 text-sky-300 border-sky-500/30",
        icon: <Terminal className="w-3 h-3 text-sky-400" />,
      };
    case "agent_thinking":
      return {
        label: "agent_thinking",
        badgeClass: "bg-purple-500/15 text-purple-300 border-purple-500/30",
        icon: <Brain className="w-3 h-3 text-purple-400" />,
      };
    case "agent_plan":
      return {
        label: "agent_plan",
        badgeClass: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
        icon: <Sparkles className="w-3 h-3 text-indigo-400" />,
      };
    case "tool_started":
      return {
        label: "tool_started",
        badgeClass: "bg-blue-500/15 text-blue-300 border-blue-500/30",
        icon: <Wrench className="w-3 h-3 text-blue-400" />,
      };
    case "tool_completed":
      return {
        label: "tool_completed",
        badgeClass: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        icon: <CheckCircle2 className="w-3 h-3 text-emerald-400" />,
      };
    case "tool_failed":
      return {
        label: "tool_failed",
        badgeClass: "bg-red-500/15 text-red-300 border-red-500/30",
        icon: <XCircle className="w-3 h-3 text-red-400" />,
      };
    case "endpoint_discovered":
      return {
        label: "endpoint_discovered",
        badgeClass: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
        icon: <Search className="w-3 h-3 text-cyan-400" />,
      };
    case "finding_hypothesis":
      return {
        label: "finding_hypothesis",
        badgeClass: "bg-amber-500/15 text-amber-300 border-amber-500/30",
        icon: <AlertTriangle className="w-3 h-3 text-amber-400" />,
      };
    case "finding_discovered":
    case "finding_confirmed":
    case "suspicious_behavior_detected":
      return {
        label: eventType,
        badgeClass: "bg-rose-500/15 text-rose-300 border-rose-500/30",
        icon: <AlertTriangle className="w-3 h-3 text-rose-400" />,
      };
    case "evidence_validated":
    case "evidence_validation_completed":
      return {
        label: "evidence_validated",
        badgeClass: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        icon: <ShieldCheck className="w-3 h-3 text-emerald-400" />,
      };
    case "source_location_found":
      return {
        label: "source_location_found",
        badgeClass: "bg-violet-500/15 text-violet-300 border-violet-500/30",
        icon: <FileCode className="w-3 h-3 text-violet-400" />,
      };
    case "explanation_generated":
      return {
        label: "explanation_generated",
        badgeClass: "bg-teal-500/15 text-teal-300 border-teal-500/30",
        icon: <Sparkles className="w-3 h-3 text-teal-400" />,
      };
    case "assessment_completed":
      return {
        label: "assessment_completed",
        badgeClass: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
        icon: <CheckCircle2 className="w-3 h-3 text-emerald-400" />,
      };
    case "assessment_failed":
      return {
        label: "assessment_failed",
        badgeClass: "bg-red-500/20 text-red-300 border-red-500/40",
        icon: <XCircle className="w-3 h-3 text-red-400" />,
      };
    default:
      return {
        label: eventType,
        badgeClass: "bg-zinc-800 text-zinc-400 border-zinc-700",
        icon: <Terminal className="w-3 h-3 text-zinc-400" />,
      };
  }
}

export function AgentActivityPanel({
  stages,
  events,
  isRunning,
}: AgentActivityPanelProps) {
  const [expanded, setExpanded] = useState<boolean>(true);

  const completedCount = Object.values(stages).filter(
    (s) => s.status === "completed"
  ).length;
  const totalCount = STAGE_ORDER.length;

  const activeStage = Object.values(stages).find((s) => s.status === "running");
  const headerLabel = isRunning
    ? activeStage
      ? `${activeStage.label}...`
      : "Running security assessment..."
    : `Agent Activity (${completedCount}/${totalCount} stages completed · ${events.length} events)`;

  return (
    <div className="my-3 rounded-xl border border-zinc-800 bg-zinc-900/70 overflow-hidden text-sm">
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          {isRunning ? (
            <Loader2 className="w-4 h-4 text-emerald-400 animate-spin shrink-0" />
          ) : (
            <Terminal className="w-4 h-4 text-zinc-400 shrink-0" />
          )}
          <span className="font-medium text-zinc-200">{headerLabel}</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <span>{expanded ? "Hide" : "Show"} details</span>
          {expanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 px-4 py-3 space-y-3 bg-zinc-950/50">
          {/* 7-Stage Checklist */}
          <div className="space-y-1.5">
            {STAGE_ORDER.map((stageKey) => {
              const stage = stages[stageKey];
              if (!stage) return null;
              return (
                <div
                  key={stageKey}
                  className="flex items-start justify-between gap-3 py-1 text-xs"
                >
                  <div className="flex items-start gap-2">
                    {stage.status === "completed" && (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                    )}
                    {stage.status === "running" && (
                      <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin mt-0.5 shrink-0" />
                    )}
                    {stage.status === "failed" && (
                      <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                    )}
                    {stage.status === "skipped" && (
                      <MinusCircle className="w-3.5 h-3.5 text-zinc-500 mt-0.5 shrink-0" />
                    )}
                    {stage.status === "waiting" && (
                      <Circle className="w-3.5 h-3.5 text-zinc-600 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <span
                        className={
                          stage.status === "completed"
                            ? "text-zinc-200 font-medium"
                            : stage.status === "running"
                            ? "text-sky-300 font-medium"
                            : stage.status === "failed"
                            ? "text-red-300 font-medium"
                            : "text-zinc-500"
                        }
                      >
                        {stage.label}
                      </span>
                      {stage.explanation && stage.explanation !== "Waiting" && (
                        <p className="text-zinc-400 mt-0.5">{stage.explanation}</p>
                      )}
                    </div>
                  </div>
                  {stage.duration_ms != null && (
                    <span className="text-zinc-500 font-mono shrink-0">
                      {stage.duration_ms.toFixed(0)} ms
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Live Event Log */}
          {events.length > 0 && (
            <div className="pt-2 border-t border-zinc-800/80">
              <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-1.5 font-semibold">
                Live Agent &amp; Engine Telemetry ({events.length} events)
              </div>
              <div className="max-h-56 overflow-y-auto space-y-1.5 font-mono text-[11px] text-zinc-400 pr-1">
                {events.slice(-30).map((ev, idx) => {
                  const badge = getEventBadgeStyle(ev.event_type);
                  return (
                    <div
                      key={ev.id ?? idx}
                      className="flex items-start gap-2 leading-relaxed py-0.5"
                    >
                      <span className="text-zinc-600 shrink-0 mt-0.5">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] shrink-0 ${badge.badgeClass}`}
                      >
                        {badge.icon}
                        {badge.label}
                      </span>
                      <span className="text-zinc-300 break-all">{ev.message}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
