"use client";

import React from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  Terminal,
} from "lucide-react";
import { AssessmentActivityEvent, AssessmentState } from "@/types/assessment";

interface AgentActivityPanelProps {
  status: AssessmentState;
  events: AssessmentActivityEvent[];
  isExpanded: boolean;
  onToggleExpand: () => void;
  elapsedSeconds: number;
}

export function AgentActivityPanel({
  status,
  events,
  isExpanded,
  onToggleExpand,
  elapsedSeconds,
}: AgentActivityPanelProps) {
  const isRunning =
    status === "running" ||
    status === "connecting" ||
    status === "analyzing" ||
    status === "findings_discovered" ||
    status === "reconnecting";

  const isCompleted =
    status === "completed" || status === "no_vulnerabilities";

  const isFailed = status === "failed" || status === "cancelled";

  return (
    <div className="mb-5 border border-[#1E293B] rounded-2xl bg-[#111827]/80 overflow-hidden backdrop-blur shadow-lg shadow-black/20">
      <button
        type="button"
        onClick={onToggleExpand}
        className="w-full flex items-center justify-between px-4 py-3 text-xs text-gray-300 hover:text-white hover:bg-[#161F30]/50 transition-colors"
      >
        <div className="flex items-center gap-2.5 flex-wrap">
          {isRunning ? (
            <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin shrink-0" />
          ) : isCompleted ? (
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          ) : isFailed ? (
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          )}

          <span className="font-medium text-gray-200">
            {isRunning
              ? `Agent Active (${elapsedSeconds}s)`
              : `Completed in ${Math.max(1, elapsedSeconds)}s`}
          </span>

          <span className="text-gray-500 font-mono text-[11px]">
            · {events.length} verified backend events
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-gray-400 font-mono text-xs">
          <span>{isExpanded ? "Hide activity" : "View activity"}</span>
          {isExpanded ? (
            <ChevronUp className="w-3.5 h-3.5" />
          ) : (
            <ChevronDown className="w-3.5 h-3.5" />
          )}
        </div>
      </button>

      {isExpanded && (
        <div className="px-4 py-3 border-t border-[#1E293B] bg-[#090E17] max-h-80 overflow-y-auto space-y-2 text-xs font-mono">
          {events.length === 0 ? (
            <div className="text-gray-500 italic py-2 flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5" />
              Connecting to security engine & awaiting initial dispatch...
            </div>
          ) : (
            events.map((ev, idx) => {
              const timeStr = ev.timestamp ? ev.timestamp.slice(11, 19) : "";
              const type = ev.event_type.toLowerCase();
              const isWarning =
                type.includes("suspicious") ||
                type.includes("failed") ||
                type.includes("rejected");
              const isSuccess =
                type.includes("completed") ||
                type.includes("confirmed") ||
                type.includes("discovered");

              return (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 text-gray-300 leading-relaxed hover:bg-[#141C2C]/50 p-1 rounded transition-colors"
                >
                  <span className="text-gray-500 shrink-0 select-none">
                    [{timeStr || "LIVE"}]
                  </span>

                  {isWarning ? (
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  ) : isSuccess ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <div className="w-2 h-2 rounded-full bg-blue-400 shrink-0 mt-1.5" />
                  )}

                  <span
                    className={`break-words ${
                      isWarning
                        ? "text-amber-200"
                        : isSuccess
                        ? "text-gray-200"
                        : "text-gray-400"
                    }`}
                  >
                    {ev.message}
                  </span>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
