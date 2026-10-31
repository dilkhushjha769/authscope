/**
 * AuthScope Frontend — TypeScript Data Contracts
 * Defines states, SSE events, finding models, and assessment structures.
 */

export type AssessmentState =
  | "ready"
  | "connecting"
  | "analyzing"
  | "running"
  | "findings_discovered"
  | "completed"
  | "no_vulnerabilities"
  | "failed"
  | "cancelled"
  | "reconnecting";

export interface AssessmentActivityEvent {
  assessment_id: string;
  event_type: string;
  stage: string;
  message: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceArtifactModel {
  id?: string;
  evidence_id?: string;
  finding_id: string;
  timestamp?: string;
  endpoint?: string;
  http_method?: string;
  testing_role?: string;
  test_role?: string;
  authorized_role?: string;
  expected_behavior?: string;
  actual_behavior?: string;
  validation_status?: string;
  request_method?: string;
  request_url?: string;
  request_headers?: Record<string, string>;
  response_status?: number;
  relevant_response_headers?: Record<string, string>;
  sanitized_response_body?: string;
  sanitized_response_evidence?: string;
  evidence_sha256?: string;
}

export interface FindingItem {
  id: string;
  title: string;
  vulnerability_category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | string;
  confidence: "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | string;
  validation_status: "CONFIRMED" | "SUSPICIOUS" | "UNVALIDATED" | string;
  explanation: string;
  affected_endpoint: string;
  http_method: string;
  source_file?: string | null;
  function_name?: string | null;
  line_numbers?: string | null;
  vulnerable_code?: string | null;
  suggested_code?: string | null;
  how_to_fix?: string | null;
  expected_behavior?: string | null;
  actual_behavior?: string | null;
  evidence?: EvidenceArtifactModel | null;
}

export interface AssessmentSummaryResponse {
  id: string;
  target_url: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  endpoints_discovered_count: number;
  endpoints_tested_count: number;
  confirmed_findings_count: number;
  suspicious_results_count: number;
  summary_text: string;
  markdown_content: string;
  stages: Record<string, { status: string; label: string; duration_ms?: number }>;
  events: AssessmentActivityEvent[];
  findings: Record<string, unknown>[];
}
