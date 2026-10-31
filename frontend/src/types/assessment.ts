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

export type FindingValidationStatus =
  | "CONFIRMED"
  | "SUSPICIOUS"
  | "NOT_CONFIRMED"
  | "INCONCLUSIVE"
  | "NOT_TESTED";

export type FindingStatus = FindingValidationStatus;

export type SSEEventType =
  | "assessment_started"
  | "agent_thinking"
  | "agent_plan"
  | "tool_started"
  | "tool_completed"
  | "tool_failed"
  | "endpoint_discovered"
  | "finding_hypothesis"
  | "finding_discovered"
  | "evidence_validated"
  | "source_location_found"
  | "explanation_generated"
  | "assessment_completed"
  | "assessment_failed"
  | "assessment_cancelled"
  | string;

export interface AssessmentStageState {
  stage: string;
  label: string;
  status: "waiting" | "running" | "completed" | "failed" | "skipped";
  explanation: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms?: number | null;
}

export interface AssessmentActivityEvent {
  id?: number | null;
  assessment_id: string;
  event_type: SSEEventType | string;
  stage: string;
  message: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export type AssessmentEventItem = AssessmentActivityEvent;

export interface EvidenceItem {
  id: string;
  finding_id: string;
  endpoint: string;
  http_method: string;
  testing_role: string;
  authorized_role?: string | null;
  resource_id?: string | null;
  expected_behavior: string;
  actual_behavior: string;
  validation_status: string;
  request_method: string;
  request_url: string;
  request_headers: Record<string, string>;
  response_status: number;
  relevant_response_headers: Record<string, string>;
  sanitized_response_body: string;
  evidence_sha256: string;
  redacted_fields: string[];
}

export type EvidenceArtifactModel = EvidenceItem;

export interface WebsiteLocationInfo {
  full_url: string;
  hostname: string;
  port: number;
  scheme: string;
  endpoint: string;
  http_method: string;
  parameter_or_resource_id: string;
}

export interface SourceLocationInfo {
  available: boolean;
  repository?: string | null;
  file_path?: string | null;
  line_range?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  function_name?: string | null;
  vulnerable_snippet?: string | null;
  unavailable_message?: string | null;
}

export interface ImpactDetailsInfo {
  summary: string;
  exposed_data_or_functionality: string;
  affected_roles: string[];
  attacker_capabilities: string;
  why_it_matters: string;
}

export interface ResolutionDetailsInfo {
  root_cause: string;
  recommended_fix: string;
  proposed_code_fix: string;
  proposed_fix_label: string;
  verification_procedure: string;
}

export interface EvidenceSummaryInfo {
  baseline_behavior: string;
  unauthorized_behavior: string;
  response_difference: string;
  validation_status: FindingValidationStatus | string;
  evidence_sha256: string;
  redacted_fields: string[];
}

export interface FindingItem {
  id: string;
  scan_id: string;
  title: string;
  vulnerability_name?: string;
  endpoint?: string;
  target_endpoint: string;
  affected_endpoint?: string;
  http_method: string;
  vulnerability_category: string;
  vulnerability_type: string;
  category_display?: string;
  affected_role: string;
  affected_roles: string[];
  expected_behavior: string;
  actual_behavior: string;
  confirmation_status: string;
  status: string;
  validation_status: FindingValidationStatus;
  finding_status?: FindingStatus | string;
  confidence?: "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | string;
  access_verdict: string;
  resource_id?: string | null;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | string;
  impact_explanation: string;
  impact?: string | null;
  description: string;
  explanation?: string;
  remediation_recommendation: string;
  remediation_guidance: string;
  how_to_fix?: string | null;
  evidence?: EvidenceItem | null;
  evidence_summary?: EvidenceSummaryInfo | string | null;
  technical_details?: Record<string, unknown>;
  beginner_explanation?: BeginnerExplanation;

  // Section B: Website location
  full_url?: string;
  hostname?: string;
  port?: number;
  scheme?: string;
  parameter_or_resource_id?: string;
  website_location?: WebsiteLocationInfo;

  // Section C: Source-code location
  source_code_available?: boolean;
  source_repository?: string | null;
  source_file?: string | null;
  source_line?: string | null;
  source_start_line?: number | null;
  source_end_line?: number | null;
  source_function?: string | null;
  function_name?: string | null;
  line_numbers?: string | null;
  vulnerable_code?: string | null;
  suggested_code?: string | null;
  vulnerable_snippet?: string | null;
  source_unavailable_message?: string | null;
  source_location?: SourceLocationInfo;
  black_box_only?: boolean;

  // Section D: What the bug can affect
  exposed_data_or_functionality?: string;
  attacker_capabilities?: string;
  why_it_matters?: string;
  impact_details?: ImpactDetailsInfo;

  // Section E: How to resolve it
  root_cause?: string;
  recommended_fix?: string;
  proposed_code_fix?: string;
  proposed_fix_label?: string;
  verification_procedure?: string;
  resolution_details?: ResolutionDetailsInfo;

  // Section F: Sanitized evidence summary
  baseline_behavior?: string;
  unauthorized_behavior?: string;
  response_difference?: string;
  evidence_validation_status?: FindingValidationStatus | string;
  retest_status?: string | null;
  verification_history?: FixVerificationRecord[];
}

export type FixVerificationStatus =
  | "FIXED"
  | "STILL VULNERABLE"
  | "PARTIALLY FIXED"
  | "INCONCLUSIVE"
  | "NOT_TESTED";

export interface FixVerificationRecord {
  id: string;
  finding_id: string;
  previous_status: string;
  new_status: FixVerificationStatus;
  is_vulnerable: boolean;
  summary?: string | null;
  notes: string;
  differential_result?: {
    before?: Record<string, unknown>;
    after?: Record<string, unknown>;
    regression_checks?: Record<string, unknown>;
    [key: string]: unknown;
  } | null;
  retested_at: string;
}

export interface BeginnerExplanation {
  simple_title: string;
  technical_name: string;
  risk_level: string;
  risk_description: string;
  confirmation_status: string;
  what_is_the_problem: string;
  what_attacker_can_do: string;
  real_world_impact: string;
  why_it_matters: string;
  how_to_fix: string[];
  secure_code_example?: string | null;
  how_to_verify_fix: string[];
  additional_recommendations: string[];
  evidence_summary: string[];
  what_is_not_yet_proven: string[];
}

export interface DiscoveredEndpointItem {
  id: string;
  scan_id: string;
  path: string;
  method: string;
  category: string;
  parameters: string[];
  requires_auth: boolean;
  discovery_status: string;
  test_status: string;
  verdict?: string | null;
  finding_status: FindingValidationStatus;
  associated_finding_ids: string[];
  summary: string;
}

export interface AIProviderInfo {
  provider: string;
  provider_id?: string;
  model: string;
  configured: boolean;
  fallback_mode?: boolean;
  mode?: string;
}

export interface AssessmentSummaryResponse {
  id: string;
  target_url: string;
  scheme?: string;
  host?: string;
  port?: number;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | string;
  started_at: string;
  updated_at?: string | null;
  completed_at?: string | null;
  failure_reason?: string | null;
  endpoints_discovered_count: number;
  endpoints_tested_count: number;
  confirmed_findings_count: number;
  suspicious_results_count: number;
  not_confirmed_count?: number;
  inconclusive_count?: number;
  not_tested_count?: number;
  no_confirmed_vulnerabilities?: boolean;
  no_confirmed_message?: string;
  summary_text: string;
  markdown_content: string;
  stages: Record<string, AssessmentStageState>;
  events: AssessmentEventItem[];
  findings: FindingItem[];
  discovered_endpoints?: DiscoveredEndpointItem[];
  ai_provider?: AIProviderInfo;
}

export type TargetApprovalStatus =
  | "PENDING"
  | "APPROVED"
  | "REJECTED"
  | "REVOKED"
  | "EXPIRED";

export type AuthorizationBasis =
  | "admin_approved"
  | "written_permission"
  | "bug_bounty_scope"
  | "domain_ownership_challenge"
  | "local_development";

export interface TargetProfile {
  id: string;
  hostname: string;
  base_url: string;
  allowed_schemes: string[];
  allowed_ports: number[];
  allowed_paths: string[];
  allowed_methods: string[];
  authorization_basis: AuthorizationBasis | string;
  permission_reference: string;
  approval_status: TargetApprovalStatus;
  approved_by?: string | null;
  approved_at?: string | null;
  created_at: string;
  expires_at?: string | null;
  revoked_at?: string | null;
  revocation_reason?: string | null;
  verification_token?: string | null;
  verified_at?: string | null;
  is_local_test: boolean;
  notes?: string | null;
}

export interface TargetCheckResponse {
  target_url: string;
  hostname: string;
  is_authorized: boolean;
  status: TargetApprovalStatus | "UNREGISTERED";
  reason: string;
  profile?: TargetProfile | null;
}
