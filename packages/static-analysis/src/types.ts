/**
 * Static & Structural Security Analysis Types
 * Intent Security Workbench - Phase 2
 */

import { Severity, Confidence, FindingStatus } from '../../core/src/index.js';

export enum StaticRuleCategory {
  BOLA = 'BOLA',
  BOLA_IDOR = 'BOLA_IDOR',
  ACCESS_CONTROL = 'ACCESS_CONTROL',
  AUTHENTICATION = 'AUTHENTICATION',
  TENANT_ISOLATION = 'TENANT_ISOLATION',
  INPUT_VALIDATION = 'INPUT_VALIDATION',
  INJECTION = 'INJECTION',
  COMMAND_EXECUTION = 'COMMAND_EXECUTION',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  SECRET_EXPOSURE = 'SECRET_EXPOSURE',
  INSECURE_DESERIALIZATION = 'INSECURE_DESERIALIZATION',
  SSRF = 'SSRF',
  SQL_INJECTION = 'SQL_INJECTION',
  XSS = 'XSS',
  CSRF = 'CSRF',
  OPEN_REDIRECT = 'OPEN_REDIRECT',
  SMART_CONTRACT = 'SMART_CONTRACT',
}

export type StaticEngineType = 'treesitter' | 'semgrep' | 'correlation';

export interface StaticRule {
  id: string;
  name: string;
  title?: string;
  description: string;
  category: StaticRuleCategory | string;
  languages: string[];
  severity: Severity;
  cwe_ids: string[];
  owasp_categories: string[];
  source: string;
  version: string;
  confidence: Confidence;
  confidence_basis: string; // Documented deterministic basis
  remediation: string;
  engine_support?: string[];
  patterns?: any;
  // Semgrep rule definition in JSON/YAML format
  semgrep_yaml?: string;
  // Tree-sitter structural query pattern
  structural_query?: {
    type: string;
    target_nodes?: string[];
    sensitive_sinks?: string[];
    authorization_boundaries?: string[];
    requires_auth_check?: boolean;
    requires_state_mutation?: boolean;
  };
}

export interface CandidateFinding {
  id: string;
  investigation_id: string;
  target_id: string;
  title: string;
  category: StaticRuleCategory | string;
  severity: Severity;
  status: FindingStatus; // Always CANDIDATE initially
  confidence: Confidence;
  confidence_basis: string;
  engine: StaticEngineType | string;
  engine_version: string;
  rule_id: string;
  rule_version: string;
  source_snapshot_id: string;
  file_path: string;
  line_start: number;
  line_end: number;
  column_start?: number;
  column_end?: number;
  commit_hash?: string;
  repository_url?: string;
  matched_code: string;
  data_flow?: {
    source?: string;
    flow?: string[];
    object?: string;
    authorization?: string;
    sink?: string;
  };
  structural_evidence?: {
    ast_node_type?: string;
    function_name?: string;
    has_auth_boundary?: boolean;
    is_state_mutation?: boolean;
    mutation_sink?: string;
  };
  evidence_artifact_ids: string[];
  cwe_ids: string[];
  owasp_categories: string[];
  remediation: string;
  corroborated?: boolean;
  status_history: {
    from_status: FindingStatus | null;
    to_status: FindingStatus;
    timestamp: string;
    actor: string;
    reason: string;
  }[];
  provenance: {
    source_snapshot_id: string;
    engine: string;
    engine_version: string;
    rule_id: string;
    rule_version: string;
    matched_at: string;
    source_file: string;
    line: number;
  };
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface TreeSitterStructuralMatch {
  rule_id: string;
  rule_name: string;
  category: StaticRuleCategory;
  function_name?: string;
  line_start: number;
  line_end: number;
  column_start?: number;
  column_end?: number;
  matched_snippet: string;
  has_authorization_boundary: boolean;
  is_state_mutation: boolean;
  is_sink: boolean;
  sink_name?: string;
  resource_identifier?: string;
  details: Record<string, any>;
}

export interface TreeSitterParseResult {
  source_file: string;
  language: string;
  parser_version: string;
  grammar_version?: string;
  source_snapshot_id: string;
  parse_status: 'SUCCESS' | 'ERROR' | 'PARTIAL' | 'UNSUPPORTED_LANGUAGE';
  error_count: number;
  node_count: number;
  root_node?: any;
  sha256?: string;
  ast_artifact_id?: string;
  ast_sha256?: string;
  structural_matches: TreeSitterStructuralMatch[];
  source_locations: {
    line: number;
    column: number;
    node_type: string;
  }[];
}

export interface SemgrepMatchResult {
  rule_id: string;
  file_path: string;
  line_start: number;
  line_end: number;
  column_start?: number;
  column_end?: number;
  message: string;
  matched_code: string;
  severity: Severity;
  metadata: Record<string, any>;
  dataflow_trace?: any;
}

export interface StaticAnalysisExecutionResult {
  investigation_id: string;
  target_id: string;
  source_snapshot_id: string;
  treesitter: {
    status: 'COMPLETED' | 'FAILED' | 'UNAVAILABLE' | 'NOT_INSTALLED';
    parser_version: string;
    files_scanned: number;
    parse_errors: number;
    artifacts_created: string[];
    duration_ms: number;
  };
  semgrep: {
    status: 'COMPLETED' | 'FAILED' | 'UNAVAILABLE' | 'NOT_INSTALLED';
    binary_path: string | null;
    version: string | null;
    command: string;
    exit_code: number;
    stdout_artifact_id?: string;
    stderr_artifact_id?: string;
    duration_ms: number;
    raw_findings_count: number;
  };
  correlation: {
    candidates_created: number;
    corroborated_candidates: number;
    duration_ms: number;
  };
  candidates: CandidateFinding[];
  executed_at: string;
  total_duration_ms: number;
}
