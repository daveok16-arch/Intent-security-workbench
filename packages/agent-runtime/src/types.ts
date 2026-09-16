/**
 * AI Security Controller Types & Domain Models
 * Phase 6 — AI Security Control Plane Core
 * 
 * Invariants:
 * - Strict separation of ground-truth FACTS from unproven HYPOTHESES.
 * - Deterministic Research State Machine with explicit transition guards.
 * - Typed tool definitions preventing arbitrary execution or unrestricted database access.
 */

import {
  Program,
  Target,
  ScopeEntry,
  Investigation,
  AnalysisJob,
  EvidenceArtifact,
  Finding,
  FindingStatus,
  Ecosystem,
  TargetType,
  ScopeAssetType,
  ScopeInclusionStatus,
} from '../../core/src/index.js';

export { ScopeAssetType, ScopeInclusionStatus, TargetType, Ecosystem };

// ==============================================================================
// 1. Research State Machine Phases
// ==============================================================================

export enum ResearchPhase {
  IDLE = 'IDLE',
  UNDERSTANDING_REQUEST = 'UNDERSTANDING_REQUEST',
  PLANNING = 'PLANNING',
  POLICY_VALIDATION = 'POLICY_VALIDATION',
  SCOPE_VALIDATION = 'SCOPE_VALIDATION',
  TARGET_VALIDATION = 'TARGET_VALIDATION',
  SOURCE_ACQUISITION = 'SOURCE_ACQUISITION',
  SOURCE_VERIFICATION = 'SOURCE_VERIFICATION',
  CAPABILITY_ASSESSMENT = 'CAPABILITY_ASSESSMENT',
  ANALYSIS_PLANNING = 'ANALYSIS_PLANNING',
  ANALYSIS_EXECUTION = 'ANALYSIS_EXECUTION',
  RESULT_CORRELATION = 'RESULT_CORRELATION',
  HYPOTHESIS_FORMATION = 'HYPOTHESIS_FORMATION',
  CORROBORATION = 'CORROBORATION',
  VERIFICATION_REQUESTED = 'VERIFICATION_REQUESTED',
  IMPACT_VERIFICATION = 'IMPACT_VERIFICATION',
  ELIGIBILITY_VERIFICATION = 'ELIGIBILITY_VERIFICATION',
  REPORT_PREPARATION = 'REPORT_PREPARATION',
  BLOCKED = 'BLOCKED',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

// ==============================================================================
// 2. Fact vs Hypothesis Model
// ==============================================================================

export interface ResearchFact {
  id: string;
  category: 'ENVIRONMENT' | 'PROGRAM' | 'SCOPE' | 'TARGET' | 'SOURCE' | 'CAPABILITY' | 'EXECUTION' | 'VERIFICATION';
  statement: string;
  source: string; // e.g., 'ScopeDecisionService', 'GitSourceProvider', 'FoundryEngine', 'ArtifactStorage'
  verified_at: string;
  confidence: number; // 1.0 = mathematically/cryptographically verified fact
  metadata?: Record<string, any>;
}

export interface ResearchHypothesis {
  id: string;
  title: string;
  premise: string;
  target_id: string;
  supporting_fact_ids: string[];
  refuting_fact_ids?: string[];
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'ACTIVE' | 'DISPROVED' | 'CORROBORATED' | 'PROVEN';
  requires_verification: boolean;
  suggested_verification_operation?: string;
  created_at: string;
  updated_at: string;
}

export interface ResearchEvidenceRef {
  id: string;
  artifact_id: string;
  artifact_type: string;
  sha256: string;
  summary: string;
  producer: string;
  producer_version: string;
  recorded_at: string;
}

export interface ResearchDecision {
  id: string;
  phase: ResearchPhase;
  decision: string;
  reason: string;
  alternatives_considered?: string[];
  timestamp: string;
}

export interface ResearchBlocker {
  id: string;
  phase: ResearchPhase;
  code: string; // e.g. 'OUT_OF_SCOPE', 'SANDBOX_VIOLATION', 'ENGINE_UNAVAILABLE', 'APPROVAL_REQUIRED'
  message: string;
  resolution_hint: string;
  blocking_entity_id?: string;
  timestamp: string;
}

export interface ResearchUnknown {
  id: string;
  question: string;
  context: string;
  impact?: string;
  status: 'UNRESOLVED' | 'RESOLVED' | 'DISMISSED';
  resolution_fact_id?: string;
  resolution_summary?: string;
  created_at: string;
  resolved_at?: string;
}

export interface CompiledScopeAsset {
  asset_identifier: string;
  asset_type: ScopeAssetType;
  inclusion_status: ScopeInclusionStatus;
  instruction?: string;
}

export interface CompiledSuggestedTarget {
  name: string;
  target_type: TargetType;
  ecosystem: Ecosystem;
  primary_location: string;
  repository_url?: string;
}

export interface CompiledPolicyAndScope {
  program_name: string;
  policy_summary: string;
  safe_harbor: boolean;
  testing_rules: string[];
  disclosure_policy: string;
  scope_entries: CompiledScopeAsset[];
  suggested_targets: CompiledSuggestedTarget[];
  unknowns: Array<{ question: string; context: string; impact: string }>;
}

export interface UserApprovalRequest {
  id: string;
  action: string;
  description: string;
  target_id?: string;
  sensitive: boolean;
  required_policy_check: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  created_at: string;
  resolved_at?: string;
  resolution_reason?: string;
}

export interface CapabilityMatrixEntry {
  engine_id: string;
  name: string;
  ecosystem: string;
  status: 'APPLICABLE' | 'NOT_APPLICABLE' | 'UNAVAILABLE' | 'NOT_INSTALLED';
  applicable: boolean;
  installed: boolean;
  version?: string;
  path?: string;
  reason: string;
}

export interface ResearchPlanStep {
  id: string;
  order: number;
  phase: ResearchPhase;
  title: string;
  description: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'BLOCKED' | 'SKIPPED' | 'FAILED';
  prerequisite_steps: string[];
  executed_tools: string[];
  result_summary?: string;
  error?: string;
}

export interface ResearchPlan {
  id: string;
  objective: string;
  steps: ResearchPlanStep[];
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 3. Persistent Controller State
// ==============================================================================

export interface ControllerState {
  investigation_id: string;
  session_id: string;
  program_id?: string;
  target_id?: string;
  current_phase: ResearchPhase;
  current_objective: string;
  current_activity: string;
  plan: ResearchPlan | null;
  facts: ResearchFact[];
  hypotheses: ResearchHypothesis[];
  unknowns: ResearchUnknown[];
  evidence_refs: ResearchEvidenceRef[];
  decisions: ResearchDecision[];
  blockers: ResearchBlocker[];
  approvals: UserApprovalRequest[];
  active_jobs: string[];
  capability_matrix: CapabilityMatrixEntry[];
  progress_percentage: number;
  created_at: string;
  updated_at: string;
}

// ==============================================================================
// 4. Typed Tool System Interfaces
// ==============================================================================

export type ToolCategory =
  | 'PROGRAM'
  | 'SCOPE'
  | 'TARGET'
  | 'INVESTIGATION'
  | 'ENGINE'
  | 'EVIDENCE'
  | 'FINDING';

export interface ToolParameterSchema {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required: boolean;
  enum?: string[];
  default?: any;
}

export interface ToolDefinition<TParams = any, TResult = any> {
  name: string;
  category: ToolCategory;
  description: string;
  parameters: Record<string, ToolParameterSchema>;
  requires_approval: boolean;
  execute: (params: TParams, context: ControllerExecutionContext) => Promise<ToolExecutionResult<TResult>>;
}

export interface ToolExecutionResult<TData = any> {
  success: boolean;
  data?: TData;
  error?: string;
  code?: string;
  facts_established?: ResearchFact[];
  blocker_encountered?: ResearchBlocker;
  duration_ms: number;
}

export interface ControllerExecutionContext {
  session_id: string;
  investigation_id?: string;
  program_id?: string;
  target_id?: string;
  is_approved: (action: string) => boolean;
}

// ==============================================================================
// 5. Policy Gate Verdict
// ==============================================================================

export interface PolicyGateVerdict {
  allowed: boolean;
  code: string;
  explanation: string;
  requires_user_approval: boolean;
  approval_request?: UserApprovalRequest;
  checks: {
    target_registered: boolean;
    scope_permitted: boolean;
    policy_authorized: boolean;
    sandbox_safe: boolean;
    prerequisites_met: boolean;
  };
}

// ==============================================================================
// 6. High-Level Controller Telemetry Events
// ==============================================================================

export enum ControllerEventType {
  PROGRAM_VERIFIED = 'PROGRAM_VERIFIED',
  SCOPE_VERIFIED = 'SCOPE_VERIFIED',
  TARGET_ACQUIRED = 'TARGET_ACQUIRED',
  SOURCE_VERIFIED = 'SOURCE_VERIFIED',
  CAPABILITY_ASSESSED = 'CAPABILITY_ASSESSED',
  ANALYSIS_STARTED = 'ANALYSIS_STARTED',
  ANALYSIS_COMPLETED = 'ANALYSIS_COMPLETED',
  CANDIDATE_DISCOVERED = 'CANDIDATE_DISCOVERED',
  VERIFICATION_STARTED = 'VERIFICATION_STARTED',
  VERIFICATION_COMPLETED = 'VERIFICATION_COMPLETED',
  ACTION_BLOCKED = 'ACTION_BLOCKED',
  POLICY_COMPILED = 'POLICY_COMPILED',
  UNKNOWN_IDENTIFIED = 'UNKNOWN_IDENTIFIED',
  UNKNOWN_RESOLVED = 'UNKNOWN_RESOLVED',
  INVESTIGATION_COMPLETED = 'INVESTIGATION_COMPLETED',
  CONTROLLER_PHASE_CHANGED = 'CONTROLLER_PHASE_CHANGED',
  CONTROLLER_DECISION_MADE = 'CONTROLLER_DECISION_MADE',
  USER_APPROVAL_REQUESTED = 'USER_APPROVAL_REQUESTED',
  USER_APPROVAL_RESOLVED = 'USER_APPROVAL_RESOLVED',
}
