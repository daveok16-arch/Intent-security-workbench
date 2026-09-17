/**
 * Core Domain Models & State Machine Enums for Intent Security Workbench
 * Phase 0 Foundational Architecture
 */

export enum ProgramStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  SUSPENDED = 'SUSPENDED',
  ARCHIVED = 'ARCHIVED',
  UNKNOWN = 'UNKNOWN',
}

export enum ProgramFreshnessStatus {
  CURRENT = 'CURRENT',
  STALE = 'STALE',
  EXPIRED = 'EXPIRED',
  UNKNOWN = 'UNKNOWN',
}

export enum ScopeInclusionStatus {
  IN_SCOPE = 'IN_SCOPE',
  OUT_OF_SCOPE = 'OUT_OF_SCOPE',
  UNKNOWN = 'UNKNOWN',
}

export enum ScopeAssetType {
  DOMAIN = 'DOMAIN',
  URL = 'URL',
  API = 'API',
  REPOSITORY = 'REPOSITORY',
  CONTRACT = 'CONTRACT',
  SMART_CONTRACT = 'SMART_CONTRACT',
  TOKEN = 'TOKEN',
  CHAIN = 'CHAIN',
  APPLICATION = 'APPLICATION',
  MOBILE_APP = 'MOBILE_APP',
  OTHER = 'OTHER',
}

export enum TargetAuthorizationStatus {
  NOT_EVALUATED = 'NOT_EVALUATED',
  AUTHORIZED = 'AUTHORIZED',
  NOT_AUTHORIZED = 'NOT_AUTHORIZED',
  UNKNOWN = 'UNKNOWN',
}

export enum TargetScopeStatus {
  NOT_EVALUATED = 'NOT_EVALUATED',
  IN_SCOPE = 'IN_SCOPE',
  OUT_OF_SCOPE = 'OUT_OF_SCOPE',
  UNKNOWN = 'UNKNOWN',
}

export enum FindingStatus {
  CANDIDATE = 'CANDIDATE',
  HYPOTHESIS = 'CANDIDATE',
  ANALYZING = 'ANALYZING',
  VERIFICATION_REQUIRED = 'VERIFICATION_REQUIRED',
  TESTING = 'TESTING',
  CORROBORATED = 'CORROBORATED',
  REPRODUCED = 'REPRODUCED',
  VALIDATED = 'VALIDATED',
  CONFIRMED = 'CONFIRMED',
  CONFIRMED_VULNERABILITY = 'CONFIRMED',
  REJECTED = 'REJECTED',
  INCONCLUSIVE = 'INCONCLUSIVE',
  OUT_OF_SCOPE = 'OUT_OF_SCOPE',
}

export enum JobStatus {
  QUEUED = 'QUEUED',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum InvestigationStatus {
  CREATED = 'CREATED',
  ACTIVE = 'ACTIVE',
  PAUSED = 'PAUSED',
  COMPLETED = 'COMPLETED',
  ARCHIVED = 'ARCHIVED',
}

export enum SourceAcquisitionStatus {
  SOURCE_NOT_ACQUIRED = 'SOURCE_NOT_ACQUIRED',
  SOURCE_ACQUIRED = 'SOURCE_ACQUIRED',
  SOURCE_ACQUISITION_FAILED = 'SOURCE_ACQUISITION_FAILED',
}

export enum TargetType {
  SMART_CONTRACT = 'SMART_CONTRACT',
  PROTOCOL = 'PROTOCOL',
  WEB_APPLICATION = 'WEB_APPLICATION',
  REST_API = 'REST_API',
  BINARY_NODE = 'BINARY_NODE',
  BINARY = 'BINARY',
  LIBRARY = 'LIBRARY',
  REPOSITORY = 'REPOSITORY',
  DEPLOYED_SYSTEM = 'DEPLOYED_SYSTEM',
}

export enum Ecosystem {
  EVM = 'EVM',
  ETHEREUM = 'EVM',
  SOLANA = 'SOLANA',
  SOLANA_RUST = 'SOLANA_RUST',
  RUST = 'RUST',
  CLARITY = 'CLARITY',
  CLARITY_STACKS = 'CLARITY_STACKS',
  MOVE = 'MOVE',
  WEB_API = 'WEB_API',
  WEB_APP = 'WEB_APP',
  COSMOS = 'COSMOS',
  COSMWASM = 'COSMWASM',
  OTHER = 'OTHER',
}

export enum BountyPlatform {
  IMMUNEFI = 'IMMUNEFI',
  HACKENPROOF = 'HACKENPROOF',
  CANTINA = 'CANTINA',
  HACKERONE = 'HACKERONE',
  CODE4RENA = 'CODE4RENA',
  CUSTOM = 'CUSTOM',
}

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

export enum Confidence {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  UNVERIFIED = 'UNVERIFIED',
}

export enum ArtifactType {
  SOURCE = 'SOURCE',
  ENGINE_STDOUT = 'ENGINE_STDOUT',
  ENGINE_STDERR = 'ENGINE_STDERR',
  ENGINE_RESULT = 'ENGINE_RESULT',
  AST = 'AST',
  TAINT_FLOW = 'TAINT_FLOW',
  CFG = 'CFG',
  SMT_INPUT = 'SMT_INPUT',
  SMT_RESULT = 'SMT_RESULT',
  TEST_OUTPUT = 'TEST_OUTPUT',
  EXECUTION_TRACE = 'EXECUTION_TRACE',
  STATE_SNAPSHOT = 'STATE_SNAPSHOT',
  STATE_DIFF = 'STATE_DIFF',
  SCREENSHOT = 'SCREENSHOT',
  LOG = 'LOG',
  REPORT = 'REPORT',
  LOG_FILE = 'LOG_FILE',
  // Backward compatibility
  RAW_STDOUT = 'RAW_STDOUT',
  RAW_STDERR = 'RAW_STDERR',
  SOURCE_SNAPSHOT = 'SOURCE_SNAPSHOT',
  AST_EXPORT = 'AST_EXPORT',
  TRANSACTION_PAYLOAD = 'TRANSACTION_PAYLOAD',
  REPRODUCTION_SCRIPT = 'REPRODUCTION_SCRIPT',
  SYSTEM_LOG = 'SYSTEM_LOG',
  COMMAND_LOG = 'COMMAND_LOG',
  ACQUISITION_LOG = 'ACQUISITION_LOG',
  GIT_METADATA = 'GIT_METADATA',
}

export enum ArtifactProvenance {
  /**
   * Produced by a real engine execution or a verified internal subsystem. The
   * workbench generated the bytes from an observed process, so the artifact is
   * machine-verifiable evidence.
   */
  MACHINE_VERIFIABLE = 'MACHINE_VERIFIABLE',
  /**
   * Supplied by a caller (e.g. POST /api/evidence) and merely hashed by the
   * workbench. The digest proves the bytes were not altered after storage, but
   * proves nothing about where they came from. Cannot satisfy the gate to
   * VALIDATED / CONFIRMED.
   */
  CLIENT_SUPPLIED = 'CLIENT_SUPPLIED',
}

export enum EvidenceEventType {
  SOURCE_ACQUIRED = 'SOURCE_ACQUIRED',
  SOURCE_ACQUISITION_STARTED = 'SOURCE_ACQUISITION_STARTED',
  SOURCE_ACQUISITION_COMPLETED = 'SOURCE_ACQUISITION_COMPLETED',
  SOURCE_ACQUISITION_FAILED = 'SOURCE_ACQUISITION_FAILED',
  ENGINE_STARTED = 'ENGINE_STARTED',
  ENGINE_COMPLETED = 'ENGINE_COMPLETED',
  ENGINE_FAILED = 'ENGINE_FAILED',
  ARTIFACT_CREATED = 'ARTIFACT_CREATED',
  VERIFICATION_STARTED = 'VERIFICATION_STARTED',
  VERIFICATION_COMPLETED = 'VERIFICATION_COMPLETED',
  METADATA_CORRECTED = 'METADATA_CORRECTED',
  SCOPE_EVALUATED = 'SCOPE_EVALUATED',
  TARGET_REGISTERED = 'TARGET_REGISTERED',
}

export enum SourceSnapshotStatus {
  PENDING = 'PENDING',
  ACQUIRING = 'ACQUIRING',
  ACQUIRED = 'ACQUIRED',
  FAILED = 'FAILED',
}

export enum EngineExecutionStatus {
  NO_ENGINE = 'NO_ENGINE',
  ENGINE_NOT_INSTALLED = 'ENGINE_NOT_INSTALLED',
  ENGINE_UNAVAILABLE = 'ENGINE_UNAVAILABLE',
  ENGINE_EXECUTION_FAILED = 'ENGINE_EXECUTION_FAILED',
  ENGINE_COMPLETED_NO_FINDINGS = 'ENGINE_COMPLETED_NO_FINDINGS',
  ENGINE_COMPLETED_WITH_FINDINGS = 'ENGINE_COMPLETED_WITH_FINDINGS',
}

export enum EngineStatus {
  AVAILABLE = 'AVAILABLE',
  UNAVAILABLE = 'UNAVAILABLE',
  NOT_INSTALLED = 'NOT_INSTALLED',
  ERROR = 'ERROR',
}

// -------------------------------------------------------------
// Core Domain Entities
// -------------------------------------------------------------

export interface ScopeEntry {
  id: string;
  program_id: string;
  asset_type: ScopeAssetType;
  asset_identifier: string;
  inclusion_status: ScopeInclusionStatus;
  environment?: string;
  technology?: string;
  source_reference?: string;
  restrictions?: string[];
  notes?: string;
  effective_from?: string;
  effective_to?: string;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Program {
  id: string;
  name: string;
  platform: BountyPlatform;
  external_id?: string;
  external_identifier?: string; // alias
  program_url?: string;
  organization?: string;
  description?: string;
  status?: ProgramStatus;
  policy_version?: string;
  scope?: any[];
  exclusions?: string[];
  testing_rules?: string[];
  disclosure_rules?: string[];
  bounty_rules?: string;
  bounty_policy?: string; // alias
  disclosure_policy?: string; // alias
  technology?: string[];
  freshness_status?: ProgramFreshnessStatus;
  retrieved_at?: string;
  last_verified_at?: string;
  source_reference?: string;
  source_hash?: string;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Target {
  id: string;
  program_id: string;
  name: string;
  target_type: TargetType;
  type?: TargetType; // alias
  ecosystem: Ecosystem;
  identifier?: string;
  primary_location?: string; // alias
  repository_url?: string;
  commit_hash?: string;
  branch?: string;
  deployment?: Record<string, any>;
  deployment_information?: Record<string, any>; // alias
  chain?: string;
  contract_address?: string;
  source_hash?: string;
  source_acquisition_status?: SourceAcquisitionStatus;
  authorization_status?: TargetAuthorizationStatus;
  scope_status?: TargetScopeStatus;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface SourceSnapshot {
  id: string;
  target_id: string;
  investigation_id?: string;
  repository_url?: string;
  commit_hash?: string; // requested commit
  resolved_commit_sha?: string; // exact resolved 40-char SHA
  branch?: string;
  acquisition_method?: string;
  retrieval_timestamp?: string;
  acquired_at?: string; // alias
  source_hash?: string; // deterministic tree hash
  provider?: string;
  provider_version?: string;
  acquisition_status?: SourceSnapshotStatus;
  status: SourceSnapshotStatus; // alias
  storage_path?: string;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ScopeDecisionResult {
  decision: ScopeInclusionStatus;
  matched_scope_entry: ScopeEntry | null;
  reason: string;
  policy_version: string;
  evaluated_at: string;
  evaluator_version: string;
  source_reference?: string;
  source_hash?: string;
  provenance: {
    source_reference?: string;
    retrieved_at?: string;
    policy_version?: string;
    source_hash?: string;
    evaluator_version: string;
    target_identifier: string;
  };
}

export interface InvestigationGateCheck {
  name: string;
  passed: boolean;
  message: string;
}

export interface InvestigationGateResult {
  passed: boolean;
  can_proceed: boolean;
  allowed: boolean;
  reason: string;
  evaluated_at: string;
  target_authorization: TargetAuthorizationStatus;
  scope_status: TargetScopeStatus;
  source_status: SourceAcquisitionStatus;
  policy_status?: string;
  checks: InvestigationGateCheck[];
}

export interface Investigation {
  id: string;
  program_id: string;
  target_id: string;
  title: string;
  name?: string;
  source_snapshot_id?: string | null;
  description?: string;
  status: InvestigationStatus;
  created_at: string;
  updated_at: string;
}

export interface AnalysisJob {
  id: string;
  investigation_id: string;
  target_id: string;
  engine: string;
  operation: string;
  status: JobStatus;
  started_at?: string;
  completed_at?: string;
  exit_code?: number;
  stdout_artifact_id?: string;
  stderr_artifact_id?: string;
  execution_status?: EngineExecutionStatus;
  error?: string;
  retry_count: number;
  max_retries: number;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface EvidenceArtifact {
  id: string;
  investigation_id: string;
  target_id?: string;
  artifact_type: ArtifactType | string;
  producer: string;
  producer_version: string;
  source_snapshot_id?: string | null;
  command?: string;
  working_directory?: string;
  path: string;
  size_bytes: number;
  sha256: string;
  mime_type: string;
  created_at: string;
  /**
   * How these bytes came to exist. Defaults to MACHINE_VERIFIABLE for artifacts
   * built by internal subsystems; caller-supplied API payloads are
   * CLIENT_SUPPLIED and cannot back a VALIDATED / CONFIRMED transition.
   */
  provenance?: ArtifactProvenance | string;
  metadata: Record<string, any>;
  // Optional convenience fields
  type?: ArtifactType | string; // alias for artifact_type
  byte_size?: number; // alias for size_bytes
  path_or_reference?: string; // alias for path
  content_preview?: string;
  target_hash?: string;
}

export interface EvidenceEvent {
  id: string;
  investigation_id: string;
  event_type: EvidenceEventType | string;
  timestamp: string;
  actor: string;
  producer: string;
  producer_version: string;
  input_artifacts: string[];
  output_artifacts: string[];
  metadata: Record<string, any>;
}

export interface ProvenanceNode {
  id: string;
  type: 'Investigation' | 'Target' | 'SourceSnapshot' | 'AnalysisJob' | 'Engine' | 'EvidenceEvent' | 'EvidenceArtifact' | 'Finding';
  label: string;
  data: Record<string, any>;
}

export interface ProvenanceEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  label?: string;
}

export interface ProvenanceGraph {
  investigation_id: string;
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
  generated_at: string;
}

export interface ProvenanceChain {
  finding_id: string;
  finding_title: string;
  finding_status: FindingStatus;
  linked_artifacts: {
    artifact_id: string;
    artifact_type: string;
    sha256: string;
    size_bytes: number;
    producer: string;
    producer_version: string;
    path: string;
    created_at: string;
  }[];
  originating_events: {
    event_id: string;
    event_type: string;
    timestamp: string;
    actor: string;
    producer: string;
  }[];
  analysis_jobs: {
    job_id: string;
    engine: string;
    operation: string;
    command?: string;
    exit_code?: number;
    started_at?: string;
    completed_at?: string;
    execution_status?: EngineExecutionStatus;
  }[];
  engines: {
    engine_id: string;
    name: string;
    version: string;
    executable: string;
  }[];
  source_snapshot?: {
    snapshot_id: string;
    commit_hash?: string;
    branch?: string;
    source_hash?: string;
    acquired_at?: string;
    status: SourceSnapshotStatus;
  } | null;
  target?: {
    target_id: string;
    name: string;
    target_type: TargetType;
    ecosystem: Ecosystem;
    repository_url?: string;
  } | null;
  investigation: {
    investigation_id: string;
    title: string;
    status: InvestigationStatus;
  };
  provenance_summary: string;
  disclaimer: string;
}

export interface Finding {
  id: string;
  investigation_id: string;
  target_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  confidence?: Confidence;
  evidence_artifact_ids: string[];
  reproduction_steps?: string;
  mitigation_notes?: string;
  cwe_ids?: string[];
  validation_history?: any[];
  state_history?: {
    from_status: FindingStatus | null;
    to_status: FindingStatus;
    timestamp: string;
    reason: string;
    actor: string;
  }[];
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

// -------------------------------------------------------------
// Strict Finding State Machine Transition Matrix
// -------------------------------------------------------------

export const VALID_FINDING_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  [FindingStatus.CANDIDATE]: [
    FindingStatus.ANALYZING,
    FindingStatus.CORROBORATED,
    FindingStatus.REJECTED,
    FindingStatus.OUT_OF_SCOPE,
  ],
  [FindingStatus.CORROBORATED]: [
    FindingStatus.TESTING,
    FindingStatus.REPRODUCED,
    FindingStatus.VERIFICATION_REQUIRED,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.REJECTED,
  ],
  [FindingStatus.ANALYZING]: [
    FindingStatus.VERIFICATION_REQUIRED,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.REJECTED,
    FindingStatus.OUT_OF_SCOPE,
  ],
  [FindingStatus.VERIFICATION_REQUIRED]: [
    FindingStatus.TESTING,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.REJECTED,
    FindingStatus.OUT_OF_SCOPE,
  ],
  [FindingStatus.TESTING]: [
    FindingStatus.REPRODUCED,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.REJECTED,
  ],
  [FindingStatus.REPRODUCED]: [
    FindingStatus.VALIDATED,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.REJECTED,
  ],
  [FindingStatus.VALIDATED]: [
    FindingStatus.CONFIRMED,
    FindingStatus.REJECTED,
  ],
  [FindingStatus.CONFIRMED]: [], // Terminal verified state
  [FindingStatus.REJECTED]: [
    FindingStatus.CANDIDATE, // Allowed to re-open only if new evidence arises
  ],
  [FindingStatus.INCONCLUSIVE]: [
    FindingStatus.ANALYZING,
    FindingStatus.REJECTED,
  ],
  [FindingStatus.OUT_OF_SCOPE]: [
    FindingStatus.CANDIDATE, // Allowed to re-evaluate if scope policy updates
  ],
};

/**
 * Validates if a state transition is legally permissible under Phase 0 rules.
 *
 * `hasEvidenceArtifacts` gates the terminal verified states. Callers that can
 * distinguish artifact provenance should pass `hasMachineVerifiableEvidence`
 * so that merely hashed caller-supplied payloads cannot reach VALIDATED /
 * CONFIRMED. Omitting it preserves the original count-based behaviour.
 */
export function validateFindingTransition(
  currentStatus: FindingStatus,
  targetStatus: FindingStatus,
  hasEvidenceArtifacts: boolean = false,
  hasMachineVerifiableEvidence?: boolean
): { allowed: boolean; reason?: string } {
  if (currentStatus === targetStatus) {
    return { allowed: true };
  }

  const allowedNext = VALID_FINDING_TRANSITIONS[currentStatus] || [];
  if (!allowedNext.includes(targetStatus)) {
    return {
      allowed: false,
      reason: `Illegal state transition from ${currentStatus} to ${targetStatus}. Permitted next states: [${allowedNext.join(', ')}]`,
    };
  }

  // Non-negotiable evidence requirement before reaching CONFIRMED or VALIDATED
  if ((targetStatus === FindingStatus.CONFIRMED || targetStatus === FindingStatus.VALIDATED) && !hasEvidenceArtifacts) {
    return {
      allowed: false,
      reason: `Cannot transition to ${targetStatus} without linked machine-verifiable evidence artifacts.`,
    };
  }

  // When provenance is known, only engine-produced artifacts qualify. A hash
  // computed over caller-supplied bytes proves integrity, not origin.
  if (
    (targetStatus === FindingStatus.CONFIRMED || targetStatus === FindingStatus.VALIDATED) &&
    hasMachineVerifiableEvidence === false
  ) {
    return {
      allowed: false,
      reason:
        `Cannot transition to ${targetStatus}: linked artifacts are CLIENT_SUPPLIED. ` +
        `A VALIDATED / CONFIRMED finding requires evidence produced by an engine execution ` +
        `or verified internal subsystem, not payloads hashed on the caller's behalf.`,
    };
  }

  return { allowed: true };
}

export * from './scope_decision.js';
export * from './investigation_gate.js';

