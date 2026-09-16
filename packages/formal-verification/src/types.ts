/**
 * Types & Domain Interfaces for Real Z3 Formal Verification Subsystem
 * Intent Security Workbench - Phase 4
 *
 * Strict Phase 4 Invariant:
 * Z3 must NEVER be used as a decorative "proof generator".
 * Clear separation between:
 *  - SOURCE FACT (observed directly from AST, Semgrep, contract)
 *  - MODEL ASSUMPTION (explicit unproven assumption)
 *  - FORMAL PROPERTY (desired security invariant)
 *  - SOLVER RESULT (actual Z3 output: sat, unsat, unknown, timeout)
 *  - FORMAL COUNTEREXAMPLE (model assignment, NOT production exploit confirmation)
 */

export enum VerificationStatus {
  PROVEN = 'PROVEN',
  REFUTED = 'REFUTED',
  COUNTEREXAMPLE_FOUND = 'COUNTEREXAMPLE_FOUND',
  PROPERTY_HOLDS_FOR_MODEL = 'PROPERTY_HOLDS_FOR_MODEL',
  FORMALLY_SUPPORTED = 'COUNTEREXAMPLE_FOUND',
  FORMALLY_REFUTED = 'PROPERTY_HOLDS_FOR_MODEL',
  UNKNOWN = 'UNKNOWN',
  INCONCLUSIVE = 'INCONCLUSIVE',
  MODEL_INVALID = 'MODEL_INVALID',
  MODEL_UNDERCONSTRAINED = 'MODEL_UNDERCONSTRAINED',
  ASSUMPTION_DEPENDENT = 'ASSUMPTION_DEPENDENT',
  SOLVER_UNAVAILABLE = 'SOLVER_UNAVAILABLE',
  EXECUTION_FAILED = 'EXECUTION_FAILED',
  TIMEOUT = 'TIMEOUT',
}

export enum ModelSoundnessStatus {
  SOUND = 'SOUND',
  MODEL_UNDERCONSTRAINED = 'MODEL_UNDERCONSTRAINED',
  ASSUMPTION_DEPENDENT = 'ASSUMPTION_DEPENDENT',
  CONTRADICTORY_MODEL = 'CONTRADICTORY_MODEL',
  INVALID_SYNTAX = 'INVALID_SYNTAX',
}

export enum PropertyCategory {
  AUTHORIZATION = 'AUTHORIZATION',
  ACCESS_CONTROL = 'ACCESS_CONTROL',
  TENANT_ISOLATION = 'TENANT_ISOLATION',
  STATE_INTEGRITY = 'STATE_INTEGRITY',
  OBJECT_OWNERSHIP = 'OBJECT_OWNERSHIP',
}

export interface SecurityProperty {
  id: string;
  name: string;
  description: string;
  category: PropertyCategory | string;
  cwe?: string;
  source?: string;
  version: string;
}

export type OriginType =
  | 'SOURCE_OBSERVATION'
  | 'MODEL_ASSUMPTION'
  | 'PROPERTY_INVARIANT'
  | 'API_CONTRACT_PARAM'
  | 'SOURCE_FACT';

export interface SourceLocation {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
}

export interface FormalVariableOrigin {
  origin_type: OriginType;
  source_location?: SourceLocation;
  symbol?: string;
  reason?: string;
}

export interface FormalVariable {
  name: string;
  type: 'Bool' | 'Int' | 'String' | 'Sort' | string;
  sort_name?: string;
  description?: string;
  origin?: FormalVariableOrigin;
}

export type VariableDefinition = FormalVariable;

export interface ConstraintOrigin {
  origin_type: OriginType;
  source_location?: SourceLocation;
  source_fact_description?: string;
  reason?: string;
}

export interface Constraint {
  id: string;
  name: string;
  expression?: string;
  smt_representation: string;
  is_assumption: boolean; // true => MODEL_ASSUMPTION, false => SOURCE FACT
  origin?: ConstraintOrigin;
  rationale?: string;
}

export type ModelConstraint = Constraint;

export interface ModelAssumption {
  id: string;
  assumption_text: string;
  rationale: string;
  impact_on_soundness?: string;
  source_reference?: string;
  smt_form?: string;
}

export interface SourceFact {
  id?: string;
  description: string;
  file: string;
  line?: number;
  snippet?: string;
  code_snippet?: string;
  observed_via: 'TREE_SITTER' | 'SEMGREP' | 'OPENAPI_CONTRACT' | 'AUTH_ANALYZER' | string;
}

export interface Counterexample {
  label: 'FORMAL_COUNTEREXAMPLE';
  is_exploit_confirmed: false; // Must strictly NEVER be marked exploit confirmed
  assignments: Record<string, string | number | boolean>;
  raw_model_string: string;
  variables_present: string[];
}

export interface VerificationResult {
  id: string;
  property_id: string;
  property: SecurityProperty;
  investigation_id: string;
  source_snapshot_id?: string | null;
  candidate_id?: string | null;
  model_hash: string;
  solver: string; // 'Z3'
  solver_version: string; // e.g. '4.8.12 - 64 bit'
  executable_path: string;
  command_executed: string;
  execution_time_ms: number;
  exit_code: number;
  status: VerificationStatus;
  solver_result_raw: 'sat' | 'unsat' | 'unknown' | 'timeout' | 'error';
  assumptions: ModelAssumption[];
  constraints: Constraint[];
  source_facts: SourceFact[];
  variables: FormalVariable[];
  counterexample?: Counterexample | null;
  smt_lib_input: string;
  smt_lib_sha256: string;
  smt_artifact_id?: string;
  result_artifact_id?: string;
  stdout: string;
  stderr: string;
  model_scope: string;
  boundary_clarification: string;
  soundness_issues?: string[];
  created_at: string;
}

export interface FormalModelDefinition {
  name: string;
  description?: string;
  target_id: string;
  investigation_id?: string;
  source_snapshot_id?: string | null;
  candidate_id?: string | null;
  sorts?: string[];
  variables: FormalVariable[];
  constraints: Constraint[];
  assumptions: ModelAssumption[];
  source_facts?: SourceFact[];
  sourceFacts?: SourceFact[];
  property?: SecurityProperty;
  query_property?: SecurityProperty;
  query_mode?: 'UNAUTHORIZED_ACCESS_REACHABLE' | 'PROPERTY_HOLDS_GLOBALLY';
}

export interface ModelSoundnessResult {
  valid: boolean;
  underconstrained: boolean;
  assumption_dependent: boolean;
  errors: string[];
  warnings: string[];
}

export interface Z3HostInfo {
  installed: boolean;
  executable_path: string | null;
  version: string | null;
  raw_version_output: string;
  status?: string;
  error?: string | null;
}
