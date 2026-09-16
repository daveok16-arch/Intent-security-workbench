/**
 * Dynamic Verification & Exploit-Witness Engine Types
 * Intent Security Workbench - Phase 5
 *
 * Formal rules:
 * - A generated exploit payload is NOT evidence.
 * - A generated transaction is NOT evidence.
 * - A simulated result is NOT evidence.
 * - A Z3 counterexample is NOT automatically an exploit.
 * - Only an actually executed verification attempt with captured runtime evidence may be classified as dynamically reproduced.
 */

export type TargetEnvironment =
  | 'LOCAL_SOURCE'
  | 'LOCAL_NODE'
  | 'LOCAL_FORK'
  | 'CONTROLLED_TESTNET'
  | 'LOCAL_ANVIL'
  | 'LOCAL_SIMNET'
  | 'DOCKER_ISOLATED'
  | string;

export type DynamicVerificationJobStatus =
  | 'QUEUED'
  | 'PREPARING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'TIMEOUT'
  | 'TOOL_UNAVAILABLE'
  | 'ENVIRONMENT_INVALID'
  | 'TARGET_REJECTED';

export type DynamicReproductionResult =
  | 'REPRODUCED'
  | 'NOT_REPRODUCED'
  | 'INCONCLUSIVE'
  | 'EXECUTION_FAILED';

export type StateDiffStatus =
  | 'PROTECTED_STATE_CHANGED'
  | 'PROTECTED_STATE_UNCHANGED'
  | 'STATE_OBSERVATION_UNAVAILABLE';

export type PoCState =
  | 'GENERATED'
  | 'EXECUTED'
  | 'REPRODUCED'
  | 'NOT_REPRODUCED';

export interface ToolDetectionResult {
  tool: string;
  executable: string;
  installed: boolean;
  version: string | null;
  executable_path: string | null;
  status: 'AVAILABLE' | 'NOT_INSTALLED' | 'ERROR';
  error: string | null;
  capabilities: string[];
}

export interface TargetValidationResult {
  valid: boolean;
  environment: TargetEnvironment | string;
  target_id: string;
  target_url?: string;
  error?: string;
  rejection_reason?: 'UNAUTHORIZED_PRODUCTION_TARGET' | 'ENVIRONMENT_INVALID' | 'MALFORMED_URL' | null;
}

export interface AuthorizationStateEvidence {
  caller: string;
  owner: string;
  role?: string;
  permission?: string;
  caller_is_owner: boolean;
  caller_has_role: boolean;
  caller_authorized: boolean;
  target_operation: string;
  resource_id?: string;
}

export interface StatePropertyDifference {
  path: string;
  before: any;
  after: any;
  is_protected: boolean;
  type?: string;
  old_value?: any;
  new_value?: any;
  protected?: boolean;
}

export interface StateDiffResult {
  status: StateDiffStatus;
  differences: StatePropertyDifference[];
  diffs?: StatePropertyDifference[];
  has_changes?: boolean;
  protected_changed: boolean;
  summary: string;
  metrics?: {
    keys_added: number;
    keys_removed: number;
    keys_modified: number;
    protected_keys_mutated: number;
  };
}

export interface TransactionOrCallTrace {
  from: string;
  to: string;
  call_type?: string;
  function_name?: string;
  calldata?: string;
  value?: string;
  gas_used?: number;
  status: 'SUCCESS' | 'REVERTED' | 'FAILED';
  output?: string;
  error?: string;
}

export interface ExecutionTrace {
  command: string;
  arguments: string[];
  environment_metadata: Record<string, any>;
  working_directory: string;
  source_snapshot_hash: string | null;
  tool_version: string | null;
  start_time: string;
  end_time: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  traces: TransactionOrCallTrace[];
  events: Array<{ name: string; params: Record<string, any> }>;
}

export interface PoCArtifact {
  id: string;
  state: PoCState;
  runtime: string;
  payload_content: string;
  payload_sha256?: string;
  format: 'FOUNDRY_TEST' | 'CLARINET_TEST' | 'CURL' | 'CUSTOM_SCRIPT';
  created_at: string;
  executed_at?: string;
  reproduced_at?: string;
  execution_result?: DynamicReproductionResult;
}

export interface DynamicVerificationJob {
  id: string;
  investigation_id: string;
  candidate_id: string;
  target_id: string;
  runtime: 'EVM' | 'CLARITY' | string;
  environment: TargetEnvironment;
  tool: string;
  tool_version: string | null;
  command: string;
  status: DynamicVerificationJobStatus;
  started_at: string;
  completed_at: string | null;
  exit_code: number | null;
  stdout_artifact_id: string | null;
  stderr_artifact_id: string | null;
  execution_trace_artifact_id: string | null;
  state_before_artifact_id: string | null;
  state_after_artifact_id: string | null;
  result: DynamicReproductionResult | null;
  failure_reason: string | null;
  stdout: string;
  stderr: string;
  trace: ExecutionTrace | null;
  state_before: Record<string, any> | null;
  state_after: Record<string, any> | null;
  state_diff: StateDiffResult | null;
  authorization_state: AuthorizationStateEvidence | null;
  formal_verification_id: string | null;
  poc_state: PoCState;
  poc_artifact_id: string | null;
  metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface DynamicVerificationOptions {
  investigation_id: string;
  candidate_id?: string;
  target_id?: string;
  target_url?: string;
  runtime?: 'EVM' | 'CLARITY' | 'HTTP' | 'API' | string;
  environment?: TargetEnvironment;
  timeout_ms?: number;
  source_snapshot_id?: string | null;
  formal_verification_id?: string | null;
  caller?: string;
  owner?: string;
  operation?: string;
  custom_fixture_dir?: string;
  working_directory?: string;
  test_filter?: string;
  endpoint?: string;
  method?: string;
  objectId?: string;
  authenticatedCaller?: string;
  resourceOwner?: string;
  callerRole?: string;
  initialDbState?: any;
  handlerType?: 'VULNERABLE' | 'SECURE';
  parameters?: Record<string, any>;
}

export interface RuntimeExecutionResult {
  status: DynamicVerificationJobStatus;
  result: DynamicReproductionResult;
  tool: string;
  tool_version: string | null;
  executable_path: string | null;
  command_executed: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  trace: ExecutionTrace;
  state_before: Record<string, any> | null;
  state_after: Record<string, any> | null;
  state_diff: StateDiffResult;
  authorization_state: AuthorizationStateEvidence;
  failure_reason?: string | null;
  error?: string | null;
}
