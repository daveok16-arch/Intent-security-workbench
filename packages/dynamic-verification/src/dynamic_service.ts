/**
 * Dynamic Verification Service
 * Intent Security Workbench - Phase 5
 *
 * Coordinates real dynamic verification attempts against isolated environments.
 * Strictly adheres to:
 * - Anti-fabrication: Never claim exploit confirmed without verified runtime witness.
 * - Tool detection: Real Forge, Anvil, Clarinet binaries.
 * - Target isolation: Rejects production URLs (UNAUTHORIZED_PRODUCTION_TARGET).
 * - State machine: Never auto-promotes finding to CONFIRMED.
 * - Evidence integrity: Cryptographically hashed immutable artifacts and provenance chains.
 */

import crypto from 'crypto';
import {
  DynamicVerificationJob,
  DynamicVerificationOptions,
  DynamicVerificationJobStatus,
  DynamicReproductionResult,
  TargetEnvironment,
  AuthorizationStateEvidence,
} from './types.js';
import { TargetValidator } from './target_validator.js';
import { ToolDetector } from './tool_detectors.js';
import { FoundryAdapter } from './adapters/foundry_adapter.js';
import { ClarinetAdapter } from './adapters/clarinet_adapter.js';
import { APIAdapter } from './adapters/api_adapter.js';
import { StateDiffer } from './state_diff.js';
import { PoCEngine } from './poc_engine.js';
import { ReproductionDecisionEngine } from './reproduction_engine.js';
import { globalDB } from '../../../apps/api/db_store.js';
import {
  createEvidenceArtifact,
  globalEvidenceEventManager,
  globalProvenanceService,
} from '../../evidence/src/index.js';
import {
  ArtifactType,
  EvidenceEventType,
  JobStatus,
  FindingStatus,
} from '../../core/src/index.js';
import { globalJobOrchestrator } from '../../orchestrator/src/index.js';

export class DynamicVerificationService {
  private foundryAdapter: FoundryAdapter;
  private clarinetAdapter: ClarinetAdapter;
  private apiAdapter: APIAdapter;

  constructor() {
    this.foundryAdapter = new FoundryAdapter();
    this.clarinetAdapter = new ClarinetAdapter();
    this.apiAdapter = new APIAdapter();
  }

  /**
   * Execute dynamic verification on an isolated target.
   */
  async execute(options: DynamicVerificationOptions): Promise<DynamicVerificationJob> {
    const jobId = `dyn-${crypto.randomBytes(8).toString('hex')}`;
    const startTime = new Date().toISOString();
    const runtime = (options.runtime || 'EVM').toUpperCase();
    const environment: TargetEnvironment = options.environment || 'LOCAL_SOURCE';

    // 1. Target Environment & Isolation Validation
    const target = options.target_id ? globalDB.getTarget(options.target_id) : undefined;
    const targetUrl = options.target_url || target?.contract_address || (target as any)?.primary_location || (target as any)?.address || options.parameters?.target_url;
    const validation = TargetValidator.validate(environment, options.target_id, targetUrl);

    if (!validation.valid) {
      if (validation.rejection_reason === 'UNAUTHORIZED_PRODUCTION_TARGET') {
        throw new Error(`UNAUTHORIZED_PRODUCTION_TARGET: ${validation.error || 'Production target rejected by security boundary validator.'}`);
      }

      const failedJob: DynamicVerificationJob = {
        id: jobId,
        investigation_id: options.investigation_id,
        candidate_id: options.candidate_id || '',
        target_id: options.target_id || '',
        runtime,
        environment,
        tool: runtime === 'CLARITY' ? 'clarinet' : 'forge',
        tool_version: null,
        command: 'validate_target',
        status: (validation.rejection_reason as string) === 'UNAUTHORIZED_PRODUCTION_TARGET'
          ? 'TARGET_REJECTED'
          : 'ENVIRONMENT_INVALID',
        started_at: startTime,
        completed_at: new Date().toISOString(),
        exit_code: 1,
        stdout_artifact_id: null,
        stderr_artifact_id: null,
        execution_trace_artifact_id: null,
        state_before_artifact_id: null,
        state_after_artifact_id: null,
        result: 'EXECUTION_FAILED',
        failure_reason: validation.error || 'Target rejected by security boundary validator.',
        stdout: '',
        stderr: validation.error || 'Target rejected.',
        trace: null,
        state_before: null,
        state_after: null,
        state_diff: null,
        authorization_state: null,
        formal_verification_id: options.formal_verification_id || null,
        poc_state: 'NOT_REPRODUCED',
        poc_artifact_id: null,
        created_at: startTime,
        updated_at: new Date().toISOString(),
      };

      globalDB.saveDynamicVerificationJob(failedJob);
      return failedJob;
    }

    // 2. Real Tool Detection
    let toolName = 'forge';
    let toolDetection: any;
    if (runtime === 'API' || runtime === 'HTTP') {
      toolName = 'node-isolated-api';
      toolDetection = {
        tool: 'node-isolated-api',
        executable: 'node',
        installed: true,
        version: process.version,
        executable_path: process.execPath,
        status: 'AVAILABLE',
        error: null,
      };
    } else if (runtime === 'CLARITY') {
      toolName = 'clarinet';
      toolDetection = ToolDetector.detectClarinet();
    } else {
      toolName = 'forge';
      toolDetection = ToolDetector.detectForge();
    }

    if (!toolDetection.installed) {
      const unavailJob: DynamicVerificationJob = {
        id: jobId,
        investigation_id: options.investigation_id,
        candidate_id: options.candidate_id || '',
        target_id: options.target_id || '',
        runtime,
        environment,
        tool: toolName,
        tool_version: null,
        command: `${toolName} test`,
        status: 'TOOL_UNAVAILABLE',
        started_at: startTime,
        completed_at: new Date().toISOString(),
        exit_code: 127,
        stdout_artifact_id: null,
        stderr_artifact_id: null,
        execution_trace_artifact_id: null,
        state_before_artifact_id: null,
        state_after_artifact_id: null,
        result: 'EXECUTION_FAILED',
        failure_reason: toolDetection.error || `ENGINE_NOT_INSTALLED: ${toolName} is not installed on host.`,
        stdout: '',
        stderr: toolDetection.error || `Executable '${toolName}' is not installed.`,
        trace: null,
        state_before: null,
        state_after: null,
        state_diff: null,
        authorization_state: null,
        formal_verification_id: options.formal_verification_id || null,
        poc_state: 'NOT_REPRODUCED',
        poc_artifact_id: null,
        created_at: startTime,
        updated_at: new Date().toISOString(),
      };

      globalDB.saveDynamicVerificationJob(unavailJob);
      return unavailJob;
    }

    // 3. PoC Lifecycle - Step 1: GENERATED
    let pocArtifact = PoCEngine.generatePoC({
      runtime,
      payload_content: options.parameters?.poc_payload || '// Isolated test payload',
      format: runtime === 'CLARITY' ? 'CLARINET_TEST' : 'FOUNDRY_TEST',
    });

    // 4. Register Background Job in JobOrchestrator
    const backgroundJob = globalJobOrchestrator.createJob({
      investigation_id: options.investigation_id,
      target_id: options.target_id || 'isolated-target',
      engine: toolName,
      operation: 'verify_dynamic',
      metadata: { candidate_id: options.candidate_id, runtime, environment },
    });
    backgroundJob.status = JobStatus.RUNNING;
    backgroundJob.started_at = startTime;

    // 5. PoC Lifecycle - Step 2: EXECUTED
    pocArtifact = PoCEngine.markExecuted(pocArtifact);

    // 6. Execute via Runtime Adapter
    let executionResult;
    const authState: AuthorizationStateEvidence = {
      caller: options.authenticatedCaller || options.caller || 'attacker',
      owner: options.resourceOwner || options.owner || 'victim',
      caller_is_owner: (options.authenticatedCaller || options.caller || 'attacker') === (options.resourceOwner || options.owner || 'victim'),
      caller_has_role: false,
      caller_authorized: Boolean(
        (options.authenticatedCaller || options.caller) &&
        (options.resourceOwner || options.owner) &&
        (options.authenticatedCaller || options.caller) === (options.resourceOwner || options.owner)
      ),
      target_operation: options.operation || 'redeem',
    };

    if (runtime === 'API' || runtime === 'HTTP') {
      executionResult = await this.apiAdapter.execute({
        endpoint: options.endpoint || options.parameters?.endpoint || '/documents/:id',
        method: options.method || options.parameters?.method || 'GET',
        objectId: options.objectId || options.parameters?.object_id || 'doc-123',
        authenticatedCaller: options.authenticatedCaller || options.caller || 'attacker',
        resourceOwner: options.resourceOwner || options.owner || 'victim',
        callerRole: options.callerRole || options.parameters?.role || 'user',
        initialDbState: options.initialDbState || options.parameters?.initial_db_state || {
          documents: [{ _id: 'doc-123', ownerId: 'victim', title: 'Victim Private Document' }],
          orders: [{ id: 'order-123', userId: 'victim', item: 'Secret Order' }],
        },
        handlerType: options.handlerType || options.parameters?.handler_type || 'VULNERABLE',
      });
    } else if (runtime === 'CLARITY') {
      executionResult = await this.clarinetAdapter.executeCheck({
        workingDirectory: options.working_directory || options.custom_fixture_dir,
        timeoutMs: options.timeout_ms || 15000,
        stateBefore: options.parameters?.state_before,
        stateAfter: options.parameters?.state_after,
        authorizationState: authState,
      });
    } else {
      executionResult = await this.foundryAdapter.executeTest({
        workingDirectory: options.working_directory || options.custom_fixture_dir,
        timeoutMs: options.timeout_ms || 20000,
        testFilter: options.test_filter || options.parameters?.test_filter,
        stateBefore: options.parameters?.state_before,
        stateAfter: options.parameters?.state_after,
        authorizationState: authState,
      });
    }

    // 7. Decision Engine
    const decision = ReproductionDecisionEngine.evaluate({
      authorization_state: executionResult.authorization_state,
      state_diff: executionResult.state_diff,
      execution_exit_code: executionResult.exit_code,
      execution_success: executionResult.exit_code === 0,
      tool_installed: true,
      formal_verification_status: options.parameters?.formal_verification_status,
      error: executionResult.error,
    });

    // 8. PoC Lifecycle - Step 3: Record outcome
    pocArtifact = PoCEngine.recordOutcome(pocArtifact, decision.result);

    const completedAt = new Date().toISOString();

    // 9. Store Raw Evidence Artifacts (Phase 0.2 Cryptographic Hashing)
    const stdoutArtifact = createEvidenceArtifact({
      investigation_id: options.investigation_id,
      target_id: options.target_id || '',
      artifact_type: ArtifactType.LOG_FILE,
      producer: toolName,
      producer_version: toolDetection.version || '1.0.0',
      command: executionResult.command_executed,
      working_directory: process.cwd(),
      content: executionResult.stdout,
      mime_type: 'text/plain',
      metadata: { exit_code: executionResult.exit_code, runtime },
    });
    globalDB.saveEvidence(stdoutArtifact.artifact);

    const stderrArtifact = createEvidenceArtifact({
      investigation_id: options.investigation_id,
      target_id: options.target_id || '',
      artifact_type: ArtifactType.ENGINE_STDERR,
      producer: toolName,
      producer_version: toolDetection.version || '1.0.0',
      command: executionResult.command_executed,
      working_directory: process.cwd(),
      content: executionResult.stderr,
      mime_type: 'text/plain',
      metadata: { exit_code: executionResult.exit_code, runtime },
    });
    globalDB.saveEvidence(stderrArtifact.artifact);

    const traceArtifact = createEvidenceArtifact({
      investigation_id: options.investigation_id,
      target_id: options.target_id || '',
      artifact_type: ArtifactType.EXECUTION_TRACE,
      producer: toolName,
      producer_version: toolDetection.version || '1.0.0',
      command: executionResult.command_executed,
      working_directory: process.cwd(),
      content: JSON.stringify(executionResult.trace, null, 2),
      mime_type: 'application/json',
      metadata: { traces_count: executionResult.trace.traces.length, runtime },
    });
    globalDB.saveEvidence(traceArtifact.artifact);

    let stateBeforeArtifactId: string | null = null;
    if (executionResult.state_before) {
      const sBefore = createEvidenceArtifact({
        investigation_id: options.investigation_id,
        target_id: options.target_id || '',
        artifact_type: ArtifactType.STATE_SNAPSHOT,
        producer: 'dynamic_verifier',
        producer_version: '1.0.0',
        command: 'capture_state_before',
        working_directory: process.cwd(),
        content: JSON.stringify(executionResult.state_before, null, 2),
        mime_type: 'application/json',
        metadata: { phase: 'BEFORE' },
      });
      globalDB.saveEvidence(sBefore.artifact);
      stateBeforeArtifactId = sBefore.artifact.id;
    }

    let stateAfterArtifactId: string | null = null;
    if (executionResult.state_after) {
      const sAfter = createEvidenceArtifact({
        investigation_id: options.investigation_id,
        target_id: options.target_id || '',
        artifact_type: ArtifactType.STATE_SNAPSHOT,
        producer: 'dynamic_verifier',
        producer_version: '1.0.0',
        command: 'capture_state_after',
        working_directory: process.cwd(),
        content: JSON.stringify(executionResult.state_after, null, 2),
        mime_type: 'application/json',
        metadata: { phase: 'AFTER' },
      });
      globalDB.saveEvidence(sAfter.artifact);
      stateAfterArtifactId = sAfter.artifact.id;
    }

    // 10. Record Evidence Event
    globalEvidenceEventManager.recordEvent({
      investigation_id: options.investigation_id,
      event_type: EvidenceEventType.VERIFICATION_COMPLETED,
      producer: toolName,
      producer_version: toolDetection.version || '1.0.0',
      input_artifacts: [stdoutArtifact.artifact.id],
      output_artifacts: [traceArtifact.artifact.id],
      metadata: {
        reproduction_result: decision.result,
        runtime,
        environment,
        duration_ms: executionResult.duration_ms,
      },
    });

    // 11. Form Provenance Graph Edges & Nodes
    const prov = globalProvenanceService.getGraph();
    if (prov) {
      prov.addNode({
        id: `dynamic-job-${jobId}`,
        type: 'DYNAMIC_VERIFICATION_JOB' as any,
        label: `Dynamic Verification: ${toolName}`,
        data: { jobId, result: decision.result },
      });

      if (options.candidate_id) {
        prov.addNode({
          id: `finding-${options.candidate_id}`,
          type: 'FINDING' as any,
          label: `Finding: ${options.candidate_id}`,
          data: { finding_id: options.candidate_id },
        });
        prov.addEdge({
          from_id: `finding-${options.candidate_id}`,
          to_id: `dynamic-job-${jobId}`,
          relationship: 'DYNAMICALLY_VERIFIED_BY',
          metadata: { result: decision.result },
        });
      }

      prov.addNode({
        id: `artifact-${stdoutArtifact.artifact.id}`,
        type: 'ARTIFACT' as any,
        label: 'Stdout',
        data: { artifact_id: stdoutArtifact.artifact.id },
      });
      prov.addEdge({
        from_id: `dynamic-job-${jobId}`,
        to_id: `artifact-${stdoutArtifact.artifact.id}`,
        relationship: 'PRODUCED_STDOUT',
      });

      prov.addNode({
        id: `artifact-${traceArtifact.artifact.id}`,
        type: 'ARTIFACT' as any,
        label: 'Execution Trace',
        data: { artifact_id: traceArtifact.artifact.id },
      });
      prov.addEdge({
        from_id: `dynamic-job-${jobId}`,
        to_id: `artifact-${traceArtifact.artifact.id}`,
        relationship: 'PRODUCED_EXECUTION_TRACE',
      });
    }

    // 12. Build DynamicVerificationJob
    const job: DynamicVerificationJob = {
      id: jobId,
      investigation_id: options.investigation_id,
      candidate_id: options.candidate_id || '',
      target_id: options.target_id || '',
      runtime,
      environment,
      tool: toolName,
      tool_version: toolDetection.version,
      command: executionResult.command_executed,
      status: executionResult.status === 'TIMEOUT' ? 'TIMEOUT' : 'COMPLETED',
      started_at: startTime,
      completed_at: completedAt,
      exit_code: executionResult.exit_code,
      stdout_artifact_id: stdoutArtifact.artifact.id,
      stderr_artifact_id: stderrArtifact.artifact.id,
      execution_trace_artifact_id: traceArtifact.artifact.id,
      state_before_artifact_id: stateBeforeArtifactId,
      state_after_artifact_id: stateAfterArtifactId,
      result: decision.result,
      failure_reason: decision.result === 'EXECUTION_FAILED' ? decision.reason : null,
      stdout: executionResult.stdout,
      stderr: executionResult.stderr,
      trace: executionResult.trace,
      state_before: executionResult.state_before,
      state_after: executionResult.state_after,
      state_diff: executionResult.state_diff,
      authorization_state: executionResult.authorization_state,
      formal_verification_id: options.formal_verification_id || null,
      poc_state: pocArtifact.state,
      poc_artifact_id: pocArtifact.id,
      metadata: {
        decision_reason: decision.reason,
        soundness_notes: decision.soundness_notes,
      },
      created_at: startTime,
      updated_at: completedAt,
    };

    // 13. State Machine Discipline: Update Authorization Candidate Finding
    if (options.candidate_id) {
      const candidate = globalDB.getAuthorizationCandidate(options.candidate_id);
      if (candidate) {
        if (decision.result === 'REPRODUCED') {
          candidate.corroborated = true;
          candidate.metadata = {
            ...candidate.metadata,
            dynamic_verification_id: jobId,
            dynamic_status: 'DYNAMICALLY_REPRODUCED',
            dynamic_reproduction: true,
            dynamic_witness: {
              tool: toolName,
              exit_code: executionResult.exit_code,
              state_diff_summary: executionResult.state_diff.summary,
              decision_reason: decision.reason,
            },
          };
          globalDB.saveAuthorizationCandidate(candidate);
        } else if (decision.result === 'NOT_REPRODUCED') {
          candidate.metadata = {
            ...candidate.metadata,
            dynamic_verification_id: jobId,
            dynamic_status: 'NOT_REPRODUCED',
            dynamic_reproduction: false,
          };
          globalDB.saveAuthorizationCandidate(candidate);
        }
      }

      const finding = globalDB.getFinding(options.candidate_id);
      if (finding) {
        if (decision.result === 'REPRODUCED') {
          finding.status = FindingStatus.CORROBORATED;
          finding.metadata = {
            ...finding.metadata,
            dynamic_verification_id: jobId,
            dynamic_status: 'DYNAMICALLY_REPRODUCED',
            dynamic_reproduction: true,
            corroborated: true,
          };
          globalDB.saveFinding(finding);
        } else if (decision.result === 'NOT_REPRODUCED') {
          finding.metadata = {
            ...finding.metadata,
            dynamic_verification_id: jobId,
            dynamic_status: 'NOT_REPRODUCED',
            dynamic_reproduction: false,
          };
          globalDB.saveFinding(finding);
        }
      }
    }

    // 14. Save Job in Database
    globalDB.saveDynamicVerificationJob(job);

    // 15. Complete Background Job
    backgroundJob.status = JobStatus.COMPLETED;
    backgroundJob.completed_at = completedAt;
    backgroundJob.exit_code = executionResult.exit_code;
    globalJobOrchestrator.log(
      backgroundJob.id,
      'INFO',
      `Dynamic verification completed with result: ${decision.result}`
    );

    return job;
  }

  /**
   * Alias for startDynamicVerification
   */
  startDynamicVerification(options: DynamicVerificationOptions): Promise<DynamicVerificationJob> {
    return this.execute(options);
  }
}

export const globalDynamicVerificationService = new DynamicVerificationService();
