/**
 * Formal Verification Service & Orchestrator Pipeline
 * Intent Security Workbench - Phase 4
 *
 * Coordinates:
 * 1. Model construction from AST, Semgrep, and API contract evidence
 * 2. Model soundness verification (detecting under-constrained & assumption-dependent models)
 * 3. Deterministic SMT-LIB2 generation & cryptographic hashing
 * 4. Genuine host Z3 execution with strict resource limits
 * 5. Full Phase 0.2 evidence artifact storage & provenance tracking
 * 6. Finding status governance (strictly forbids premature CONFIRMED transitions)
 */

import {
  FormalModelDefinition,
  VerificationResult,
  VerificationStatus,
  ModelSoundnessResult,
  SecurityProperty,
} from './types.js';
import { ModelSoundnessChecker } from './model_soundness.js';
import { FormalDSLCompiler } from './dsl.js';
import { Z3Executor } from './z3_executor.js';
import { Z3Detector } from './z3_detector.js';
import { STANDARD_PROPERTIES } from './properties.js';
import { globalDB } from '../../../apps/api/db_store.js';
import {
  createEvidenceArtifact,
  globalArtifactStorage,
  globalEvidenceEventManager,
} from '../../evidence/src/index.js';
import {
  ArtifactType,
  EvidenceEventType,
  FindingStatus,
  JobStatus,
  EngineExecutionStatus,
} from '../../core/src/index.js';
import { globalJobOrchestrator } from '../../orchestrator/src/index.js';

export interface VerifyFormalOptions {
  investigationId: string;
  targetId: string;
  sourceSnapshotId?: string | null;
  candidateId?: string | null;
  model: FormalModelDefinition;
  timeoutMs?: number;
  runInBackground?: boolean;
}

export class FormalVerificationService {
  /**
   * Executes formal verification on a formalized security model.
   */
  async verifyModel(options: VerifyFormalOptions): Promise<VerificationResult> {
    const { investigationId, targetId, model, candidateId } = options;
    const now = new Date().toISOString();
    const resultId = `fvr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    const queryProperty = model.query_property || model.property || STANDARD_PROPERTIES.UNAUTHORIZED_OBJECT_ACCESS;
    model.query_property = queryProperty;
    model.query_mode = model.query_mode || 'UNAUTHORIZED_ACCESS_REACHABLE';
    model.assumptions = model.assumptions || [];
    model.sourceFacts = model.sourceFacts || model.source_facts || [];
    for (const v of model.variables || []) {
      if (!v.origin) {
        v.origin = {
          origin_type: 'SOURCE_OBSERVATION',
          reason: v.description || 'Modeled variable',
        };
      }
    }
    for (const c of model.constraints || []) {
      if (!c.origin) {
        c.origin = {
          origin_type: c.is_assumption ? 'MODEL_ASSUMPTION' : 'SOURCE_FACT',
          reason: c.rationale || c.name,
        };
      }
    }

    // Create JobOrchestrator analysis job for transparency & WS broadcasts
    const job = globalJobOrchestrator.createJob({
      investigation_id: investigationId,
      target_id: targetId,
      engine: 'z3',
      operation: 'formal_verification',
      metadata: {
        property: queryProperty.name,
        candidate_id: candidateId,
        model_name: model.name,
      },
    });

    job.status = JobStatus.RUNNING;
    job.started_at = now;
    globalJobOrchestrator.log(job.id, 'INFO', `Formal verification started for model ${model.name}`);

    // 1. Validate Model Soundness
    const soundness: ModelSoundnessResult = ModelSoundnessChecker.validate(model);

    if (!soundness.valid) {
      const failedResult: VerificationResult = {
        id: resultId,
        property_id: queryProperty.id,
        property: queryProperty,
        investigation_id: investigationId,
        source_snapshot_id: options.sourceSnapshotId || null,
        candidate_id: candidateId || null,
        model_hash: '',
        solver: 'Z3',
        solver_version: 'unknown',
        executable_path: 'z3',
        command_executed: 'z3 [pre-validation-failed]',
        execution_time_ms: 0,
        exit_code: 1,
        status: VerificationStatus.MODEL_INVALID,
        solver_result_raw: 'error',
        assumptions: model.assumptions,
        constraints: model.constraints,
        source_facts: model.sourceFacts || model.source_facts || [],
        variables: model.variables,
        counterexample: null,
        smt_lib_input: '',
        smt_lib_sha256: '',
        stdout: '',
        stderr: soundness.errors.join('\n'),
        model_scope: 'Model failed soundness validation',
        boundary_clarification: 'Proof aborted: Model is invalid.',
        soundness_issues: soundness.errors,
        created_at: now,
      };

      globalDB.saveVerificationResult(failedResult);
      job.status = JobStatus.FAILED;
      job.completed_at = new Date().toISOString();
      globalJobOrchestrator.log(job.id, 'ERROR', `Model validation failed: ${soundness.errors.join(', ')}`);
      return failedResult;
    }

    // 2. Compile to SMT-LIB2
    const { smtCode, sha256 } = FormalDSLCompiler.compileToSMTLIB2(model);

    // 3. Store SMT-LIB2 input as machine-verifiable evidence artifact
    const smtArtifactResult = createEvidenceArtifact({
      investigation_id: investigationId,
      target_id: targetId,
      artifact_type: ArtifactType.SMT_INPUT,
      producer: 'formal_dsl_compiler',
      producer_version: '1.0.0',
      command: 'compileToSMTLIB2',
      working_directory: process.cwd(),
      content: smtCode,
      mime_type: 'text/plain',
      metadata: {
        model_name: model.name,
        property_id: queryProperty.id,
        property_name: queryProperty.name,
        sha256,
      },
    });
    const smtArtifact = smtArtifactResult.artifact;
    globalDB.saveEvidence(smtArtifact);

    globalEvidenceEventManager.recordEvent({
      investigation_id: investigationId,
      event_type: EvidenceEventType.VERIFICATION_STARTED,
      producer: 'formal_verification_service',
      producer_version: '1.0.0',
      input_artifacts: [smtArtifact.id],
      output_artifacts: [],
      metadata: { model_name: model.name, property: model.query_property.name },
    });

    // 4. Check Z3 host availability
    const hostInfo = Z3Detector.detect();
    if (!hostInfo.installed || !hostInfo.executable_path) {
      const unavailResult: VerificationResult = {
        id: resultId,
        property_id: model.query_property.id,
        property: model.query_property,
        investigation_id: investigationId,
        source_snapshot_id: options.sourceSnapshotId || null,
        candidate_id: candidateId || null,
        model_hash: sha256,
        solver: 'Z3',
        solver_version: 'unavailable',
        executable_path: 'z3',
        command_executed: 'z3 --version',
        execution_time_ms: 0,
        exit_code: 127,
        status: VerificationStatus.SOLVER_UNAVAILABLE,
        solver_result_raw: 'error',
        assumptions: model.assumptions,
        constraints: model.constraints,
        source_facts: model.sourceFacts,
        variables: model.variables,
        counterexample: null,
        smt_lib_input: smtCode,
        smt_lib_sha256: sha256,
        smt_artifact_id: smtArtifact.id,
        stdout: '',
        stderr: hostInfo.error || 'Z3 SMT solver is not installed on host.',
        model_scope: 'Host environment lacks Z3 binary',
        boundary_clarification: 'Verification cannot proceed without Z3 executable.',
        created_at: now,
      };

      globalDB.saveVerificationResult(unavailResult);
      job.status = JobStatus.FAILED;
      job.error = 'ENGINE_NOT_INSTALLED: Z3 SMT solver is not installed on host.';
      job.completed_at = now;
      job.updated_at = now;
      globalJobOrchestrator.log(job.id, 'ERROR', 'Z3 SMT solver is not installed on host.');
      return unavailResult;
    }

    // 5. Execute genuine Z3 solver
    const modeledVarNames = model.variables.map((v) => v.name);
    const z3Output = await Z3Executor.executeSMT2(smtCode, {
      timeoutMs: options.timeoutMs || 8000,
      solverTimeoutMs: 5000,
      queryMode: model.query_mode,
      modeledVariables: modeledVarNames,
    });

    // 6. Store solver output as SMT_RESULT evidence artifact
    const resultArtifactResult = createEvidenceArtifact({
      investigation_id: investigationId,
      target_id: targetId,
      artifact_type: ArtifactType.SMT_RESULT,
      producer: 'z3',
      producer_version: hostInfo.version || '4.8.12',
      command: z3Output.command_executed,
      working_directory: process.cwd(),
      content: `STATUS: ${z3Output.status}\nSTDOUT:\n${z3Output.stdout}\nSTDERR:\n${z3Output.stderr}`,
      mime_type: 'text/plain',
      metadata: {
        exit_code: z3Output.exit_code,
        duration_ms: z3Output.execution_time_ms,
        status: z3Output.status,
        raw_result: z3Output.solver_result_raw,
      },
    });
    const resultArtifact = resultArtifactResult.artifact;
    globalDB.saveEvidence(resultArtifact);

    globalEvidenceEventManager.recordEvent({
      investigation_id: investigationId,
      event_type: EvidenceEventType.VERIFICATION_COMPLETED,
      producer: 'z3',
      producer_version: hostInfo.version || '4.8.12',
      input_artifacts: [smtArtifact.id],
      output_artifacts: [resultArtifact.id],
      metadata: {
        verification_status: z3Output.status,
        solver_result_raw: z3Output.solver_result_raw,
        duration_ms: z3Output.execution_time_ms,
      },
    });

    // 7. Adjust status for under-constrained / assumption-dependent models
    let finalStatus = z3Output.status;
    const soundnessIssues: string[] = [];

    if (soundness.underconstrained) {
      soundnessIssues.push(...soundness.warnings.filter((w) => w.includes('MODEL_UNDERCONSTRAINED')));
      if (finalStatus === VerificationStatus.PROPERTY_HOLDS_FOR_MODEL || finalStatus === VerificationStatus.PROVEN) {
        finalStatus = VerificationStatus.MODEL_UNDERCONSTRAINED;
      }
    }

    if (soundness.assumption_dependent) {
      soundnessIssues.push(...soundness.warnings.filter((w) => w.includes('ASSUMPTION_DEPENDENT')));
      if (finalStatus === VerificationStatus.COUNTEREXAMPLE_FOUND || finalStatus === VerificationStatus.REFUTED) {
        // Tag as assumption dependent rather than definite refuted
        // Keep status but record warning
      }
    }

    const verificationResult: VerificationResult = {
      id: resultId,
      property_id: model.query_property.id,
      property: model.query_property,
      investigation_id: investigationId,
      source_snapshot_id: options.sourceSnapshotId || null,
      candidate_id: candidateId || null,
      model_hash: sha256,
      solver: 'Z3',
      solver_version: hostInfo.version || '4.8.12',
      executable_path: hostInfo.executable_path,
      command_executed: z3Output.command_executed,
      execution_time_ms: z3Output.execution_time_ms,
      exit_code: z3Output.exit_code,
      status: finalStatus,
      solver_result_raw: z3Output.solver_result_raw,
      assumptions: model.assumptions,
      constraints: model.constraints,
      source_facts: model.sourceFacts,
      variables: model.variables,
      counterexample: z3Output.counterexample || null,
      smt_lib_input: smtCode,
      smt_lib_sha256: sha256,
      smt_artifact_id: smtArtifact.id,
      result_artifact_id: resultArtifact.id,
      stdout: z3Output.stdout,
      stderr: z3Output.stderr,
      model_scope: `Abstract formal authorization model for ${model.name}`,
      boundary_clarification:
        'Formal Model Result: Property refuted in formal model is a FORMAL COUNTEREXAMPLE to the model, NOT automatically an exploit confirmed in production.',
      soundness_issues: soundnessIssues.length > 0 ? soundnessIssues : undefined,
      created_at: now,
    };

    // Save to database
    globalDB.saveVerificationResult(verificationResult);

    // 8. Update Candidate finding if linked (Strict State Machine Discipline)
    if (candidateId) {
      const candidate = globalDB.getAuthorizationCandidate(candidateId);
      if (candidate) {
        if (finalStatus === VerificationStatus.COUNTEREXAMPLE_FOUND) {
          candidate.corroborated = true;
          // IMPORTANT: Do NOT set CONFIRMED! Keep status as CANDIDATE.
          // Store formal verification corroboration in metadata:
          candidate.metadata = {
            ...candidate.metadata,
            formal_verification_id: resultId,
            formal_status: 'FORMALLY_SUPPORTED',
            formal_counterexample: z3Output.counterexample,
          };
          globalDB.saveAuthorizationCandidate(candidate);
        } else if (finalStatus === VerificationStatus.PROPERTY_HOLDS_FOR_MODEL) {
          candidate.metadata = {
            ...candidate.metadata,
            formal_verification_id: resultId,
            formal_status: 'FORMALLY_REFUTED',
          };
          globalDB.saveAuthorizationCandidate(candidate);
        }
      }
    }

    // Complete background job
    job.status = JobStatus.COMPLETED;
    job.completed_at = new Date().toISOString();
    job.exit_code = z3Output.exit_code;
    globalJobOrchestrator.log(
      job.id,
      'INFO',
      `Formal verification finished with solver result: ${z3Output.solver_result_raw}`
    );

    return verificationResult;
  }
}

export const globalFormalVerificationService = new FormalVerificationService();
