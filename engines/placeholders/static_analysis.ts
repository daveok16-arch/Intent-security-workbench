/**
 * Static & Structural Analysis Pipeline Engine
 * Intent Security Workbench - Phase 2
 *
 * Unified multi-engine orchestrator executing Tree-sitter and Semgrep
 * with cross-engine candidate correlation.
 */

import { BaseEngine } from '../base_engine.js';
import {
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineAvailabilityStatus,
  EngineAvailability,
  EngineArtifact,
} from '../types.js';
import { executeStaticAnalysisPipeline } from '../../packages/static-analysis/src/orchestration.js';
import { globalTreeSitterService } from '../../packages/static-analysis/src/treesitter_service.js';
import { globalSemgrepService } from '../../packages/static-analysis/src/semgrep_service.js';

export class StaticAnalysisEngine extends BaseEngine {
  readonly engine_id = 'static-analysis';
  readonly name = 'Static Analysis Pipeline';
  readonly version = '2.0.0';
  readonly description = 'Unified static & structural security analysis pipeline combining Tree-sitter CST queries and Semgrep taint matching.';
  readonly executable = 'semgrep';
  readonly capabilities = ['treesitter', 'semgrep', 'structural_analysis', 'taint_analysis', 'correlation'];
  readonly supported_target_types = ['SMART_CONTRACT', 'WEB_APPLICATION', 'REST_API', 'LIBRARY', 'REPOSITORY'];
  readonly supported_languages = ['javascript', 'typescript', 'solidity', 'python', 'go', 'rust', 'c', 'cpp', 'java'];

  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();
    const tsOk = await globalTreeSitterService.init();
    const sgAvail = await globalSemgrepService.checkAvailability();

    if (tsOk || sgAvail.available) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.AVAILABLE,
        executable: this.executable,
        detected_path: sgAvail.path || globalTreeSitterService.wasmsDirectory,
        version: this.version,
        checked_at,
        error: null,
        capabilities: this.capabilities,
      };
    }

    return {
      engine_id: this.engine_id,
      name: this.name,
      status: EngineAvailabilityStatus.NOT_INSTALLED,
      executable: this.executable,
      detected_path: null,
      version: null,
      checked_at,
      error: 'Neither Tree-sitter nor Semgrep is available.',
      capabilities: this.capabilities,
    };
  }

  async prepare(targetId: string, context: Record<string, any>): Promise<boolean> {
    const avail = await this.check_availability();
    return avail.status === EngineAvailabilityStatus.AVAILABLE;
  }

  async execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult> {
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    const investigationId = context.investigation_id || 'inv-unknown';
    const sourceSnapshotId = context.source_snapshot_id || 'snap-unknown';
    const sourceDir = context.source_directory || context.working_directory || process.cwd();

    try {
      const pipelineResult = await executeStaticAnalysisPipeline(
        investigationId,
        targetId,
        sourceSnapshotId,
        sourceDir
      );

      const findings: EngineFinding[] = pipelineResult.candidates.map(c => ({
        id: c.id,
        title: c.title,
        description: c.confidence_basis,
        severity: c.severity,
        category: c.category,
        cwe: c.cwe_ids,
        owasp: c.owasp_categories,
        confidence: c.confidence,
        file: c.file_path,
        line_start: c.line_start,
        line_end: c.line_end,
        evidence: c.matched_code,
        metadata: {
          corroborated: c.corroborated,
          engine: c.engine,
          data_flow: c.data_flow,
          structural_evidence: c.structural_evidence,
        },
      }));

      const artifacts: EngineArtifact[] = [
        ...pipelineResult.treesitter.artifacts_created.map(id =>
          this.describeArtifact(id, 'AST', `ast/${id}`)
        ),
        ...(pipelineResult.semgrep.stdout_artifact_id
          ? [
              this.describeArtifact(
                pipelineResult.semgrep.stdout_artifact_id,
                'ENGINE_STDOUT',
                `stdout/${pipelineResult.semgrep.stdout_artifact_id}`
              ),
            ]
          : []),
      ];

      const stdout = JSON.stringify({
        pipeline: 'static_and_structural_analysis',
        treesitter: pipelineResult.treesitter,
        semgrep: pipelineResult.semgrep,
        correlation: pipelineResult.correlation,
        total_candidates: pipelineResult.candidates.length,
      }, null, 2);

      // The pipeline only reports SUCCESS when it actually analysed a source
      // tree. A missing directory, or a failed Semgrep run, is a real failure.
      const tsOk = pipelineResult.treesitter.status === 'COMPLETED';
      const sgStatus = pipelineResult.semgrep.status;
      const sgOk = sgStatus === 'COMPLETED';
      const succeeded = tsOk || sgOk;

      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: succeeded ? EngineResultStatus.SUCCESS : EngineResultStatus.FAILED,
        target_id: targetId,
        investigation_id: investigationId,
        command: `static-analysis pipeline [treesitter+semgrep] on ${sourceDir}`,
        working_directory: sourceDir,
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: pipelineResult.total_duration_ms,
        exit_code: succeeded ? 0 : 1,
        stdout,
        stderr: succeeded
          ? ''
          : `treesitter=${pipelineResult.treesitter.status}, semgrep=${sgStatus}`,
        findings,
        artifacts,
        environment: this.getEnvironmentInfo(),
        error: succeeded
          ? null
          : `ENGINE_FAILED: no analysis engine completed successfully (treesitter=${pipelineResult.treesitter.status}, semgrep=${sgStatus}).`,
      };
    } catch (err: any) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.FAILED,
        target_id: targetId,
        investigation_id: investigationId,
        command: `static-analysis pipeline on ${sourceDir}`,
        working_directory: sourceDir,
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - startMs,
        exit_code: 1,
        stdout: '',
        stderr: err.message,
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(),
        error: `STATIC_ANALYSIS_FAILED: ${err.message}`,
      };
    }
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    return [];
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}
