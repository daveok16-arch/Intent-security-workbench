/**
 * Static Analysis Pipeline Coordinator
 * Intent Security Workbench - Phase 2
 *
 * Coordinates Tree-sitter structural analysis, Semgrep taint/pattern scan,
 * multi-engine correlation, and candidate finding generation.
 */

import {
  globalTreeSitterService,
} from './treesitter_service.js';
import {
  globalSemgrepService,
} from './semgrep_service.js';
import {
  globalStaticCorrelationService,
} from './correlation_service.js';
import {
  globalCandidateStore,
} from './candidate_store.js';
import {
  globalEvidenceEventManager,
} from '../../evidence/src/index.js';
import {
  StaticAnalysisExecutionResult,
} from './types.js';

export async function executeStaticAnalysisPipeline(
  investigationId: string,
  targetId: string,
  sourceSnapshotId: string,
  sourceDir: string
): Promise<StaticAnalysisExecutionResult> {
  const startTime = Date.now();

  // 1. Record evidence event: STATIC_ANALYSIS_STARTED
  try {
    globalEvidenceEventManager.recordEvent({
      investigation_id: investigationId,
      event_type: 'STATIC_ANALYSIS_STARTED',
      actor: 'system:orchestrator',
      producer: 'static_analysis_pipeline',
      producer_version: '2.0.0',
      input_artifacts: [],
      output_artifacts: [],
      metadata: {
        target_id: targetId,
        source_snapshot_id: sourceSnapshotId,
        source_directory: sourceDir,
      },
    });
  } catch {
    // optional in test contexts
  }

  // 2. Tree-sitter Structural Analysis
  const tsStartTime = Date.now();
  let tsStatus: 'COMPLETED' | 'FAILED' = 'COMPLETED';
  let tsResults: any[] = [];
  let tsCandidates: any[] = [];
  let tsArtifactIds: string[] = [];

  try {
    const tsScan = await globalTreeSitterService.scanDirectory(
      sourceDir,
      sourceSnapshotId,
      investigationId,
      targetId
    );
    tsResults = tsScan.results;
    tsCandidates = tsScan.candidates;
    tsArtifactIds = tsScan.artifactIds;
    if (tsScan.directory_exists === false) {
      tsStatus = 'FAILED';
    }
  } catch (err: any) {
    console.error('Tree-sitter analysis failed:', err);
    tsStatus = 'FAILED';
  }
  const tsDuration = Date.now() - tsStartTime;

  // 3. Semgrep Analysis
  const sgScan = await globalSemgrepService.executeScan(
    sourceDir,
    sourceSnapshotId,
    investigationId,
    targetId
  );
  const sgCandidates = sgScan.candidates;
  const sgArtifactIds = sgScan.artifactIds;

  // 4. Cross-Engine Correlation
  const corrStartTime = Date.now();
  const correlationResult = globalStaticCorrelationService.correlateFindings(
    tsCandidates,
    sgCandidates,
    investigationId,
    targetId,
    sourceSnapshotId
  );
  const corrDuration = Date.now() - corrStartTime;

  // 5. Register all candidates into store
  for (const candidate of correlationResult.allCandidates) {
    globalCandidateStore.addCandidate(candidate);
  }

  // Aggregate all output artifacts
  const allOutputArtifactIds = [
    ...tsArtifactIds,
    ...sgArtifactIds,
  ];
  if (correlationResult.correlationArtifactId) {
    allOutputArtifactIds.push(correlationResult.correlationArtifactId);
  }

  // 6. Record evidence event: STATIC_ANALYSIS_COMPLETED
  try {
    globalEvidenceEventManager.recordEvent({
      investigation_id: investigationId,
      event_type: 'STATIC_ANALYSIS_COMPLETED',
      actor: 'system:orchestrator',
      producer: 'static_analysis_pipeline',
      producer_version: '2.0.0',
      input_artifacts: [],
      output_artifacts: allOutputArtifactIds,
      metadata: {
        treesitter_candidates: tsCandidates.length,
        semgrep_candidates: sgCandidates.length,
        total_unique_candidates: correlationResult.allCandidates.length,
        corroborated_candidates: correlationResult.corroboratedCount,
        duration_ms: Date.now() - startTime,
      },
    });
  } catch {
    // optional in test contexts
  }

  return {
    investigation_id: investigationId,
    target_id: targetId,
    source_snapshot_id: sourceSnapshotId,
    treesitter: {
      status: tsStatus,
      parser_version: '0.20.8',
      files_scanned: tsResults.length,
      parse_errors: tsResults.reduce((acc, r) => acc + r.error_count, 0),
      artifacts_created: tsArtifactIds,
      duration_ms: tsDuration,
    },
    semgrep: {
      status: sgScan.execution.status,
      binary_path: sgScan.execution.executable_path,
      version: sgScan.execution.version,
      command: sgScan.execution.command,
      exit_code: sgScan.execution.exit_code,
      stdout_artifact_id: sgScan.execution.stdout_artifact_id,
      stderr_artifact_id: sgScan.execution.stderr_artifact_id,
      duration_ms: sgScan.execution.duration_ms,
      raw_findings_count: sgScan.execution.raw_findings_count,
    },
    correlation: {
      candidates_created: correlationResult.allCandidates.length,
      corroborated_candidates: correlationResult.corroboratedCount,
      duration_ms: corrDuration,
    },
    candidates: correlationResult.allCandidates,
    executed_at: new Date().toISOString(),
    total_duration_ms: Date.now() - startTime,
  };
}
