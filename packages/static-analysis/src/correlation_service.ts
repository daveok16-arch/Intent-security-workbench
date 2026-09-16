/**
 * Cross-Engine Static Analysis Correlation Service
 * Intent Security Workbench - Phase 2
 *
 * Correlates structural findings from Tree-sitter with pattern/taint findings from Semgrep.
 * Corroborated candidates receive elevated confidence and multi-engine provenance,
 * while strictly adhering to the Finding state machine (remaining CANDIDATE).
 */

import crypto from 'crypto';
import {
  ArtifactType,
  Confidence,
  FindingStatus,
  Severity,
} from '../../core/src/index.js';
import {
  createEvidenceArtifact,
} from '../../evidence/src/index.js';
import {
  CandidateFinding,
  StaticEngineType,
} from './types.js';

export class StaticAnalysisCorrelationService {
  /**
   * Correlate findings between Tree-sitter and Semgrep.
   */
  correlateFindings(
    treesitterCandidates: CandidateFinding[],
    semgrepCandidates: CandidateFinding[],
    investigationId: string,
    targetId: string,
    sourceSnapshotId: string
  ): {
    allCandidates: CandidateFinding[];
    corroboratedCount: number;
    correlationArtifactId?: string;
  } {
    const combined: CandidateFinding[] = [];
    let corroboratedCount = 0;

    // Track matched pairs
    const matchedTsIds = new Set<string>();
    const matchedSgIds = new Set<string>();
    // Semgrep ids that already produced a correlated finding (see below).
    const correlatedSgIds = new Set<string>();

    for (const tsCand of treesitterCandidates) {
      let isCorroborated = false;
      let matchingSg: CandidateFinding | null = null;

      for (const sgCand of semgrepCandidates) {
        // Correlate if same file and overlapping line boundaries (within +/- 15 lines)
        const fileMatches = tsCand.file_path === sgCand.file_path ||
          tsCand.file_path.endsWith(sgCand.file_path) ||
          sgCand.file_path.endsWith(tsCand.file_path) ||
          (tsCand.file_path.split(/[/\\]/).pop() === sgCand.file_path.split(/[/\\]/).pop());

        if (fileMatches) {
          const lineOverlap = 
            (tsCand.line_start <= sgCand.line_end + 15) &&
            (tsCand.line_end >= sgCand.line_start - 15);

          if (lineOverlap) {
            isCorroborated = true;
            matchingSg = sgCand;
            matchedTsIds.add(tsCand.id);
            matchedSgIds.add(sgCand.id);
            break;
          }
        }
      }

      if (isCorroborated && matchingSg) {
        // One Semgrep match may overlap several Tree-sitter candidates (e.g. a
        // route handler and its inner query). Emitting a correlated finding per
        // pairing produced duplicate findings for the same defect, so each
        // Semgrep match yields at most one correlated finding.
        if (correlatedSgIds.has(matchingSg.id)) {
          combined.push(tsCand);
          continue;
        }
        correlatedSgIds.add(matchingSg.id);
        corroboratedCount++;
        // Create unified Correlated Candidate
        const correlatedId = `cand-corr-${crypto.randomBytes(6).toString('hex')}`;
        const unifiedArtifactIds = Array.from(new Set([
          ...tsCand.evidence_artifact_ids,
          ...matchingSg.evidence_artifact_ids,
        ]));

        const correlatedCandidate: CandidateFinding = {
          id: correlatedId,
          investigation_id: investigationId,
          target_id: targetId,
          title: `[Correlated] ${tsCand.category}: ${matchingSg.title.replace(/^\[Semgrep\]\s*/, '')}`,
          category: tsCand.category,
          severity: Severity.HIGH,
          status: FindingStatus.CANDIDATE, // Invariant: Remains CANDIDATE
          confidence: Confidence.HIGH,
          confidence_basis: `Multi-engine corroboration: Tree-sitter AST structural analysis confirmed absence of authorization boundary before state mutation, matching Semgrep pattern detection (${matchingSg.rule_id}).`,
          engine: 'correlated[treesitter+semgrep]',
          engine_version: '1.0.0',
          rule_id: `${tsCand.rule_id}+${matchingSg.rule_id}`,
          rule_version: '1.0.0',
          source_snapshot_id: sourceSnapshotId,
          file_path: tsCand.file_path,
          line_start: Math.min(tsCand.line_start, matchingSg.line_start),
          line_end: Math.max(tsCand.line_end, matchingSg.line_end),
          column_start: tsCand.column_start,
          column_end: tsCand.column_end,
          matched_code: tsCand.matched_code || matchingSg.matched_code,
          data_flow: tsCand.data_flow || matchingSg.data_flow,
          structural_evidence: tsCand.structural_evidence,
          evidence_artifact_ids: unifiedArtifactIds,
          cwe_ids: Array.from(new Set([...tsCand.cwe_ids, ...matchingSg.cwe_ids])),
          owasp_categories: Array.from(new Set([...tsCand.owasp_categories, ...matchingSg.owasp_categories])),
          remediation: matchingSg.remediation || tsCand.remediation,
          corroborated: true,
          status_history: [
            {
              from_status: null,
              to_status: FindingStatus.CANDIDATE,
              timestamp: new Date().toISOString(),
              actor: 'engine:correlation',
              reason: 'Initial candidate creation via multi-engine corroboration',
            },
          ],
          provenance: {
            source_snapshot_id: sourceSnapshotId,
            engine: 'correlation(treesitter+semgrep)',
            engine_version: '1.0.0',
            rule_id: `${tsCand.rule_id}+${matchingSg.rule_id}`,
            rule_version: '1.0.0',
            matched_at: new Date().toISOString(),
            source_file: tsCand.file_path,
            line: tsCand.line_start,
          },
          metadata: {
            treesitter_candidate_id: tsCand.id,
            semgrep_candidate_id: matchingSg.id,
            treesitter_evidence: tsCand.structural_evidence,
          },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        combined.push(correlatedCandidate);
      } else {
        combined.push(tsCand);
      }
    }

    // Add remaining unmatched Semgrep candidates
    for (const sgCand of semgrepCandidates) {
      if (!matchedSgIds.has(sgCand.id)) {
        combined.push(sgCand);
      }
    }

    // Register correlation artifact
    let correlationArtifactId: string | undefined;
    try {
      const summaryContent = JSON.stringify({
        investigation_id: investigationId,
        source_snapshot_id: sourceSnapshotId,
        treesitter_candidates_count: treesitterCandidates.length,
        semgrep_candidates_count: semgrepCandidates.length,
        corroborated_count: corroboratedCount,
        total_unique_candidates: combined.length,
        correlated_candidates: combined.map(c => ({
          id: c.id,
          title: c.title,
          engine: c.engine,
          corroborated: c.corroborated,
          confidence: c.confidence,
          file: c.file_path,
          line: c.line_start,
        })),
      }, null, 2);

      const artifact = createEvidenceArtifact({
        investigation_id: investigationId,
        target_id: targetId,
        artifact_type: ArtifactType.ENGINE_RESULT,
        producer: 'correlation_engine',
        producer_version: '1.0.0',
        source_snapshot_id: sourceSnapshotId,
        content: summaryContent,
        filename: `static_analysis_correlation_${Date.now()}.json`,
        mime_type: 'application/json',
        metadata: {
          corroborated_count: corroboratedCount,
          total_candidates: combined.length,
        },
      });
      correlationArtifactId = artifact.id;
    } catch (err) {
      console.error('Failed to create correlation artifact:', err);
    }

    return {
      allCandidates: combined,
      corroboratedCount,
      correlationArtifactId,
    };
  }
}

export const globalStaticCorrelationService = new StaticAnalysisCorrelationService();
