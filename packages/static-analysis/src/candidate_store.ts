/**
 * Candidate Findings Store & State Transition Controller
 * Intent Security Workbench - Phase 2
 *
 * Enforces strict Finding state machine transitions, provenance linking,
 * and ground-truth evidence artifact associations.
 */

import {
  FindingStatus,
  validateFindingTransition,
} from '../../core/src/index.js';
import {
  globalEvidenceEventManager,
  globalArtifactStorage,
  registeredEvidenceArtifacts,
} from '../../evidence/src/index.js';
import { CandidateFinding } from './types.js';

export class CandidateStore {
  private candidates: Map<string, CandidateFinding> = new Map();

  createCandidate(params: {
    investigation_id: string;
    target_id: string;
    source_snapshot_id: string;
    rule_id: string;
    title: string;
    category: string;
    severity: any;
    confidence: any;
    confidence_basis: string;
    file_path: string;
    line_start: number;
    line_end: number;
    matched_code: string;
    engine: string;
    evidence_artifact_ids?: string[];
    [key: string]: any;
  }): CandidateFinding {
    const id = params.id || `cand-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();

    const candidate: CandidateFinding = {
      id,
      investigation_id: params.investigation_id,
      target_id: params.target_id,
      source_snapshot_id: params.source_snapshot_id,
      title: params.title,
      category: params.category,
      severity: params.severity,
      status: FindingStatus.CANDIDATE, // STRICT INVARIANT: Always starts at CANDIDATE
      confidence: params.confidence,
      confidence_basis: params.confidence_basis,
      engine: params.engine,
      engine_version: params.engine_version || '1.0.0',
      rule_id: params.rule_id,
      rule_version: params.rule_version || '1.0.0',
      file_path: params.file_path,
      line_start: params.line_start,
      line_end: params.line_end,
      matched_code: params.matched_code,
      evidence_artifact_ids: params.evidence_artifact_ids || [],
      cwe_ids: params.cwe_ids || [],
      owasp_categories: params.owasp_categories || [],
      remediation: params.remediation || '',
      corroborated: Boolean(params.corroborated),
      status_history: [
        {
          from_status: null,
          to_status: FindingStatus.CANDIDATE,
          timestamp: now,
          actor: params.actor || `engine:${params.engine}`,
          reason: 'Initial candidate creation',
        },
      ],
      provenance: {
        source_snapshot_id: params.source_snapshot_id,
        engine: params.engine,
        engine_version: params.engine_version || '1.0.0',
        rule_id: params.rule_id,
        rule_version: params.rule_version || '1.0.0',
        matched_at: now,
        source_file: params.file_path,
        line: params.line_start,
      },
      metadata: params.metadata || {},
      created_at: now,
      updated_at: now,
    };

    this.addCandidate(candidate);
    return candidate;
  }

  addCandidate(candidate: CandidateFinding): void {
    // Invariant: Initial state is ALWAYS CANDIDATE
    if (candidate.status !== FindingStatus.CANDIDATE) {
      candidate.status = FindingStatus.CANDIDATE;
    }
    if (!candidate.status_history || candidate.status_history.length === 0) {
      candidate.status_history = [
        {
          from_status: null,
          to_status: FindingStatus.CANDIDATE,
          timestamp: candidate.created_at || new Date().toISOString(),
          actor: `engine:${candidate.engine}`,
          reason: 'Initial candidate creation',
        },
      ];
    }
    this.candidates.set(candidate.id, { ...candidate });

    // Record evidence event
    try {
      globalEvidenceEventManager.recordEvent({
        investigation_id: candidate.investigation_id,
        event_type: 'CANDIDATE_RECORDED',
        actor: `engine:${candidate.engine}`,
        producer: candidate.engine,
        producer_version: candidate.engine_version,
        input_artifacts: candidate.evidence_artifact_ids,
        output_artifacts: [],
        metadata: {
          candidate_id: candidate.id,
          title: candidate.title,
          rule_id: candidate.rule_id,
          file_path: candidate.file_path,
          line: candidate.line_start,
          severity: candidate.severity,
          confidence: candidate.confidence,
        },
      });
    } catch {
      // Event record optional in unit environments
    }
  }

  getCandidate(id: string): CandidateFinding | undefined {
    return this.candidates.get(id);
  }

  listCandidates(
    investigationId?: string,
    filters?: {
      status?: string;
      engine?: string;
      category?: string;
      severity?: string;
      confidence?: string;
      corroborated?: boolean;
    }
  ): CandidateFinding[] {
    let list = Array.from(this.candidates.values());

    if (investigationId) {
      list = list.filter(c => c.investigation_id === investigationId);
    }

    if (filters?.status) {
      list = list.filter(c => c.status.toLowerCase() === filters.status!.toLowerCase());
    }

    if (filters?.engine) {
      list = list.filter(c => c.engine.toLowerCase().includes(filters.engine!.toLowerCase()));
    }

    if (filters?.category) {
      list = list.filter(c => c.category.toLowerCase() === filters.category!.toLowerCase());
    }

    if (filters?.severity) {
      list = list.filter(c => c.severity.toLowerCase() === filters.severity!.toLowerCase());
    }

    if (filters?.confidence) {
      list = list.filter(c => c.confidence.toLowerCase() === filters.confidence!.toLowerCase());
    }

    if (filters?.corroborated !== undefined) {
      list = list.filter(c => !!c.corroborated === filters.corroborated);
    }

    return list;
  }

  /**
   * Transitions a candidate's status while strictly adhering to the Phase 0 state machine.
   * Rejects illegal transitions (e.g. CANDIDATE -> CONFIRMED).
   */
  transitionStatus(
    candidateId: string,
    targetStatus: FindingStatus,
    reasonOrActor: string,
    actorOrReason?: string
  ): CandidateFinding {
    const candidate = this.candidates.get(candidateId);
    if (!candidate) {
      throw new Error(`Candidate finding '${candidateId}' not found.`);
    }

    let actor = 'security-analyst';
    let reason = reasonOrActor;

    if (actorOrReason) {
      // Both provided: convention (candidateId, targetStatus, reason, actor) or (id, status, actor, reason)
      // Check if actorOrReason looks like an actor or reason
      if (actorOrReason.includes(' ') || actorOrReason.length > 30) {
        reason = actorOrReason;
        actor = reasonOrActor;
      } else {
        actor = actorOrReason;
        reason = reasonOrActor;
      }
    }

    const hasArtifacts = (candidate.evidence_artifact_ids || []).length > 0;
    const validation = validateFindingTransition(candidate.status, targetStatus, hasArtifacts);

    if (!validation.allowed) {
      throw new Error(`Invalid state transition: ${validation.reason || `Illegal transition from ${candidate.status} to ${targetStatus}`}`);
    }

    const prevStatus = candidate.status;
    candidate.status = targetStatus;
    candidate.updated_at = new Date().toISOString();

    if (!candidate.status_history) {
      candidate.status_history = [];
    }

    candidate.status_history.push({
      from_status: prevStatus,
      to_status: targetStatus,
      timestamp: new Date().toISOString(),
      actor,
      reason,
    });

    if (!candidate.metadata) {
      candidate.metadata = {};
    }
    candidate.metadata.state_history = candidate.status_history;

    this.candidates.set(candidate.id, candidate);

    // Record provenance event
    try {
      globalEvidenceEventManager.recordEvent({
        investigation_id: candidate.investigation_id,
        event_type: 'FINDING_STATUS_TRANSITIONED',
        actor,
        producer: 'candidate_store',
        producer_version: '1.0.0',
        input_artifacts: candidate.evidence_artifact_ids,
        output_artifacts: [],
        metadata: {
          candidate_id: candidate.id,
          from_status: prevStatus,
          to_status: targetStatus,
          reason,
        },
      });
    } catch {
      // ignore in test context
    }

    return candidate;
  }

  /**
   * Retrieves all verified evidence artifacts associated with a candidate finding.
   */
  getEvidenceForCandidate(candidateId: string): {
    candidate: CandidateFinding;
    artifacts: any[];
    provenance_events: any[];
  } | null {
    const candidate = this.candidates.get(candidateId);
    if (!candidate) return null;

    const artifacts: any[] = [];
    for (const artId of candidate.evidence_artifact_ids) {
      const registered = registeredEvidenceArtifacts.get(artId);
      if (registered) {
        artifacts.push(registered.artifact);
      } else if ((globalArtifactStorage as any).getArtifact) {
        const art = (globalArtifactStorage as any).getArtifact(artId);
        if (art) {
          artifacts.push(art);
        }
      }
    }

    const provenance_events = (globalEvidenceEventManager as any)?.getEventsForArtifact
      ? candidate.evidence_artifact_ids.flatMap(id => (globalEvidenceEventManager as any).getEventsForArtifact(id))
      : [];

    return { candidate, artifacts, provenance_events };
  }

  clear(): void {
    this.candidates.clear();
  }
}

export const globalCandidateStore = new CandidateStore();
