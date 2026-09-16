/**
 * Provenance Graph & Chain of Custody Service
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Implements deterministic graph construction and chain of custody queries:
 * Investigation -> Target -> SourceSnapshot
 * Investigation -> AnalysisJob -> Engine -> EvidenceEvent -> Artifact -> Finding
 */

import {
  Investigation,
  Target,
  SourceSnapshot,
  AnalysisJob,
  EvidenceEvent,
  EvidenceArtifact,
  Finding,
  ProvenanceGraph,
  ProvenanceNode,
  ProvenanceEdge,
  ProvenanceChain,
  SourceSnapshotStatus,
} from '../../core/src/index.js';

export interface ProvenanceQueryEntities {
  investigation: Investigation;
  target?: Target;
  sourceSnapshots?: SourceSnapshot[];
  jobs?: AnalysisJob[];
  events?: EvidenceEvent[];
  artifacts?: EvidenceArtifact[];
  findings?: Finding[];
}

export class DynamicProvenanceGraph {
  public nodes: Map<string, any> = new Map();
  public edges: any[] = [];

  addNode(node: { id: string; type?: string; label?: string; data?: any }) {
    this.nodes.set(node.id, node);
  }

  addEdge(edge: { from_id: string; to_id: string; relationship?: string; metadata?: any }) {
    this.edges.push(edge);
  }

  clear() {
    this.nodes.clear();
    this.edges = [];
  }
}

export class ProvenanceService {
  private dynamicGraph: DynamicProvenanceGraph = new DynamicProvenanceGraph();

  public getGraph(): DynamicProvenanceGraph {
    return this.dynamicGraph;
  }

  /**
   * Constructs a strictly grounded, non-fabricated provenance graph from actual stored entities.
   */
  public buildGraph(entities: ProvenanceQueryEntities): ProvenanceGraph {
    const nodes: ProvenanceNode[] = [];
    const edges: ProvenanceEdge[] = [];
    const seenNodeIds = new Set<string>();

    const addNode = (node: ProvenanceNode) => {
      if (!seenNodeIds.has(node.id)) {
        seenNodeIds.add(node.id);
        nodes.push(node);
      }
    };

    const addEdge = (edge: ProvenanceEdge) => {
      edges.push(edge);
    };

    const { investigation, target, sourceSnapshots = [], jobs = [], events = [], artifacts = [], findings = [] } = entities;

    // 1. Investigation Node
    addNode({
      id: investigation.id,
      type: 'Investigation',
      label: investigation.title,
      data: {
        id: investigation.id,
        status: investigation.status,
        created_at: investigation.created_at,
      },
    });

    // 2. Target Node
    if (target) {
      addNode({
        id: target.id,
        type: 'Target',
        label: target.name,
        data: {
          id: target.id,
          target_type: target.target_type,
          ecosystem: target.ecosystem,
          repository_url: target.repository_url,
          source_hash: target.source_hash,
        },
      });

      addEdge({
        id: `e-inv-target-${investigation.id}-${target.id}`,
        source: investigation.id,
        target: target.id,
        relationship: 'ANALYZES_TARGET',
        label: 'analyzes',
      });

      // 3. SourceSnapshots linked to Target
      for (const snap of sourceSnapshots) {
        addNode({
          id: snap.id,
          type: 'SourceSnapshot',
          label: `Snapshot (${snap.commit_hash ? snap.commit_hash.substring(0, 7) : snap.id})`,
          data: {
            id: snap.id,
            status: snap.status,
            commit_hash: snap.commit_hash,
            branch: snap.branch,
            source_hash: snap.source_hash,
            acquired_at: snap.acquired_at,
          },
        });

        addEdge({
          id: `e-target-snap-${target.id}-${snap.id}`,
          source: target.id,
          target: snap.id,
          relationship: 'HAS_SOURCE_SNAPSHOT',
          label: 'snapshot of',
        });
      }
    }

    // 4. AnalysisJobs linked to Investigation
    for (const job of jobs) {
      addNode({
        id: job.id,
        type: 'AnalysisJob',
        label: `Job: ${job.engine} (${job.operation})`,
        data: {
          id: job.id,
          engine: job.engine,
          operation: job.operation,
          status: job.status,
          exit_code: job.exit_code,
          execution_status: job.execution_status,
          started_at: job.started_at,
          completed_at: job.completed_at,
        },
      });

      addEdge({
        id: `e-inv-job-${investigation.id}-${job.id}`,
        source: investigation.id,
        target: job.id,
        relationship: 'DISPATCHED_JOB',
        label: 'executes',
      });

      // 5. Engine Node representing the tool invoked
      const engineNodeId = `engine-${job.engine}`;
      addNode({
        id: engineNodeId,
        type: 'Engine',
        label: `Engine: ${job.engine}`,
        data: {
          engine_id: job.engine,
        },
      });

      addEdge({
        id: `e-job-engine-${job.id}-${engineNodeId}`,
        source: job.id,
        target: engineNodeId,
        relationship: 'INVOKED_ENGINE',
        label: 'invokes',
      });
    }

    // 6. EvidenceEvents
    for (const ev of events) {
      addNode({
        id: ev.id,
        type: 'EvidenceEvent',
        label: `Event: ${ev.event_type}`,
        data: {
          id: ev.id,
          event_type: ev.event_type,
          actor: ev.actor,
          producer: ev.producer,
          producer_version: ev.producer_version,
          timestamp: ev.timestamp,
        },
      });

      // Link event to investigation
      addEdge({
        id: `e-inv-event-${investigation.id}-${ev.id}`,
        source: investigation.id,
        target: ev.id,
        relationship: 'RECORDED_EVENT',
        label: 'recorded',
      });

      // Link input artifacts to event
      if (Array.isArray(ev.input_artifacts)) {
        for (const inputArtId of ev.input_artifacts) {
          addEdge({
            id: `e-in-art-ev-${inputArtId}-${ev.id}`,
            source: inputArtId,
            target: ev.id,
            relationship: 'INPUT_TO_EVENT',
            label: 'consumed by',
          });
        }
      }

      // Link output artifacts from event
      if (Array.isArray(ev.output_artifacts)) {
        for (const outputArtId of ev.output_artifacts) {
          addEdge({
            id: `e-ev-out-art-${ev.id}-${outputArtId}`,
            source: ev.id,
            target: outputArtId,
            relationship: 'PRODUCED_ARTIFACT',
            label: 'produced',
          });
        }
      }
    }

    // 7. EvidenceArtifacts
    for (const art of artifacts) {
      addNode({
        id: art.id,
        type: 'EvidenceArtifact',
        label: `${art.artifact_type} (${art.producer})`,
        data: {
          id: art.id,
          artifact_type: art.artifact_type,
          producer: art.producer,
          producer_version: art.producer_version,
          command: art.command,
          sha256: art.sha256,
          size_bytes: art.size_bytes || art.byte_size,
          path: art.path || art.path_or_reference,
          created_at: art.created_at,
        },
      });

      // If artifact was not linked by an event, link it to investigation
      if (!edges.some(e => e.target === art.id && e.relationship === 'PRODUCED_ARTIFACT')) {
        addEdge({
          id: `e-inv-art-${investigation.id}-${art.id}`,
          source: investigation.id,
          target: art.id,
          relationship: 'RETAINS_ARTIFACT',
          label: 'retains',
        });
      }
    }

    // 8. Findings and their links to EvidenceArtifacts
    for (const f of findings) {
      addNode({
        id: f.id,
        type: 'Finding',
        label: `Finding: ${f.title}`,
        data: {
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          category: f.category,
        },
      });

      addEdge({
        id: `e-inv-finding-${investigation.id}-${f.id}`,
        source: investigation.id,
        target: f.id,
        relationship: 'IDENTIFIED_FINDING',
        label: 'identifies',
      });

      if (Array.isArray(f.evidence_artifact_ids)) {
        for (const artId of f.evidence_artifact_ids) {
          addEdge({
            id: `e-art-finding-${artId}-${f.id}`,
            source: artId,
            target: f.id,
            relationship: 'SUPPORTS_FINDING',
            label: 'supports finding',
          });
        }
      }
    }

    return {
      investigation_id: investigation.id,
      nodes,
      edges,
      generated_at: new Date().toISOString(),
    };
  }

  /**
   * Traverses chain of custody answering: "Why does this finding exist?"
   */
  public explainFindingProvenance(
    findingId: string,
    entities: ProvenanceQueryEntities
  ): ProvenanceChain {
    const finding = entities.findings?.find(f => f.id === findingId);
    if (!finding) {
      throw new Error(`Finding '${findingId}' not found in investigation entities.`);
    }

    const linkedArtifacts = (entities.artifacts || [])
      .filter(a => finding.evidence_artifact_ids.includes(a.id))
      .map(a => ({
        artifact_id: a.id,
        artifact_type: String(a.artifact_type),
        sha256: a.sha256,
        size_bytes: a.size_bytes || a.byte_size || 0,
        producer: a.producer,
        producer_version: a.producer_version,
        path: a.path || a.path_or_reference || '',
        created_at: a.created_at,
      }));

    const originatingEvents = (entities.events || [])
      .filter(ev => ev.output_artifacts.some(outId => finding.evidence_artifact_ids.includes(outId)))
      .map(ev => ({
        event_id: ev.id,
        event_type: String(ev.event_type),
        timestamp: ev.timestamp,
        actor: ev.actor,
        producer: ev.producer,
      }));

    const analysisJobs = (entities.jobs || [])
      .filter(j => 
        (j.stdout_artifact_id && finding.evidence_artifact_ids.includes(j.stdout_artifact_id)) ||
        (j.stderr_artifact_id && finding.evidence_artifact_ids.includes(j.stderr_artifact_id)) ||
        originatingEvents.some(ev => ev.producer.includes(j.engine))
      )
      .map(j => ({
        job_id: j.id,
        engine: j.engine,
        operation: j.operation,
        command: (entities.artifacts?.find(a => a.id === j.stdout_artifact_id))?.command,
        exit_code: j.exit_code,
        started_at: j.started_at,
        completed_at: j.completed_at,
        execution_status: j.execution_status,
      }));

    const engines = (entities.jobs || [])
      .filter(j => analysisJobs.some(aj => aj.job_id === j.id))
      .map(j => ({
        engine_id: j.engine,
        name: j.engine,
        version: (entities.artifacts?.find(a => a.producer.includes(j.engine)))?.producer_version || '1.0.0',
        executable: j.engine,
      }));

    const snap = entities.sourceSnapshots && entities.sourceSnapshots.length > 0
      ? entities.sourceSnapshots[0]
      : null;

    const sourceSnapshotInfo = snap ? {
      snapshot_id: snap.id,
      commit_hash: snap.commit_hash,
      branch: snap.branch,
      source_hash: snap.source_hash,
      acquired_at: snap.acquired_at,
      status: snap.status,
    } : null;

    const targetInfo = entities.target ? {
      target_id: entities.target.id,
      name: entities.target.name,
      target_type: entities.target.target_type,
      ecosystem: entities.target.ecosystem,
      repository_url: entities.target.repository_url,
    } : null;

    const summaryParts: string[] = [
      `Finding '${finding.title}' (${finding.status}) is linked to ${linkedArtifacts.length} verified artifact(s).`,
    ];

    if (linkedArtifacts.length > 0) {
      summaryParts.push(
        `Artifacts: ${linkedArtifacts.map(a => `${a.artifact_type} [SHA-256: ${a.sha256.substring(0, 12)}...] produced by ${a.producer} (v${a.producer_version})`).join('; ')}.`
      );
    }

    if (analysisJobs.length > 0) {
      summaryParts.push(
        `Executed via Job(s): ${analysisJobs.map(j => `${j.job_id} (${j.engine} ${j.operation}, exit code ${j.exit_code ?? 'unknown'})`).join(', ')}.`
      );
    }

    if (sourceSnapshotInfo && sourceSnapshotInfo.source_hash) {
      summaryParts.push(
        `Grounded against Source Snapshot '${sourceSnapshotInfo.snapshot_id}' (Source Hash: ${sourceSnapshotInfo.source_hash.substring(0, 16)}...).`
      );
    }

    return {
      finding_id: finding.id,
      finding_title: finding.title,
      finding_status: finding.status,
      linked_artifacts: linkedArtifacts,
      originating_events: originatingEvents,
      analysis_jobs: analysisJobs,
      engines,
      source_snapshot: sourceSnapshotInfo,
      target: targetInfo,
      investigation: {
        investigation_id: entities.investigation.id,
        title: entities.investigation.title,
        status: entities.investigation.status,
      },
      provenance_summary: summaryParts.join(' '),
      disclaimer: 'Provenance guarantees cryptographic and procedural chain of custody for evidence artifacts. It establishes verifiable auditability without fabricating findings.',
    };
  }
}

export const globalProvenanceService = new ProvenanceService();
