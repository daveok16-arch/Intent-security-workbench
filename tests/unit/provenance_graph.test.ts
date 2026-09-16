import { describe, it, expect } from 'vitest';
import { ProvenanceService } from '../../packages/evidence/src/provenance.js';
import {
  Investigation,
  Target,
  AnalysisJob,
  EvidenceArtifact,
  Finding,
  ArtifactType,
  JobStatus,
  FindingStatus,
  InvestigationStatus,
  SourceAcquisitionStatus,
  TargetType,
  Ecosystem,
  Severity,
  Confidence,
} from '../../packages/core/src/index.js';

describe('Phase 0.2 — ProvenanceService Graph & Chain-of-Custody Tests', () => {
  const service = new ProvenanceService();

  const mockInvestigation: Investigation = {
    id: 'inv-prov-1',
    program_id: 'prog-1',
    target_id: 'tgt-1',
    title: 'Audit Vault Security',
    description: 'Security audit of smart contract vault',
    status: InvestigationStatus.ACTIVE,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const mockTarget: Target = {
    id: 'tgt-1',
    program_id: 'prog-1',
    name: 'Vault Contract',
    target_type: TargetType.SMART_CONTRACT,
    ecosystem: Ecosystem.EVM,
    source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
    deployment_information: {},
    metadata: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const mockJob: AnalysisJob = {
    id: 'job-1',
    investigation_id: 'inv-prov-1',
    target_id: 'tgt-1',
    engine: 'slither',
    operation: 'analyze',
    status: JobStatus.COMPLETED,
    retry_count: 0,
    max_retries: 2,
    metadata: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const mockArtifact: EvidenceArtifact = {
    id: 'art-1',
    investigation_id: 'inv-prov-1',
    target_id: 'tgt-1',
    artifact_type: ArtifactType.ENGINE_STDOUT,
    producer: 'slither',
    producer_version: '0.10.0',
    command: 'slither . --json -',
    path: 'storage/jobs/job-1/stdout.log',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    size_bytes: 120,
    mime_type: 'text/plain',
    metadata: {},
    created_at: new Date().toISOString(),
  };

  const mockFinding: Finding = {
    id: 'fnd-1',
    investigation_id: 'inv-prov-1',
    target_id: 'tgt-1',
    title: 'Unprotected Reentrancy',
    category: 'Reentrancy',
    severity: Severity.HIGH,
    confidence: Confidence.HIGH,
    status: FindingStatus.CANDIDATE,
    evidence_artifact_ids: ['art-1'],
    reproduction_steps: 'Run forge test',
    state_history: [],
    metadata: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  it('should build a deterministic provenance graph with correct nodes and directed edges', () => {
    const graph = service.buildGraph({
      investigation: mockInvestigation,
      target: mockTarget,
      sourceSnapshots: [],
      jobs: [mockJob],
      events: [],
      artifacts: [mockArtifact],
      findings: [mockFinding],
    });

    expect(graph.investigation_id).toBe(mockInvestigation.id);
    expect(graph.nodes.length).toBeGreaterThanOrEqual(4);
    expect(graph.edges.length).toBeGreaterThanOrEqual(3);

    // Verify investigation node
    const invNode = graph.nodes.find((n: any) => n.id === mockInvestigation.id);
    expect(invNode).toBeDefined();
    expect(invNode?.type).toBe('Investigation');

    // Verify finding node
    const fndNode = graph.nodes.find((n: any) => n.id === mockFinding.id);
    expect(fndNode).toBeDefined();
    expect(fndNode?.type).toBe('Finding');

    // Verify edges
    const artifactToFinding = graph.edges.find((e: any) => e.source === mockArtifact.id && e.target === mockFinding.id);
    expect(artifactToFinding).toBeDefined();
    expect(artifactToFinding?.relationship).toBe('SUPPORTS_FINDING');
  });

  it('should build chain of custody explanation for a finding', () => {
    const chain = service.explainFindingProvenance(
      mockFinding.id,
      {
        investigation: mockInvestigation,
        target: mockTarget,
        jobs: [mockJob],
        artifacts: [mockArtifact],
        findings: [mockFinding],
      }
    );

    expect(chain.finding_id).toBe(mockFinding.id);
    expect(chain.linked_artifacts.length).toBe(1);
    expect(chain.provenance_summary).toContain('Unprotected Reentrancy');
  });
});
