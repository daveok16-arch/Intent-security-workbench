import { describe, it, expect } from 'vitest';
import { DatabaseStore } from '../../apps/api/db_store.js';
import { JobOrchestrator } from '../../packages/orchestrator/src/index.js';
import {
  BountyPlatform, TargetType, Ecosystem, Severity, FindingStatus,
  ArtifactType, SourceAcquisitionStatus
} from '../../packages/core/src/index.js';

describe('Full Workbench Security Research Lifecycle E2E Test (Phase 0 Complete Flow)', () => {
  it('should complete full lifecycle: Program -> Target -> Investigation -> Job -> Artifact -> Finding Candidate -> Verified State Transition', async () => {
    const db = new DatabaseStore();
    const orchestrator = new JobOrchestrator();

    // 1. Program Registration
    const program = db.createProgram({
      name: 'Immunefi Multi-Chain Lending Scope',
      platform: BountyPlatform.IMMUNEFI,
      external_identifier: 'lending-protocol-2026',
      scope: ['0x1111111111111111111111111111111111111111'],
      exclusions: ['Front-end social engineering'],
      bounty_policy: 'Up to $500k for Critical Direct Theft of Funds',
      disclosure_policy: '90-day standard responsible disclosure',
      technology: ['Solidity', 'Foundry'],
      metadata: {},
    });
    expect(program.id).toBeDefined();

    // 2. Target Definition
    const target = db.createTarget({
      program_id: program.id,
      name: 'LendingPoolCore',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/protocol/lending-core',
      commit_hash: '9a8b7c6d5e4f3a2b1c0d',
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      source_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      deployment_information: { address: '0x1111111111111111111111111111111111111111' },
      metadata: {},
    });
    expect(target.id).toBeDefined();

    // 3. Investigation Creation
    const investigation = db.createInvestigation({
      program_id: program.id,
      target_id: target.id,
      title: 'Liquidation Fee Precision Analysis',
      description: 'Evaluating interest calculation rounding bounds during high volatility',
    });
    expect(investigation.id).toBeDefined();

    // 4. Job Creation & Execution
    const job = orchestrator.createJob({
      id: `job-${Date.now()}`,
      investigation_id: investigation.id,
      target_id: target.id,
      engine: 'git-source-integrity',
      operation: 'verify_commit',
    });

    const finishedJob = await orchestrator.runJob(job.id, (artifact) => {
      db.evidence.set(artifact.id, artifact);
      db.rawArtifactStorage.set(artifact.id, artifact.content_preview);
    });

    expect(finishedJob.status).toBe('COMPLETED');
    expect(finishedJob.exit_code).toBe(0);

    // 5. Store Verified Evidence Artifact
    const evidence = db.storeEvidenceArtifact({
      investigation_id: investigation.id,
      target_id: target.id,
      artifact_type: ArtifactType.EXECUTION_TRACE,
      producer: 'researcher-reproduction-harness',
      producer_version: '1.0.0',
      command: 'forge test --match-test testFeeRounding',
      content: 'PASS: [testFeeRounding] precision loss demonstrated with 1 wei discrepancy',
      path_or_reference: 'traces/testFeeRounding.log',
    });
    expect(evidence.sha256).toBeDefined();
    expect(evidence.byte_size).toBeGreaterThan(0);

    // 6. Register Candidate Finding
    const finding = db.createFinding({
      investigation_id: investigation.id,
      target_id: target.id,
      title: 'Rounding Direction Inversion in calculateLiquidationBonus',
      category: 'CRYPTO_LOGIC',
      severity: Severity.MEDIUM,
      evidence_artifact_ids: [evidence.id],
      reproduction_steps: 'Run reproduction harness trace against pinned commit.',
    });

    expect(finding.status).toBe(FindingStatus.CANDIDATE);
    expect(finding.state_history).toHaveLength(1);

    // 7. Follow State Machine to VALIDATED and CONFIRMED
    db.transitionFinding(finding.id, FindingStatus.ANALYZING, 'Beginning AST dataflow analysis');
    db.transitionFinding(finding.id, FindingStatus.VERIFICATION_REQUIRED, 'Static model suggests potential rounding bias');
    db.transitionFinding(finding.id, FindingStatus.TESTING, 'Constructing test reproduction harness');
    db.transitionFinding(finding.id, FindingStatus.REPRODUCED, 'Reproduction test verified on local execution trace');
    db.transitionFinding(finding.id, FindingStatus.VALIDATED, 'Reviewed with linked machine-verifiable evidence artifact');
    const confirmed = db.transitionFinding(finding.id, FindingStatus.CONFIRMED, 'Final confirmation with evidence provenance');

    expect(confirmed.status).toBe(FindingStatus.CONFIRMED);
    expect(confirmed.state_history.length).toBe(7);
  });
});
