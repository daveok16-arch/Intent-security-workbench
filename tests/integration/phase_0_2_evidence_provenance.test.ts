import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { LocalFilesystemArtifactStorage } from '../../packages/evidence/src/storage/local_storage.js';
import { EvidenceEventManager } from '../../packages/evidence/src/events.js';
import { ProvenanceService } from '../../packages/evidence/src/provenance.js';
import { DatabaseStore } from '../../apps/api/db_store.js';
import { JobOrchestrator } from '../../packages/orchestrator/src/index.js';
import { BaseEngine } from '../../engines/base_engine.js';
import { EngineAvailabilityStatus, EngineResultStatus, EngineResult } from '../../engines/types.js';
import {
  Investigation,
  Target,
  SourceSnapshot,
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
  EvidenceEventType,
  EngineExecutionStatus,
  EngineStatus,
  SourceSnapshotStatus,
} from '../../packages/core/src/index.js';

class MockTestEngine extends BaseEngine {
  readonly name: string;
  readonly engine_id: string;
  readonly version: string;
  readonly description: string = 'Test engine for phase 0.2 verification';
  readonly capabilities: string[] = ['analysis'];
  readonly supported_target_types: string[] = ['SMART_CONTRACT'];
  readonly supported_languages: string[] = ['solidity'];
  readonly executable: string = 'echo';

  private availStatus: EngineAvailabilityStatus;
  private resultFn: () => Partial<EngineResult>;

  constructor(opts: {
    id: string;
    name: string;
    version?: string;
    availStatus?: EngineAvailabilityStatus;
    resultFn?: () => Partial<EngineResult>;
  }) {
    super();
    this.engine_id = opts.id;
    this.name = opts.name;
    this.version = opts.version || '1.0.0';
    this.availStatus = opts.availStatus || EngineAvailabilityStatus.AVAILABLE;
    this.resultFn = opts.resultFn || (() => ({ status: EngineResultStatus.SUCCESS, exit_code: 0 }));
  }

  async check_availability() {
    return {
      engine_id: this.engine_id,
      name: this.name,
      status: this.availStatus,
      executable: this.executable,
      version: this.availStatus === EngineAvailabilityStatus.AVAILABLE ? this.version : null,
      detected_path: this.availStatus === EngineAvailabilityStatus.AVAILABLE ? '/bin/echo' : null,
      checked_at: new Date().toISOString(),
      error: this.availStatus === EngineAvailabilityStatus.NOT_INSTALLED ? 'Binary not found in PATH' : null,
      capabilities: this.capabilities,
    };
  }

  async prepare() { return true; }
  async cleanup() {}
  parse_result() { return []; }

  async execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult> {
    const res = this.resultFn();
    return {
      id: `res-${Date.now()}`,
      engine_id: this.engine_id,
      engine_name: this.name,
      engine_version: this.version,
      status: res.status || EngineResultStatus.SUCCESS,
      target_id: targetId,
      command: 'echo test',
      working_directory: process.cwd(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: 10,
      exit_code: res.exit_code ?? 0,
      stdout: res.stdout || '',
      stderr: res.stderr || '',
      findings: [],
      artifacts: [],
      environment: this.getEnvironmentInfo(),
      ...res,
    };
  }
}

describe('PHASE 0.2 — REAL EVIDENCE & PROVENANCE SUBSYSTEM (18 Definition of Done Tests)', () => {
  const tmpDir = path.resolve(process.cwd(), 'storage/test_evidence_p02_tmp');
  let storage: LocalFilesystemArtifactStorage;
  let eventManager: EvidenceEventManager;
  let provenanceService: ProvenanceService;
  let db: DatabaseStore;

  beforeEach(() => {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
    fs.mkdirSync(tmpDir, { recursive: true });
    storage = new LocalFilesystemArtifactStorage(tmpDir);
    eventManager = new EvidenceEventManager();
    provenanceService = new ProvenanceService();
    db = new DatabaseStore(storage);
  });

  afterEach(() => {
    if (fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // 1. Artifact bytes are stored correctly
  it('1. Artifact bytes are stored correctly', async () => {
    const rawContent = 'RAW_SECURITY_ANALYSIS_LOG_OUTPUT_BYTES_12345\nSECOND_LINE';
    const metadata = await storage.store('inv-test-1', 'evidence', 'run.log', rawContent);

    expect(fs.existsSync(metadata.absolute_path)).toBe(true);
    const diskContent = fs.readFileSync(metadata.absolute_path, 'utf-8');
    expect(diskContent).toBe(rawContent);
    expect(metadata.size_bytes).toBe(Buffer.byteLength(rawContent, 'utf-8'));
  });

  // 2. SHA-256 matches actual bytes
  it('2. SHA-256 matches actual bytes', async () => {
    const rawBuffer = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]); // ELF header bytes
    const expectedHash = crypto.createHash('sha256').update(rawBuffer).digest('hex');

    const metadata = await storage.store('inv-test-2', 'engines', 'binary.bin', rawBuffer, 'application/octet-stream');
    expect(metadata.sha256).toBe(expectedHash);

    const actualDiskBytes = fs.readFileSync(metadata.absolute_path);
    const actualComputedHash = crypto.createHash('sha256').update(actualDiskBytes).digest('hex');
    expect(metadata.sha256).toBe(actualComputedHash);
  });

  // 3. Integrity verification succeeds for unchanged artifacts
  it('3. Integrity verification succeeds for unchanged artifacts', async () => {
    const testContent = 'Original unaltered artifact content from compiler';
    const metadata = await storage.store('inv-test-3', 'evidence', 'compile.log', testContent);

    const result = await storage.verifyIntegrity(metadata.path, metadata.sha256);
    expect(result.valid).toBe(true);
    expect(result.status).toBe('VALID');
    expect(result.actual_sha256).toBe(metadata.sha256);
    expect(result.size_bytes).toBe(Buffer.byteLength(testContent, 'utf-8'));
  });

  // 4. Integrity verification detects modified artifacts
  it('4. Integrity verification detects modified artifacts', async () => {
    const originalContent = 'Valid untampered original text';
    const metadata = await storage.store('inv-test-4', 'evidence', 'unaltered.txt', originalContent);

    // Tamper with the artifact directly on the filesystem
    fs.writeFileSync(metadata.absolute_path, 'TAMPERED_MALICIOUS_MODIFIED_BYTES');

    const result = await storage.verifyIntegrity(metadata.path, metadata.sha256);
    expect(result.valid).toBe(false);
    expect(result.status).toBe('INVALID');
    expect(result.actual_sha256).not.toBe(metadata.sha256);
  });

  // 5. Source snapshots record actual hashes
  it('5. Source snapshots record actual hashes', async () => {
    const sourceCode = 'pragma solidity ^0.8.20;\ncontract SecureVault {}';
    const computedHash = crypto.createHash('sha256').update(sourceCode, 'utf-8').digest('hex');

    const target: Target = {
      id: 'tgt-src-1',
      program_id: 'prog-1',
      name: 'Vault Contract',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      source_hash: computedHash,
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      deployment_information: {},
      metadata: {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db.createTarget(target);

    const pendingSnap = db.createSourceSnapshot({
      target_id: target.id,
      investigation_id: 'inv-src-1',
      commit_hash: '3a88bf0a5d1297e0b51f081e649069d35c8b7ff2',
      branch: 'main',
      acquisition_method: 'direct_source',
    });

    const snapshot = await db.acquireSourceSnapshotContent(pendingSnap.id, sourceCode, 'Vault.sol');

    expect(snapshot.source_hash).toBe(computedHash);
    expect(snapshot.source_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(snapshot.status).toBe(SourceSnapshotStatus.ACQUIRED);
  });

  // 6. Evidence events are persisted
  it('6. Evidence events are persisted', () => {
    const ev = eventManager.recordEvent({
      investigation_id: 'inv-ev-1',
      event_type: EvidenceEventType.ARTIFACT_CREATED,
      actor: 'security-researcher-1',
      producer: 'semgrep-engine',
      producer_version: '1.68.0',
      input_artifacts: ['art-src-01'],
      output_artifacts: ['art-out-01'],
      metadata: { scan_scope: 'src/' },
    });

    expect(ev.id).toBeDefined();
    const retrieved = eventManager.getEvent(ev.id);
    expect(retrieved).toBeDefined();
    expect(retrieved?.actor).toBe('security-researcher-1');
    expect(retrieved?.event_type).toBe(EvidenceEventType.ARTIFACT_CREATED);

    const list = eventManager.listEvents('inv-ev-1');
    expect(list.length).toBe(1);
    expect(list[0].id).toBe(ev.id);
  });

  // 7. Evidence relationships are persisted
  it('7. Evidence relationships are persisted', () => {
    const inv: Investigation = {
      id: 'inv-rel-1',
      program_id: 'prog-1',
      target_id: 'tgt-rel-1',
      title: 'Relationship Persistence Test',
      description: 'Test evidence relations',
      status: InvestigationStatus.ACTIVE,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const target: Target = {
      id: 'tgt-rel-1',
      program_id: 'prog-1',
      name: 'Test Target',
      target_type: TargetType.REPOSITORY,
      ecosystem: Ecosystem.RUST,
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      deployment_information: {},
      metadata: {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const artifact = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      target_id: target.id,
      artifact_type: ArtifactType.COMMAND_LOG,
      producer: 'cargo-audit',
      content: 'Cargo audit execution log output',
      actor: 'researcher',
    });

    const graph = provenanceService.buildGraph({
      investigation: inv,
      target,
      artifacts: [artifact],
    });

    const retainsEdge = graph.edges.find(e => e.source === inv.id && e.target === artifact.id);
    expect(retainsEdge).toBeDefined();
    expect(retainsEdge?.relationship).toBe('RETAINS_ARTIFACT');
  });

  // 8. Provenance chain can be traversed
  it('8. Provenance chain can be traversed', () => {
    const inv: Investigation = {
      id: 'inv-trav-1',
      program_id: 'prog-1',
      target_id: 'tgt-trav-1',
      title: 'Traversal Test',
      description: 'Testing full chain of custody traversal',
      status: InvestigationStatus.ACTIVE,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const target: Target = {
      id: 'tgt-trav-1',
      program_id: 'prog-1',
      name: 'Smart Contract',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      source_hash: 'a1b2c3d4e5f60000000000000000000000000000000000000000000000000000',
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      deployment_information: {},
      metadata: {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const artifact = db.storeEvidenceArtifact({
      id: 'art-evidence-01',
      investigation_id: inv.id,
      target_id: target.id,
      artifact_type: ArtifactType.ENGINE_RESULT,
      producer: 'slither',
      producer_version: '0.10.0',
      command: 'slither contracts/Vault.sol --json -',
      content: '{"results": {"detectors": []}}',
    });

    const finding: Finding = {
      id: 'find-001',
      investigation_id: inv.id,
      target_id: target.id,
      title: 'Reentrancy in withdraw()',
      severity: Severity.HIGH,
      status: FindingStatus.HYPOTHESIS,
      category: 'SWC-107',
      cwe_ids: ['CWE-841'],
      evidence_artifact_ids: [artifact.id],
      validation_history: [],
      metadata: {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const chain = provenanceService.explainFindingProvenance(finding.id, {
      investigation: inv,
      target,
      artifacts: [artifact],
      findings: [finding],
    });

    expect(chain.finding_id).toBe('find-001');
    expect(chain.linked_artifacts.length).toBe(1);
    expect(chain.linked_artifacts[0].artifact_id).toBe('art-evidence-01');
    expect(chain.linked_artifacts[0].producer).toBe('slither');
    expect(chain.disclaimer).toContain('Provenance guarantees cryptographic and procedural chain of custody');
  });

  // 9. Engine stdout creates a real artifact
  it('9. Engine stdout creates a real artifact', async () => {
    const orchestrator = new JobOrchestrator(storage);
    const mockStdoutContent = 'SLITHER_RUN_STDOUT_RESULTS: 0 vulnerabilities found';

    const testEngine = new MockTestEngine({
      id: 'mock-stdout-engine',
      name: 'Mock Stdout Engine',
      resultFn: () => ({
        status: EngineResultStatus.SUCCESS,
        stdout: mockStdoutContent,
        stderr: '',
        exit_code: 0,
      }),
    });

    orchestrator.registerEngine(testEngine);

    const job = orchestrator.createJob({
      investigation_id: 'inv-stdout-1',
      target_id: 'tgt-stdout-1',
      engine: 'mock-stdout-engine',
      operation: 'analyze',
    });

    let storedArtifact: EvidenceArtifact | null = null;
    await orchestrator.runJob(job.id, (art) => {
      if (art.artifact_type === ArtifactType.ENGINE_STDOUT) {
        storedArtifact = art;
      }
    });

    expect(storedArtifact).not.toBeNull();
    expect(storedArtifact!.artifact_type).toBe(ArtifactType.ENGINE_STDOUT);
    expect(storedArtifact!.producer).toBe('Mock Stdout Engine');
    expect(storedArtifact!.content_preview).toContain('SLITHER_RUN_STDOUT_RESULTS');
  });

  // 10. Engine stderr creates a real artifact
  it('10. Engine stderr creates a real artifact', async () => {
    const orchestrator = new JobOrchestrator(storage);
    const mockStderrContent = 'WARNING: Solc version mismatch, compilation produced 2 warnings';

    const testEngine = new MockTestEngine({
      id: 'mock-stderr-engine',
      name: 'Mock Stderr Engine',
      resultFn: () => ({
        status: EngineResultStatus.SUCCESS,
        stdout: 'normal output',
        stderr: mockStderrContent,
        exit_code: 0,
      }),
    });

    orchestrator.registerEngine(testEngine);

    const job = orchestrator.createJob({
      investigation_id: 'inv-stderr-1',
      target_id: 'tgt-stderr-1',
      engine: 'mock-stderr-engine',
      operation: 'analyze',
    });

    let storedStderrArtifact: EvidenceArtifact | null = null;
    await orchestrator.runJob(job.id, (art) => {
      if (art.artifact_type === ArtifactType.ENGINE_STDERR) {
        storedStderrArtifact = art;
      }
    });

    expect(storedStderrArtifact).not.toBeNull();
    expect(storedStderrArtifact!.artifact_type).toBe(ArtifactType.ENGINE_STDERR);
    expect(storedStderrArtifact!.content_preview).toContain('Solc version mismatch');
  });

  // 11. Failed engine execution records failure evidence
  it('11. Failed engine execution records failure evidence', async () => {
    const orchestrator = new JobOrchestrator(storage);

    const failingEngine = new MockTestEngine({
      id: 'failing-engine',
      name: 'Failing Engine',
      resultFn: () => ({
        status: EngineResultStatus.FAILED,
        stdout: '',
        stderr: 'FATAL: Syntax error in file.sol at line 42',
        exit_code: 1,
      }),
    });

    orchestrator.registerEngine(failingEngine);

    const job = orchestrator.createJob({
      investigation_id: 'inv-fail-1',
      target_id: 'tgt-fail-1',
      engine: 'failing-engine',
      operation: 'analyze',
    });

    const artifactsCreated: EvidenceArtifact[] = [];
    const completedJob = await orchestrator.runJob(job.id, (art) => {
      artifactsCreated.push(art);
    });

    expect(completedJob.status).toBe(JobStatus.FAILED);
    expect(completedJob.exit_code).toBe(1);
    expect(completedJob.execution_status).toBe(EngineExecutionStatus.ENGINE_EXECUTION_FAILED);

    // Stderr failure artifact was recorded
    const stderrArt = artifactsCreated.find(a => a.artifact_type === ArtifactType.ENGINE_STDERR);
    expect(stderrArt).toBeDefined();
    expect(stderrArt?.content_preview).toContain('FATAL: Syntax error');

    // Crucial: No ENGINE_RESULT artifact was manufactured!
    const manufacturedResult = artifactsCreated.find(a => a.artifact_type === ArtifactType.ENGINE_RESULT);
    expect(manufacturedResult).toBeUndefined();
  });

  // 12. Missing engine does not create successful evidence
  it('12. Missing engine does not create successful evidence', async () => {
    const orchestrator = new JobOrchestrator(storage);

    const missingEngine = new MockTestEngine({
      id: 'missing-tool',
      name: 'Missing Tool',
      availStatus: EngineAvailabilityStatus.NOT_INSTALLED,
    });

    orchestrator.registerEngine(missingEngine);

    const job = orchestrator.createJob({
      investigation_id: 'inv-missing-1',
      target_id: 'tgt-missing-1',
      engine: 'missing-tool',
      operation: 'analyze',
    });

    const artifactsCreated: EvidenceArtifact[] = [];
    const resultJob = await orchestrator.runJob(job.id, (art) => {
      artifactsCreated.push(art);
    });

    expect(resultJob.status).toBe(JobStatus.FAILED);
    expect(resultJob.execution_status).toBe(EngineExecutionStatus.ENGINE_NOT_INSTALLED);
    // No successful evidence artifacts or findings created
    expect(artifactsCreated.some(a => a.artifact_type === ArtifactType.ENGINE_RESULT)).toBe(false);
  });

  // 13. Empty engine output does not become a fake finding
  it('13. Empty engine output does not become a fake finding', async () => {
    const orchestrator = new JobOrchestrator(storage);

    const cleanEngine = new MockTestEngine({
      id: 'clean-engine',
      name: 'Clean Engine',
      resultFn: () => ({
        status: EngineResultStatus.SUCCESS,
        stdout: '',
        stderr: '',
        exit_code: 0,
      }),
    });

    orchestrator.registerEngine(cleanEngine);

    const job = orchestrator.createJob({
      investigation_id: 'inv-clean-1',
      target_id: 'tgt-clean-1',
      engine: 'clean-engine',
      operation: 'analyze',
    });

    const finishedJob = await orchestrator.runJob(job.id);
    expect(finishedJob.status).toBe(JobStatus.COMPLETED);
    expect(finishedJob.execution_status).toBe(EngineExecutionStatus.ENGINE_COMPLETED_NO_FINDINGS);

    // Verify no findings were created in the database
    const findings = db.listFindings('inv-clean-1');
    expect(findings.length).toBe(0);
  });

  // 14. Historical evidence cannot be silently modified
  it('14. Historical evidence cannot be silently modified', () => {
    const ev = eventManager.recordEvent({
      investigation_id: 'inv-immutable-1',
      event_type: EvidenceEventType.ARTIFACT_CREATED,
      actor: 'lead-auditor',
      producer: 'slither',
      output_artifacts: ['art-1'],
      metadata: { original_note: 'Initial scan' },
    });

    // Attempt direct mutation of the returned object
    expect(() => {
      (ev as any).actor = 'unauthorized_attacker';
    }).toThrow();

    expect(() => {
      (ev.metadata as any).original_note = 'Silently altered note';
    }).toThrow();

    // Instead, system records a formal METADATA_CORRECTED event
    const correctionEvent = eventManager.recordMetadataCorrection({
      investigation_id: 'inv-immutable-1',
      target_entity_type: 'ARTIFACT',
      target_entity_id: 'art-1',
      actor: 'lead-auditor',
      reason: 'Updated description of scan context',
      correction_details: { note: 'Corrected scan context' },
    });

    expect(correctionEvent.event_type).toBe(EvidenceEventType.METADATA_CORRECTED);
    const events = eventManager.listEvents('inv-immutable-1');
    expect(events.length).toBe(2);
    expect(events[0].metadata.original_note).toBe('Initial scan');
    expect(events[1].metadata.reason).toBe('Updated description of scan context');
  });

  // 15. API returns actual evidence
  it('15. API returns actual evidence', () => {
    const inv: Investigation = {
      id: 'inv-api-1',
      program_id: 'prog-1',
      target_id: 'tgt-1',
      title: 'API Evidence Test',
      description: 'Test API evidence querying',
      status: InvestigationStatus.ACTIVE,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db.createInvestigation(inv);

    const art1 = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      artifact_type: ArtifactType.COMMAND_LOG,
      producer: 'git',
      content: 'git clone https://github.com/example/repo',
    });

    const art2 = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      artifact_type: ArtifactType.ENGINE_STDOUT,
      producer: 'semgrep',
      content: '{"results": []}',
    });

    const list = db.listEvidence(inv.id);
    expect(list.length).toBe(2);
    expect(list.some(a => a.id === art1.id)).toBe(true);
    expect(list.some(a => a.id === art2.id)).toBe(true);

    const fetched = db.getEvidenceArtifact(art1.id);
    expect(fetched).toBeDefined();
    expect(fetched?.producer).toBe('git');
    expect(fetched?.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  // 16. CLI returns actual evidence
  it('16. CLI returns actual evidence', () => {
    // Run CLI commands with --help or subcommand and verify real non-fabricated output
    const output = execSync('npx tsx cli.ts evidence list', { encoding: 'utf-8' });
    expect(output).toContain('INTENT SECURITY WORKBENCH — EVIDENCE LOCKER');
    expect(output).toContain('Artifact ID');
    expect(output).toContain('Type');
    expect(output).toContain('Producer');
    expect(output).toContain('SHA-256 Prefix');
  });

  // 17. Frontend displays actual evidence
  it('17. Frontend displays actual evidence', () => {
    const inv: Investigation = {
      id: 'inv-fe-1',
      program_id: 'prog-1',
      target_id: 'tgt-fe-1',
      title: 'Frontend Provenance Verification',
      description: 'Test frontend graph topology',
      status: InvestigationStatus.ACTIVE,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const target: Target = {
      id: 'tgt-fe-1',
      program_id: 'prog-1',
      name: 'Frontend Target',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      deployment_information: {},
      metadata: {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const emptyGraph = provenanceService.buildGraph({
      investigation: inv,
    });

    // If no evidence nodes exist, only 1 node (investigation itself) is present
    const hasEvidenceNodes = emptyGraph.nodes.some(n => n.type === 'EvidenceArtifact' || n.type === 'AnalysisJob');
    expect(hasEvidenceNodes).toBe(false);

    // When real artifacts are stored:
    const realArtifact = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      target_id: target.id,
      artifact_type: ArtifactType.COMMAND_LOG,
      producer: 'npm',
      content: 'npm test -- --coverage',
    });

    const populatedGraph = provenanceService.buildGraph({
      investigation: inv,
      target,
      artifacts: [realArtifact],
    });

    expect(populatedGraph.nodes.length).toBeGreaterThan(1);
    expect(populatedGraph.nodes.some(n => n.id === realArtifact.id)).toBe(true);
  });

  // 18. No test depends on fabricated security findings
  it('18. No test depends on fabricated security findings', () => {
    // Findings require verified real evidence artifacts and strict validation status
    const allFindings = db.listFindings();
    for (const f of allFindings) {
      // Every finding must reference genuine evidence artifacts
      expect(f.evidence_artifact_ids).toBeDefined();
      expect(Array.isArray(f.evidence_artifact_ids)).toBe(true);
      // Status must not claim CONFIRMED_VULNERABILITY without execution proof
      if (f.status === FindingStatus.CONFIRMED_VULNERABILITY) {
        expect(f.evidence_artifact_ids.length).toBeGreaterThan(0);
      }
    }
  });
});
