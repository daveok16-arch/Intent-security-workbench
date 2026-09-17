/**
 * Relational Data Store & Persistence Layer for Intent Security Workbench
 * Phase 1 Scope & Target Authorization Subsystem
 * 
 * Strict Phase 1 Rules:
 * No fake data. Only real, researcher-created records.
 * Deterministic scope evaluation, sandboxed Git source acquisition,
 * and immutable evidence / provenance linking.
 */

import {
  Program, Target, Investigation, AnalysisJob, EvidenceArtifact, Finding,
  FindingStatus, JobStatus, InvestigationStatus, SourceAcquisitionStatus,
  BountyPlatform, TargetType, Ecosystem, Severity, Confidence, ArtifactType,
  ArtifactProvenance,
  EvidenceEvent, EvidenceEventType, SourceSnapshot, SourceSnapshotStatus,
  ProvenanceGraph, ProvenanceChain, ScopeEntry, ScopeInclusionStatus, ScopeAssetType,
  ProgramStatus, ProgramFreshnessStatus, TargetAuthorizationStatus, TargetScopeStatus,
  ScopeDecisionResult, InvestigationGateResult,
  validateFindingTransition, VALID_FINDING_TRANSITIONS,
  ScopeDecisionService, InvestigationGateService
} from '../../packages/core/src/index.js';
import {
  computeArtifactSHA256,
  createEvidenceArtifact,
  globalArtifactStorage,
  globalEvidenceEventManager,
  globalSourceSnapshotService,
  globalProvenanceService,
  registeredEvidenceArtifacts,
  IArtifactStorage,
} from '../../packages/evidence/src/index.js';
import { globalGitSourceProvider } from '../../packages/source/src/index.js';
import { globalProgramAdapterRegistry } from '../../adapters/programs/index.js';
import {
  APIContract,
  APIEndpoint,
  AuthorizationCandidate,
  ContractDiffResult,
} from '../../packages/api-analysis/src/types.js';
import { VerificationResult } from '../../packages/formal-verification/src/types.js';
import { DynamicVerificationJob } from '../../packages/dynamic-verification/src/types.js';

export class DatabaseStore {
  public programs: Map<string, Program> = new Map();
  public targets: Map<string, Target> = new Map();
  public scopeEntries: Map<string, ScopeEntry> = new Map();
  public investigations: Map<string, Investigation> = new Map();
  public evidence: Map<string, EvidenceArtifact> = new Map();
  public rawArtifactStorage: Map<string, string | Buffer> = new Map();
  public findings: Map<string, Finding> = new Map();
  public apiContracts: Map<string, APIContract> = new Map();
  public authorizationCandidates: Map<string, AuthorizationCandidate> = new Map();
  public contractDiffs: Map<string, ContractDiffResult> = new Map();
  public verificationResults: Map<string, VerificationResult> = new Map();
  public dynamicVerificationJobs: Map<string, DynamicVerificationJob> = new Map();
  public storage: IArtifactStorage = globalArtifactStorage;

  constructor(storage?: IArtifactStorage) {
    if (storage) {
      this.storage = storage;
    }
    // Empty on startup - zero fake records
  }

  // --- Program Operations ---
  createProgram(data: Omit<Program, 'id' | 'created_at' | 'updated_at'> & { id?: string }): Program {
    const id = data.id || `prog-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const program: Program = {
      id,
      name: data.name,
      platform: data.platform || BountyPlatform.CUSTOM,
      external_id: data.external_id || data.external_identifier || '',
      external_identifier: data.external_identifier || data.external_id || '',
      program_url: data.program_url || '',
      organization: data.organization || '',
      description: data.description || '',
      status: data.status || ProgramStatus.ACTIVE,
      policy_version: data.policy_version || '1.0.0',
      scope: data.scope || [],
      exclusions: data.exclusions || [],
      testing_rules: data.testing_rules || [],
      disclosure_rules: data.disclosure_rules || [],
      bounty_rules: data.bounty_rules || data.bounty_policy || '',
      bounty_policy: data.bounty_policy || data.bounty_rules || '',
      disclosure_policy: data.disclosure_policy || '',
      technology: data.technology || [],
      freshness_status: data.freshness_status || ProgramFreshnessStatus.CURRENT,
      retrieved_at: data.retrieved_at || now,
      last_verified_at: data.last_verified_at || now,
      source_reference: data.source_reference || data.program_url || '',
      source_hash: data.source_hash || '',
      metadata: data.metadata || {},
      created_at: now,
      updated_at: now,
    };
    this.programs.set(id, program);

    // If scope entries were provided, normalize and store them
    if (Array.isArray(data.scope) && data.scope.length > 0) {
      const adapter = globalProgramAdapterRegistry.get(program.platform);
      const normalized = adapter.normalize_scope(data.scope, id);
      for (const entry of normalized) {
        this.scopeEntries.set(entry.id, entry);
      }
    }

    return program;
  }

  getProgram(id: string): Program | undefined {
    return this.programs.get(id);
  }

  listPrograms(): Program[] {
    return Array.from(this.programs.values()).sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }

  updateProgram(id: string, updates: Partial<Program>): Program {
    const prog = this.programs.get(id);
    if (!prog) throw new Error(`Program '${id}' not found.`);
    const updated = {
      ...prog,
      ...updates,
      updated_at: new Date().toISOString(),
    };
    this.programs.set(id, updated);
    return updated;
  }

  deleteProgram(id: string): boolean {
    // Also remove associated scope entries
    const entries = this.listScopeEntries(id);
    for (const entry of entries) {
      this.scopeEntries.delete(entry.id);
    }
    return this.programs.delete(id);
  }

  // --- Scope Operations ---
  createScopeEntry(data: Omit<ScopeEntry, 'id' | 'created_at' | 'updated_at'> & { id?: string }): ScopeEntry {
    const id = data.id || `scope-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const entry: ScopeEntry = {
      id,
      program_id: data.program_id,
      asset_type: data.asset_type || ScopeAssetType.REPOSITORY,
      asset_identifier: data.asset_identifier,
      inclusion_status: data.inclusion_status || ScopeInclusionStatus.IN_SCOPE,
      environment: data.environment,
      technology: data.technology,
      source_reference: data.source_reference,
      restrictions: data.restrictions || [],
      notes: data.notes,
      effective_from: data.effective_from,
      effective_to: data.effective_to,
      metadata: data.metadata || {},
      created_at: now,
      updated_at: now,
    };
    this.scopeEntries.set(id, entry);
    return entry;
  }

  getScopeEntry(id: string): ScopeEntry | undefined {
    return this.scopeEntries.get(id);
  }

  listScopeEntries(program_id?: string): ScopeEntry[] {
    let list = Array.from(this.scopeEntries.values());
    if (program_id) {
      list = list.filter(s => s.program_id === program_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  deleteScopeEntry(id: string): boolean {
    return this.scopeEntries.delete(id);
  }

  importScope(program_id: string, rawScope: any[], replaceExisting: boolean = false): ScopeEntry[] {
    const program = this.getProgram(program_id);
    if (!program) throw new Error(`Program '${program_id}' not found.`);

    if (replaceExisting) {
      const existing = this.listScopeEntries(program_id);
      for (const e of existing) {
        this.scopeEntries.delete(e.id);
      }
    }

    const adapter = globalProgramAdapterRegistry.get(program.platform);
    const normalized = adapter.normalize_scope(rawScope, program_id);
    for (const entry of normalized) {
      this.scopeEntries.set(entry.id, entry);
    }
    return normalized;
  }

  // --- Target Operations ---
  createTarget(data: Omit<Target, 'id' | 'created_at' | 'updated_at' | 'target_type'> & { id?: string; target_type?: TargetType; type?: TargetType; primary_location?: string }): Target {
    const id = data.id || `tgt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const target: Target = {
      id,
      program_id: data.program_id,
      name: data.name,
      target_type: data.target_type || data.type || TargetType.SMART_CONTRACT,
      type: data.type || data.target_type || TargetType.SMART_CONTRACT,
      ecosystem: data.ecosystem || Ecosystem.EVM,
      identifier: data.identifier || data.repository_url || data.contract_address || data.name,
      primary_location: data.primary_location,
      repository_url: data.repository_url || data.primary_location,
      commit_hash: data.commit_hash,
      branch: data.branch,
      deployment: data.deployment || data.deployment_information || {},
      deployment_information: data.deployment_information || data.deployment || {},
      chain: data.chain,
      contract_address: data.contract_address,
      source_hash: data.source_hash,
      source_acquisition_status: data.source_acquisition_status || SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED,
      authorization_status: data.authorization_status || TargetAuthorizationStatus.NOT_EVALUATED,
      scope_status: data.scope_status || TargetScopeStatus.NOT_EVALUATED,
      metadata: data.metadata || {},
      created_at: now,
      updated_at: now,
    };
    this.targets.set(id, target);

    // Record TARGET_REGISTERED event
    globalEvidenceEventManager.recordEvent({
      investigation_id: `inv-target-${id}`,
      event_type: EvidenceEventType.TARGET_REGISTERED,
      actor: 'researcher',
      producer: 'DatabaseStore',
      metadata: {
        target_id: id,
        target_name: target.name,
        target_type: target.target_type,
        ecosystem: target.ecosystem,
        program_id: target.program_id,
      },
    });

    return target;
  }

  getTarget(id: string): Target | undefined {
    return this.targets.get(id);
  }

  listTargets(program_id?: string): Target[] {
    let list = Array.from(this.targets.values());
    if (program_id) {
      list = list.filter(t => t.program_id === program_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  updateTarget(id: string, updates: Partial<Target>): Target {
    const target = this.targets.get(id);
    if (!target) throw new Error(`Target '${id}' not found.`);
    const updated = {
      ...target,
      ...updates,
      updated_at: new Date().toISOString(),
    };
    this.targets.set(id, updated);
    return updated;
  }

  updateTargetSourceStatus(id: string, status: SourceAcquisitionStatus, source_hash?: string): Target {
    const target = this.targets.get(id);
    if (!target) throw new Error(`Target ${id} not found.`);
    target.source_acquisition_status = status;
    if (source_hash) target.source_hash = source_hash;
    target.updated_at = new Date().toISOString();
    return target;
  }

  deleteTarget(id: string): boolean {
    return this.targets.delete(id);
  }

  // --- Scope Evaluation ---
  evaluateTargetScope(targetId: string, investigationRequestId?: string): ScopeDecisionResult {
    const target = this.getTarget(targetId);
    if (!target) throw new Error(`Target '${targetId}' not found.`);

    const program = this.getProgram(target.program_id);
    if (!program) throw new Error(`Program '${target.program_id}' associated with target not found.`);

    const scopeEntries = this.listScopeEntries(program.id);
    const result = ScopeDecisionService.evaluate({
      program,
      target,
      scopeEntries,
      investigationRequestId,
    });

    // Update target scope and authorization state
    if (result.decision === ScopeInclusionStatus.IN_SCOPE) {
      target.scope_status = TargetScopeStatus.IN_SCOPE;
      target.authorization_status = TargetAuthorizationStatus.AUTHORIZED;
    } else if (result.decision === ScopeInclusionStatus.OUT_OF_SCOPE) {
      target.scope_status = TargetScopeStatus.OUT_OF_SCOPE;
      target.authorization_status = TargetAuthorizationStatus.NOT_AUTHORIZED;
    } else {
      target.scope_status = TargetScopeStatus.UNKNOWN;
      target.authorization_status = TargetAuthorizationStatus.UNKNOWN;
    }
    target.updated_at = new Date().toISOString();
    this.targets.set(targetId, target);

    // Record SCOPE_EVALUATED evidence event
    globalEvidenceEventManager.recordEvent({
      investigation_id: investigationRequestId || `inv-target-${target.id}`,
      event_type: EvidenceEventType.SCOPE_EVALUATED,
      actor: 'scope-decision-engine',
      producer: 'ScopeDecisionService',
      producer_version: result.evaluator_version,
      metadata: {
        target_id: target.id,
        decision: result.decision,
        reason: result.reason,
        matched_entry_id: result.matched_scope_entry?.id,
        policy_version: result.policy_version,
      },
    });

    return result;
  }

  // --- Investigation Gate Pre-flight Check ---
  evaluateInvestigationGate(investigationId: string, options?: { requireSourceAcquisition?: boolean; strictFreshness?: boolean }): InvestigationGateResult {
    const inv = this.getInvestigation(investigationId);
    if (!inv) {
      return InvestigationGateService.evaluateGate({ program: null, target: null });
    }

    const program = this.getProgram(inv.program_id);
    const target = this.getTarget(inv.target_id);

    return InvestigationGateService.evaluateGate({
      program,
      target,
      requireSourceAcquisition: options?.requireSourceAcquisition ?? true,
      strictFreshness: options?.strictFreshness ?? true,
    });
  }

  // --- Source Acquisition with Git Provider ---
  async acquireTargetSource(
    targetId: string,
    options?: {
      branch?: string;
      commit?: string;
      timeout_ms?: number;
      investigation_id?: string;
    }
  ) {
    const target = this.getTarget(targetId);
    if (!target) throw new Error(`Target '${targetId}' not found.`);

    const result = await globalGitSourceProvider.acquire(target, options);
    if (result.success && result.snapshot) {
      this.updateTargetSourceStatus(targetId, SourceAcquisitionStatus.SOURCE_ACQUIRED, result.source_hash);
      if (result.resolved_commit_sha) {
        target.commit_hash = result.resolved_commit_sha;
      }
      target.updated_at = new Date().toISOString();
      this.targets.set(targetId, target);
    } else {
      this.updateTargetSourceStatus(targetId, SourceAcquisitionStatus.SOURCE_ACQUISITION_FAILED);
    }
    return result;
  }

  async verifyTargetSourceIntegrity(targetId: string) {
    const target = this.getTarget(targetId);
    if (!target) throw new Error(`Target '${targetId}' not found.`);

    const snapshots = this.listSourceSnapshots(targetId);
    if (snapshots.length === 0) {
      return {
        verified: false,
        computed_hash: '',
        stored_hash: '',
        expected_hash: '',
        actual_hash: '',
        error: 'No source snapshots exist for this target.',
      };
    }

    const latest = snapshots[0];
    return globalGitSourceProvider.verify_source_integrity(latest);
  }

  // --- Source Snapshot Operations ---
  createSourceSnapshot(data: {
    target_id: string;
    investigation_id?: string;
    repository_url?: string;
    commit_hash?: string;
    branch?: string;
    acquisition_method: string;
    metadata?: Record<string, any>;
  }): SourceSnapshot {
    return globalSourceSnapshotService.createPendingSnapshot(data);
  }

  async acquireSourceSnapshotContent(
    snapshotId: string,
    content: Buffer | string,
    filename?: string
  ): Promise<SourceSnapshot> {
    const snap = await globalSourceSnapshotService.acquireFromContent(snapshotId, content, filename);
    if (snap.investigation_id) {
      globalEvidenceEventManager.recordEvent({
        investigation_id: snap.investigation_id,
        event_type: EvidenceEventType.SOURCE_ACQUIRED,
        actor: 'source-acquisition-engine',
        producer: 'source-manager',
        producer_version: '1.0.0',
        metadata: {
          snapshot_id: snap.id,
          source_hash: snap.source_hash,
          commit_hash: snap.commit_hash,
        },
      });
    }
    return snap;
  }

  getSourceSnapshot(id: string): SourceSnapshot | undefined {
    return globalSourceSnapshotService.getSnapshot(id);
  }

  listSourceSnapshots(target_id?: string): SourceSnapshot[] {
    return globalSourceSnapshotService.listSnapshots(target_id);
  }

  // --- Investigation Operations ---
  createInvestigation(data: Partial<Investigation> & { target_id: string }): Investigation {
    const id = data.id || `inv-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const investigation: Investigation = {
      id,
      program_id: data.program_id || 'prog-default',
      target_id: data.target_id,
      title: data.title || data.name || 'Untitled Investigation',
      name: data.name || data.title,
      description: data.description || '',
      status: data.status || InvestigationStatus.CREATED,
      created_at: now,
      updated_at: now,
    };
    this.investigations.set(id, investigation);
    return investigation;
  }

  getInvestigation(id: string): Investigation | undefined {
    return this.investigations.get(id);
  }

  listInvestigations(filter?: { program_id?: string; target_id?: string }): Investigation[] {
    let list = Array.from(this.investigations.values());
    if (filter?.program_id) {
      list = list.filter(i => i.program_id === filter.program_id);
    }
    if (filter?.target_id) {
      list = list.filter(i => i.target_id === filter.target_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  updateInvestigationStatus(id: string, status: InvestigationStatus): Investigation {
    const inv = this.investigations.get(id);
    if (!inv) throw new Error(`Investigation ${id} not found.`);
    inv.status = status;
    inv.updated_at = new Date().toISOString();
    return inv;
  }

  deleteInvestigation(id: string): boolean {
    return this.investigations.delete(id);
  }

  // --- Evidence Artifact Operations ---
  storeEvidenceArtifact(params: {
    id?: string;
    investigation_id: string;
    target_id?: string;
    artifact_type: ArtifactType | string;
    producer: string;
    producer_version?: string;
    command?: string;
    working_directory?: string;
    source_snapshot_id?: string | null;
    target_hash?: string;
    content: string | Buffer;
    path_or_reference?: string;
    path?: string;
    mime_type?: string;
    metadata?: Record<string, any>;
    actor?: string;
    /**
     * Defaults to MACHINE_VERIFIABLE because internal callers only invoke this
     * after observing a real process. API surfaces that accept raw payloads must
     * pass CLIENT_SUPPLIED explicitly.
     */
    provenance?: ArtifactProvenance | string;
  }): EvidenceArtifact {
    const id = params.id || `art-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const producerVersion = params.producer_version || '1.0.0';
    const provenance = params.provenance || ArtifactProvenance.MACHINE_VERIFIABLE;
    
    // Write artifact to storage
    let storedPath = params.path || params.path_or_reference;
    const artType = (params.artifact_type || 'evidence').toString().toLowerCase().replace(/[^a-z0-9]/g, '_');
    const filename = `${id}_${artType}.log`;

    // Attempt immediate synchronous store to filesystem
    if (typeof (this.storage as any).storeSync === 'function') {
      try {
        const meta = (this.storage as any).storeSync(
          params.investigation_id,
          'evidence',
          filename,
          params.content,
          params.mime_type || 'text/plain'
        );
        storedPath = meta.path;
      } catch (err) {
        console.warn('Filesystem storage sync write failed, falling back:', err);
      }
    }

    if (!storedPath) {
      storedPath = `investigations/${params.investigation_id}/evidence/${filename}`;
    }

    const { artifact, rawContent } = createEvidenceArtifact({
      id,
      investigation_id: params.investigation_id,
      target_id: params.target_id,
      artifact_type: params.artifact_type,
      producer: params.producer,
      producer_version: producerVersion,
      command: params.command,
      working_directory: params.working_directory,
      source_snapshot_id: params.source_snapshot_id,
      target_hash: params.target_hash,
      content: params.content,
      path: storedPath,
      path_or_reference: storedPath,
      mime_type: params.mime_type,
      metadata: params.metadata,
    });

    // Stamp provenance so the finding state machine can distinguish genuine
    // engine-produced evidence from payloads the workbench merely hashed.
    artifact.provenance = provenance;

    this.evidence.set(id, artifact);
    this.rawArtifactStorage.set(id, rawContent);

    // Record immutable ARTIFACT_CREATED evidence event
    globalEvidenceEventManager.recordEvent({
      investigation_id: params.investigation_id,
      event_type: EvidenceEventType.ARTIFACT_CREATED,
      actor: params.actor || 'researcher',
      producer: params.producer,
      producer_version: producerVersion,
      input_artifacts: params.source_snapshot_id ? [params.source_snapshot_id] : [],
      output_artifacts: [id],
      metadata: {
        artifact_type: params.artifact_type,
        sha256: artifact.sha256,
        size_bytes: artifact.size_bytes,
        command: params.command,
      },
    });

    return artifact;
  }

  getEvidenceArtifact(id: string): EvidenceArtifact | undefined {
    return this.evidence.get(id);
  }

  getRawArtifactContent(id: string): string | Buffer | undefined {
    return this.rawArtifactStorage.get(id);
  }

  listEvidence(investigation_id?: string): EvidenceArtifact[] {
    let list = Array.from(this.evidence.values());
    if (investigation_id) {
      list = list.filter(e => e.investigation_id === investigation_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  async verifyArtifactIntegrity(artifactId: string): Promise<{
    valid: boolean;
    status: 'VALID' | 'INVALID';
    expected_sha256: string;
    actual_sha256: string;
    size_bytes: number;
    error?: string;
  }> {
    const art = this.evidence.get(artifactId);
    if (!art) {
      return {
        valid: false,
        status: 'INVALID',
        expected_sha256: '',
        actual_sha256: '',
        size_bytes: 0,
        error: `Artifact '${artifactId}' not found in registry.`,
      };
    }

    // Try verifying from filesystem storage if path exists
    if (art.path && await this.storage.exists(art.path)) {
      return this.storage.verifyIntegrity(art.path, art.sha256);
    }

    // Fall back to stored raw buffer
    const raw = this.rawArtifactStorage.get(artifactId);
    if (raw !== undefined) {
      const computedHash = computeArtifactSHA256(raw);
      const byteSize = typeof raw === 'string' ? Buffer.byteLength(raw, 'utf-8') : raw.length;
      const valid = computedHash.toLowerCase() === art.sha256.toLowerCase();
      return {
        valid,
        status: valid ? 'VALID' : 'INVALID',
        expected_sha256: art.sha256,
        actual_sha256: computedHash,
        size_bytes: byteSize,
      };
    }

    return {
      valid: false,
      status: 'INVALID',
      expected_sha256: art.sha256,
      actual_sha256: '',
      size_bytes: 0,
      error: 'Raw artifact bytes not found on disk or memory.',
    };
  }

  // --- Evidence Events Operations ---
  recordEvidenceEvent(params: {
    investigation_id: string;
    event_type: EvidenceEventType | string;
    actor?: string;
    producer: string;
    producer_version?: string;
    input_artifacts?: string[];
    output_artifacts?: string[];
    metadata?: Record<string, any>;
  }): EvidenceEvent {
    return globalEvidenceEventManager.recordEvent(params);
  }

  listEvidenceEvents(investigation_id?: string): EvidenceEvent[] {
    return globalEvidenceEventManager.listEvents(investigation_id);
  }

  // --- Provenance Operations ---
  getInvestigationProvenance(investigation_id: string, jobs: AnalysisJob[] = []): ProvenanceGraph {
    const inv = this.getInvestigation(investigation_id);
    if (!inv) throw new Error(`Investigation '${investigation_id}' not found.`);

    const target = this.getTarget(inv.target_id);
    const sourceSnapshots = this.listSourceSnapshots(inv.target_id);
    const events = this.listEvidenceEvents(investigation_id);
    const artifacts = this.listEvidence(investigation_id);
    const findings = this.listFindings(investigation_id);

    return globalProvenanceService.buildGraph({
      investigation: inv,
      target,
      sourceSnapshots,
      jobs,
      events,
      artifacts,
      findings,
    });
  }

  getFindingProvenance(finding_id: string, jobs: AnalysisJob[] = []): ProvenanceChain {
    const finding = this.getFinding(finding_id);
    if (!finding) throw new Error(`Finding '${finding_id}' not found.`);

    const inv = this.getInvestigation(finding.investigation_id);
    if (!inv) throw new Error(`Investigation '${finding.investigation_id}' not found.`);

    const target = this.getTarget(finding.target_id || inv.target_id);
    const sourceSnapshots = this.listSourceSnapshots(target?.id);
    const events = this.listEvidenceEvents(inv.id);
    const artifacts = this.listEvidence(inv.id);
    const findings = this.listFindings(inv.id);

    return globalProvenanceService.explainFindingProvenance(finding_id, {
      investigation: inv,
      target,
      sourceSnapshots,
      jobs,
      events,
      artifacts,
      findings,
    });
  }

  // --- Finding Operations ---
  createFinding(data: {
    investigation_id: string;
    target_id?: string;
    title: string;
    category?: string;
    rule_id?: string;
    description?: string;
    location?: any;
    severity: Severity;
    confidence?: Confidence;
    evidence_artifact_ids?: string[];
    reproduction_steps?: string;
    mitigation_notes?: string;
    metadata?: Record<string, any>;
  }): Finding {
    const id = `fnd-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = new Date().toISOString();
    const resolvedTargetId = data.target_id || this.investigations.get(data.investigation_id)?.target_id || '';
    
    // Initial state is ALWAYS Candidate - never pre-confirmed
    const finding: Finding = {
      id,
      investigation_id: data.investigation_id,
      target_id: resolvedTargetId,
      title: data.title,
      category: data.category || data.rule_id || 'ACCESS_CONTROL',
      severity: data.severity,
      status: FindingStatus.CANDIDATE,
      confidence: data.confidence || Confidence.UNVERIFIED,
      evidence_artifact_ids: data.evidence_artifact_ids || [],
      reproduction_steps: data.reproduction_steps || data.description || '',
      mitigation_notes: data.mitigation_notes || '',
      metadata: {
        ...(data.metadata || {}),
        ...(data.rule_id ? { rule_id: data.rule_id } : {}),
        ...(data.description ? { description: data.description } : {}),
        ...(data.location ? { location: data.location } : {}),
      },
      state_history: [
        {
          from_status: null,
          to_status: FindingStatus.CANDIDATE,
          timestamp: now,
          reason: 'Initial candidate registration',
          actor: 'researcher',
        },
      ],
      created_at: now,
      updated_at: now,
    };

    this.findings.set(id, finding);
    return finding;
  }

  transitionFinding(id: string, targetStatus: FindingStatus, reason: string, actor: string = 'researcher'): Finding {
    const finding = this.findings.get(id);
    if (!finding) throw new Error(`Finding ${id} not found.`);

    const linked = (finding.evidence_artifact_ids || [])
      .map(eid => this.evidence.get(eid))
      .filter((a): a is EvidenceArtifact => Boolean(a));

    const hasArtifacts = linked.length > 0;
    // Only artifacts produced by a real engine execution or an internal
    // subsystem count as machine-verifiable. Caller-supplied payloads that the
    // workbench merely hashed must not satisfy the terminal gate.
    const hasMachineVerifiableEvidence =
      hasArtifacts &&
      linked.some(a => (a.provenance || ArtifactProvenance.MACHINE_VERIFIABLE) === ArtifactProvenance.MACHINE_VERIFIABLE);

    const validation = validateFindingTransition(
      finding.status,
      targetStatus,
      hasArtifacts,
      hasMachineVerifiableEvidence
    );

    if (!validation.allowed) {
      throw new Error(`State machine error: ${validation.reason}`);
    }

    const now = new Date().toISOString();
    finding.state_history.push({
      from_status: finding.status,
      to_status: targetStatus,
      timestamp: now,
      reason,
      actor,
    });
    finding.status = targetStatus;
    finding.updated_at = now;

    return finding;
  }

  linkEvidenceToFinding(finding_id: string, evidence_id: string): Finding {
    const finding = this.findings.get(finding_id);
    if (!finding) throw new Error(`Finding ${finding_id} not found.`);
    if (!this.evidence.has(evidence_id)) throw new Error(`Evidence artifact ${evidence_id} not found.`);

    if (!finding.evidence_artifact_ids.includes(evidence_id)) {
      finding.evidence_artifact_ids.push(evidence_id);
      finding.updated_at = new Date().toISOString();
    }
    return finding;
  }

  getFinding(id: string): Finding | undefined {
    return this.findings.get(id);
  }

  saveFinding(finding: Finding): Finding {
    finding.updated_at = new Date().toISOString();
    this.findings.set(finding.id, finding);
    return finding;
  }

  listFindings(investigation_id?: string): Finding[] {
    let list = Array.from(this.findings.values());
    if (investigation_id) {
      list = list.filter(f => f.investigation_id === investigation_id);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  // --- Phase 3 API Contract & Authorization Candidate Operations ---

  saveApiContract(contract: APIContract): APIContract {
    this.apiContracts.set(contract.id, contract);
    return contract;
  }

  getApiContract(id: string): APIContract | undefined {
    return this.apiContracts.get(id);
  }

  getApiContractsByInvestigation(investigationId: string): APIContract[] {
    return Array.from(this.apiContracts.values())
      .filter((c) => c.investigation_id === investigationId)
      .sort((a, b) => new Date(b.retrieved_at).getTime() - new Date(a.retrieved_at).getTime());
  }

  getEndpointsByContractId(contractId: string): APIEndpoint[] {
    const contract = this.apiContracts.get(contractId);
    return contract ? contract.endpoints : [];
  }

  saveAuthorizationCandidate(candidate: AuthorizationCandidate): AuthorizationCandidate {
    this.authorizationCandidates.set(candidate.id, candidate);
    return candidate;
  }

  getAuthorizationCandidate(id: string): AuthorizationCandidate | undefined {
    return this.authorizationCandidates.get(id);
  }

  getAuthorizationCandidatesByInvestigation(investigationId: string): AuthorizationCandidate[] {
    return Array.from(this.authorizationCandidates.values())
      .filter((c) => c.investigation_id === investigationId)
      .sort((a, b) => b.priority_score - a.priority_score);
  }

  saveContractDiff(diff: ContractDiffResult): ContractDiffResult {
    this.contractDiffs.set(diff.id, diff);
    return diff;
  }

  getContractDiffByInvestigation(investigationId: string): ContractDiffResult | undefined {
    const list = Array.from(this.contractDiffs.values())
      .filter((d) => d.investigation_id === investigationId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return list[0];
  }

  saveEvidence(evidence: EvidenceArtifact): EvidenceArtifact {
    this.evidence.set(evidence.id, evidence);
    // Artifacts built outside storeEvidenceArtifact (formal/dynamic verification)
    // already registered their real bytes globally; mirror them into the local
    // raw store so integrity verification and download return genuine content
    // instead of an INVALID empty payload.
    const registered = registeredEvidenceArtifacts.get(evidence.id);
    if (registered && !this.rawArtifactStorage.has(evidence.id)) {
      this.rawArtifactStorage.set(evidence.id, registered.content);
    }
    return evidence;
  }

  getEvidence(id: string): EvidenceArtifact | undefined {
    return this.evidence.get(id);
  }

  saveVerificationResult(result: VerificationResult): VerificationResult {
    this.verificationResults.set(result.id, result);
    return result;
  }

  getVerificationResult(id: string): VerificationResult | undefined {
    return this.verificationResults.get(id);
  }

  getVerificationResultsByInvestigation(investigationId: string): VerificationResult[] {
    return Array.from(this.verificationResults.values())
      .filter((r) => r.investigation_id === investigationId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  getAllVerificationResults(): VerificationResult[] {
    return Array.from(this.verificationResults.values())
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  saveDynamicVerificationJob(job: DynamicVerificationJob): DynamicVerificationJob {
    this.dynamicVerificationJobs.set(job.id, job);
    return job;
  }

  getDynamicVerificationJob(id: string): DynamicVerificationJob | undefined {
    return this.dynamicVerificationJobs.get(id);
  }

  listDynamicVerificationJobs(investigationId?: string): DynamicVerificationJob[] {
    let list = Array.from(this.dynamicVerificationJobs.values());
    if (investigationId) {
      list = list.filter((j) => j.investigation_id === investigationId);
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  deleteDynamicVerificationJob(id: string): boolean {
    return this.dynamicVerificationJobs.delete(id);
  }
}

export const globalDB = new DatabaseStore();
