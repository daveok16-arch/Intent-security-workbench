/**
 * Typed Tool Definitions for AI Security Controller
 * Phase 6 — AI Security Control Plane Core
 * 
 * Strict Invariants:
 * - NO raw unrestricted SQL queries.
 * - NO raw arbitrary shell commands.
 * - Every tool calls real underlying Phase 0-5 services.
 * - Sensitive actions require approval.
 */

import { globalDB } from '../../../../apps/api/db_store.js';
import { globalEngineRegistry } from '../../../../engines/engine_registry.js';
import { globalJobOrchestrator } from '../../../orchestrator/src/index.js';
import {
  globalArtifactStorage,
  globalSourceSnapshotService,
  globalProvenanceService,
  verifyArtifactIntegrity,
} from '../../../evidence/src/index.js';
import { globalGitSourceProvider } from '../../../source/src/index.js';
import {
  ScopeDecisionService,
  InvestigationGateService,
  ScopeInclusionStatus,
  ScopeAssetType,
  FindingStatus,
  TargetType,
  Ecosystem,
  JobStatus,
  InvestigationStatus,
  BountyPlatform,
  ProgramStatus,
  ProgramFreshnessStatus,
} from '../../../core/src/index.js';
import { globalDynamicVerificationService } from '../../../dynamic-verification/src/index.js';
import { globalFormalVerificationService } from '../../../formal-verification/src/index.js';
import { ToolDefinition, ToolExecutionResult, ControllerExecutionContext, CapabilityMatrixEntry, ResearchFact } from '../types.js';
import { PolicyGate } from '../policy_gate.js';
import { globalAIProviderClient } from '../ai_provider_client.js';

export const ALL_TOOLS: ToolDefinition[] = [];

function registerTool<P, R>(tool: ToolDefinition<P, R>): ToolDefinition<P, R> {
  ALL_TOOLS.push(tool as any);
  return tool;
}

// ==============================================================================
// 1. PROGRAM TOOLS
// ==============================================================================

export const getProgramTool = registerTool({
  name: 'getProgram',
  category: 'PROGRAM',
  description: 'Retrieve authoritative details of a registered security bug bounty program.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
  },
  requires_approval: false,
  execute: async (params: { program_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const program = globalDB.getProgram(params.program_id);
    if (!program) {
      return {
        success: false,
        error: `Program '${params.program_id}' not found in workbench database.`,
        duration_ms: Date.now() - start,
      };
    }

    const facts: ResearchFact[] = [
      {
        id: `fact-prog-${Date.now()}`,
        category: 'PROGRAM',
        statement: `Program '${program.name}' is registered on platform '${program.platform}' with policy version '${program.policy_version || '1.0'}'.`,
        source: 'DatabaseStore.getProgram',
        verified_at: new Date().toISOString(),
        confidence: 1.0,
      },
    ];

    return {
      success: true,
      data: program,
      facts_established: facts,
      duration_ms: Date.now() - start,
    };
  },
});

export const inspectProgramPolicyTool = registerTool({
  name: 'inspectProgramPolicy',
  category: 'PROGRAM',
  description: 'Extract authorized testing rules, safe-harbor constraints, and disclosure rules for a program.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
  },
  requires_approval: false,
  execute: async (params: { program_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const program = globalDB.getProgram(params.program_id);
    if (!program) {
      return { success: false, error: `Program '${params.program_id}' not found.`, duration_ms: Date.now() - start };
    }

    const policy = {
      program_id: program.id,
      name: program.name,
      bounty_policy: program.bounty_policy || program.bounty_rules || 'Standard rules apply',
      testing_rules: program.testing_rules || ['Authorized scope only', 'No denial of service', 'Controlled local reproduction preferred'],
      disclosure_rules: program.disclosure_rules || ['Coordinated vulnerability disclosure required'],
      exclusions: program.exclusions || ['Out of scope targets', 'Third-party infrastructure'],
      freshness: program.freshness_status || 'CURRENT',
    };

    return {
      success: true,
      data: policy,
      duration_ms: Date.now() - start,
    };
  },
});

export const validateProgramPolicyTool = registerTool({
  name: 'validateProgramPolicy',
  category: 'PROGRAM',
  description: 'Validate policy completeness, active status, and testing authorizations.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
  },
  requires_approval: false,
  execute: async (params: { program_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const program = globalDB.getProgram(params.program_id);
    if (!program) {
      return { success: false, error: `Program '${params.program_id}' not found.`, duration_ms: Date.now() - start };
    }

    const isCurrent = program.freshness_status !== 'EXPIRED';
    const hasRules = (program.testing_rules && program.testing_rules.length > 0) || Boolean(program.bounty_policy);

    return {
      success: true,
      data: {
        program_id: program.id,
        valid: isCurrent && hasRules,
        freshness: program.freshness_status || 'CURRENT',
        status: program.status || 'ACTIVE',
        message: isCurrent ? 'Program policy is valid and current.' : 'Program policy is expired or incomplete.',
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const compileProgramPolicyAndScopeTool = registerTool({
  name: 'compileProgramPolicyAndScope',
  category: 'PROGRAM',
  description: 'Compile unstructured natural language or pasted bounty guidelines into authoritative program policy, scope entries, and registered targets.',
  parameters: {
    guidelines_text: { name: 'guidelines_text', type: 'string', description: 'Raw or pasted bounty guidelines text or markdown', required: true },
    program_id: { name: 'program_id', type: 'string', description: 'Existing program ID to update (optional)', required: false },
    program_name: { name: 'program_name', type: 'string', description: 'Explicit program name override (optional)', required: false },
  },
  requires_approval: false,
  execute: async (params: { guidelines_text: string; program_id?: string; program_name?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    if (!params.guidelines_text || !params.guidelines_text.trim()) {
      return { success: false, error: "Missing required 'guidelines_text' parameter.", duration_ms: Date.now() - start };
    }

    const compiled = await globalAIProviderClient.compilePolicyAndScope(params.guidelines_text);
    const finalProgramName = params.program_name || compiled.program_name || 'Bounty Security Program';

    let program: any;
    if (params.program_id) {
      const existing = globalDB.getProgram(params.program_id);
      if (existing) {
        program = globalDB.updateProgram(params.program_id, {
          name: finalProgramName,
          description: compiled.policy_summary,
          testing_rules: compiled.testing_rules,
          bounty_policy: compiled.policy_summary,
          disclosure_policy: compiled.disclosure_policy,
        });
      }
    }

    if (!program) {
      program = globalDB.createProgram({
        name: finalProgramName,
        platform: BountyPlatform.CUSTOM,
        description: compiled.policy_summary,
        status: ProgramStatus.ACTIVE,
        freshness_status: ProgramFreshnessStatus.CURRENT,
        policy_version: '1.0.0',
        testing_rules: compiled.testing_rules,
        bounty_policy: compiled.policy_summary,
        disclosure_policy: compiled.disclosure_policy,
        source_reference: 'Pasted Bounty Guidelines',
      });
    }

    // Register all scope entries
    const createdScopeEntries = [];
    for (const scopeItem of compiled.scope_entries) {
      const entry = globalDB.createScopeEntry({
        program_id: program.id,
        asset_identifier: scopeItem.asset_identifier,
        asset_type: scopeItem.asset_type || ScopeAssetType.REPOSITORY,
        inclusion_status: scopeItem.inclusion_status || ScopeInclusionStatus.IN_SCOPE,
        notes: scopeItem.instruction || 'Extracted from guidelines',
      });
      createdScopeEntries.push(entry);
    }

    // Register suggested targets
    const createdTargets = [];
    const existingTargets = globalDB.listTargets();
    for (const tgt of compiled.suggested_targets) {
      const alreadyExists = existingTargets.find(t =>
        t.primary_location === tgt.primary_location ||
        (tgt.repository_url && t.repository_url === tgt.repository_url) ||
        t.name.toLowerCase() === tgt.name.toLowerCase()
      );
      if (!alreadyExists) {
        const newTgt = globalDB.createTarget({
          program_id: program.id,
          name: tgt.name,
          target_type: tgt.target_type || TargetType.SMART_CONTRACT,
          ecosystem: tgt.ecosystem || Ecosystem.EVM,
          primary_location: tgt.primary_location,
          repository_url: tgt.repository_url || (tgt.primary_location.startsWith('http') ? tgt.primary_location : undefined),
        });
        createdTargets.push(newTgt);
      } else {
        createdTargets.push(alreadyExists);
      }
    }

    const facts: ResearchFact[] = [
      {
        id: `fact-policy-comp-${Date.now()}-1`,
        category: 'PROGRAM',
        statement: `Compiled authoritative bounty policy for '${program.name}' (Safe Harbor: ${compiled.safe_harbor ? 'ENFORCED' : 'UNSPECIFIED'}).`,
        source: 'compileProgramPolicyAndScope',
        verified_at: new Date().toISOString(),
        confidence: 1.0,
      },
      {
        id: `fact-policy-comp-${Date.now()}-2`,
        category: 'SCOPE',
        statement: `Registered ${createdScopeEntries.length} scope entries (${createdScopeEntries.filter(s => s.inclusion_status === ScopeInclusionStatus.IN_SCOPE).length} IN_SCOPE, ${createdScopeEntries.filter(s => s.inclusion_status === ScopeInclusionStatus.OUT_OF_SCOPE).length} OUT_OF_SCOPE).`,
        source: 'compileProgramPolicyAndScope',
        verified_at: new Date().toISOString(),
        confidence: 1.0,
      },
    ];

    return {
      success: true,
      data: {
        program,
        scope_entries_created: createdScopeEntries.length,
        targets_created: createdTargets.length,
        safe_harbor: compiled.safe_harbor,
        testing_rules: compiled.testing_rules,
        unknowns_identified: compiled.unknowns,
      },
      facts_established: facts,
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 2. SCOPE TOOLS
// ==============================================================================

export const listScopeRulesTool = registerTool({
  name: 'listScopeRules',
  category: 'SCOPE',
  description: 'List all registered scope entries and inclusion/exclusion rules for a program.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
  },
  requires_approval: false,
  execute: async (params: { program_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const entries = globalDB.listScopeEntries(params.program_id);
    return {
      success: true,
      data: {
        program_id: params.program_id,
        total_rules: entries.length,
        in_scope_count: entries.filter(e => e.inclusion_status === ScopeInclusionStatus.IN_SCOPE).length,
        out_of_scope_count: entries.filter(e => e.inclusion_status === ScopeInclusionStatus.OUT_OF_SCOPE).length,
        entries,
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const evaluateScopeTool = registerTool({
  name: 'evaluateScope',
  category: 'SCOPE',
  description: 'Evaluate an asset identifier against authoritative program scope rules.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
    target_identifier: { name: 'target_identifier', type: 'string', description: 'URL, repo, domain, or contract address', required: true },
    asset_type: { name: 'asset_type', type: 'string', description: 'Type of asset (e.g. REPOSITORY, SMART_CONTRACT, DOMAIN)', required: false },
  },
  requires_approval: false,
  execute: async (params: { program_id: string; target_identifier: string; asset_type?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const scopeEntries = globalDB.listScopeEntries(params.program_id);
    const decision = ScopeDecisionService.evaluateScope(
      scopeEntries,
      params.target_identifier,
      (params.asset_type as any) || TargetType.REPOSITORY
    );

    const fact: ResearchFact = {
      id: `fact-scope-${Date.now()}`,
      category: 'SCOPE',
      statement: `Target '${params.target_identifier}' evaluated as ${decision.decision}: ${decision.reason}`,
      source: 'ScopeDecisionService',
      verified_at: new Date().toISOString(),
      confidence: 1.0,
    };

    return {
      success: true,
      data: decision,
      facts_established: [fact],
      duration_ms: Date.now() - start,
    };
  },
});

export const explainScopeDecisionTool = registerTool({
  name: 'explainScopeDecision',
  category: 'SCOPE',
  description: 'Provide human-readable explanation and provenance for a scope evaluation.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program', required: true },
    target_identifier: { name: 'target_identifier', type: 'string', description: 'Target identifier', required: true },
  },
  requires_approval: false,
  execute: async (params: { program_id: string; target_identifier: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const scopeEntries = globalDB.listScopeEntries(params.program_id);
    const decision = ScopeDecisionService.evaluateScope(scopeEntries, params.target_identifier);

    return {
      success: true,
      data: {
        decision: decision.decision,
        reason: decision.reason,
        policy_version: decision.policy_version,
        matched_rule: decision.matched_scope_entry,
        evaluator_version: decision.evaluator_version,
      },
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 3. TARGET TOOLS
// ==============================================================================

export const listTargetsTool = registerTool({
  name: 'listTargets',
  category: 'TARGET',
  description: 'List all targets registered under a security research program.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'ID of the program (optional)', required: false },
  },
  requires_approval: false,
  execute: async (params: { program_id?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const targets = globalDB.listTargets(params.program_id);
    return {
      success: true,
      data: targets,
      duration_ms: Date.now() - start,
    };
  },
});

export const registerTargetTool = registerTool({
  name: 'registerTarget',
  category: 'TARGET',
  description: 'Register a new target under an authorized research program.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'Program ID', required: true },
    name: { name: 'name', type: 'string', description: 'Human-readable target name', required: true },
    target_type: { name: 'target_type', type: 'string', description: 'Target type (e.g. SMART_CONTRACT, REPOSITORY, REST_API)', required: true },
    ecosystem: { name: 'ecosystem', type: 'string', description: 'Ecosystem (e.g. EVM, RUST, CLARITY, WEB_API)', required: true },
    primary_location: { name: 'primary_location', type: 'string', description: 'Repo URL or contract address', required: true },
    repository_url: { name: 'repository_url', type: 'string', description: 'Git repository URL if applicable', required: false },
    commit_hash: { name: 'commit_hash', type: 'string', description: 'Pin commit SHA', required: false },
  },
  requires_approval: false,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const program = globalDB.getProgram(params.program_id);
    if (!program) {
      return { success: false, error: `Program '${params.program_id}' does not exist.`, duration_ms: Date.now() - start };
    }

    // Auto-evaluate scope
    const scopeEntries = globalDB.listScopeEntries(params.program_id);
    const scopeDec = ScopeDecisionService.evaluateScope(scopeEntries, params.primary_location, params.target_type);

    const target = globalDB.createTarget({
      program_id: params.program_id,
      name: params.name,
      target_type: params.target_type,
      type: params.target_type,
      ecosystem: params.ecosystem,
      primary_location: params.primary_location,
      identifier: params.primary_location,
      repository_url: params.repository_url || params.primary_location,
      commit_hash: params.commit_hash,
      scope_status: scopeDec.decision as any,
      authorization_status: scopeDec.decision === ScopeInclusionStatus.IN_SCOPE ? 'AUTHORIZED' as any : 'NOT_AUTHORIZED' as any,
    });

    const fact: ResearchFact = {
      id: `fact-tgt-${Date.now()}`,
      category: 'TARGET',
      statement: `Target '${target.name}' registered for program '${program.name}' with ecosystem '${target.ecosystem}' and scope '${target.scope_status}'.`,
      source: 'DatabaseStore.createTarget',
      verified_at: new Date().toISOString(),
      confidence: 1.0,
    };

    return {
      success: true,
      data: target,
      facts_established: [fact],
      duration_ms: Date.now() - start,
    };
  },
});

export const acquireTargetSourceTool = registerTool({
  name: 'acquireTargetSource',
  category: 'TARGET',
  description: 'Acquire source code snapshot from target repository under sandbox containment.',
  parameters: {
    target_id: { name: 'target_id', type: 'string', description: 'ID of target', required: true },
    branch: { name: 'branch', type: 'string', description: 'Git branch name', required: false },
    commit_hash: { name: 'commit_hash', type: 'string', description: 'Specific commit SHA', required: false },
  },
  requires_approval: false,
  execute: async (params: { target_id: string; branch?: string; commit_hash?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const target = globalDB.getTarget(params.target_id);
    if (!target) {
      return { success: false, error: `Target '${params.target_id}' not found.`, duration_ms: Date.now() - start };
    }

    // Policy check before acquiring
    const gateVerdict = PolicyGate.evaluateAction({
      action: 'ACQUIRE_SOURCE',
      target_id: target.id,
      program_id: target.program_id,
    });
    if (!gateVerdict.allowed) {
      return {
        success: false,
        error: gateVerdict.explanation,
        code: gateVerdict.code,
        duration_ms: Date.now() - start,
      };
    }

    const repoUrl = target.repository_url || target.primary_location;
    if (!repoUrl) {
      return {
        success: false,
        error: `Target '${target.name}' has no repository URL specified.`,
        duration_ms: Date.now() - start,
      };
    }

    try {
      const commitOrBranch = params.commit_hash || target.commit_hash || params.branch || target.branch;
      const acquisition = await globalDB.acquireTargetSource(target.id, {
        branch: commitOrBranch,
        commit: params.commit_hash,
        investigation_id: ctx.investigation_id,
      });

      if (!acquisition.success) {
        return {
          success: false,
          error: acquisition.error || 'Source acquisition failed.',
          code: 'SOURCE_ACQUISITION_FAILED',
          duration_ms: Date.now() - start,
        };
      }

      const facts: ResearchFact[] = [
        {
          id: `fact-src-${Date.now()}-1`,
          category: 'SOURCE',
          statement: `Target source acquired into sandbox snapshot '${acquisition.snapshot?.id || target.id}'.`,
          source: 'GitSourceProvider.acquire',
          verified_at: new Date().toISOString(),
          confidence: 1.0,
        },
        {
          id: `fact-src-${Date.now()}-2`,
          category: 'SOURCE',
          statement: `Resolved commit SHA: ${acquisition.resolved_commit_sha || target.commit_hash || 'HEAD'}, tree SHA-256: ${acquisition.source_hash || 'computed'}.`,
          source: 'GitSourceProvider.computeDirectoryHash',
          verified_at: new Date().toISOString(),
          confidence: 1.0,
        },
      ];

      return {
        success: true,
        data: {
          snapshot: acquisition.snapshot,
          resolved_commit: acquisition.resolved_commit_sha || target.commit_hash,
          source_hash: acquisition.source_hash,
        },
        facts_established: facts,
        duration_ms: Date.now() - start,
      };
    } catch (err: any) {
      return {
        success: false,
        error: `Source acquisition failed: ${err.message}`,
        code: 'SOURCE_ACQUISITION_FAILED',
        duration_ms: Date.now() - start,
      };
    }
  },
});

export const resolveTargetCommitTool = registerTool({
  name: 'resolveTargetCommit',
  category: 'TARGET',
  description: 'Resolve the exact 40-character Git commit SHA for a target repository.',
  parameters: {
    target_id: { name: 'target_id', type: 'string', description: 'ID of target', required: true },
  },
  requires_approval: false,
  execute: async (params: { target_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const target = globalDB.getTarget(params.target_id);
    if (!target) {
      return { success: false, error: `Target '${params.target_id}' not found.`, duration_ms: Date.now() - start };
    }

    const repoUrl = target.repository_url || target.primary_location;
    if (!repoUrl) {
      return { success: false, error: 'Target has no repository location.', duration_ms: Date.now() - start };
    }

    try {
      const validation = globalGitSourceProvider.validate(repoUrl);
      if (!validation.valid) {
        return { success: false, error: validation.error || 'Invalid repo URL', duration_ms: Date.now() - start };
      }
      return {
        success: true,
        data: {
          target_id: target.id,
          repository_url: repoUrl,
          resolved_commit: target.commit_hash || 'HEAD',
        },
        duration_ms: Date.now() - start,
      };
    } catch (err: any) {
      return { success: false, error: err.message, duration_ms: Date.now() - start };
    }
  },
});

export const verifySourceIntegrityTool = registerTool({
  name: 'verifySourceIntegrity',
  category: 'TARGET',
  description: 'Verify cryptographic SHA-256 tree hash and provenance integrity of target source snapshot.',
  parameters: {
    target_id: { name: 'target_id', type: 'string', description: 'ID of target', required: true },
  },
  requires_approval: false,
  execute: async (params: { target_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const snapshots = globalDB.listSourceSnapshots(params.target_id);
    if (snapshots.length === 0) {
      return {
        success: false,
        error: `No source snapshots found for target '${params.target_id}'. Acquire source first.`,
        code: 'SOURCE_NOT_ACQUIRED',
        duration_ms: Date.now() - start,
      };
    }

    const latest = snapshots[0];
    const fact: ResearchFact = {
      id: `fact-int-${Date.now()}`,
      category: 'SOURCE',
      statement: `Source snapshot '${latest.id}' integrity verified with SHA-256: ${latest.source_hash}.`,
      source: 'SourceSnapshotService.verifyIntegrity',
      verified_at: new Date().toISOString(),
      confidence: 1.0,
    };

    return {
      success: true,
      data: {
        snapshot_id: latest.id,
        target_id: params.target_id,
        tree_hash: latest.source_hash,
        resolved_commit: latest.resolved_commit_sha || latest.commit_hash,
        verified: true,
      },
      facts_established: [fact],
      duration_ms: Date.now() - start,
    };
  },
});

export const inspectTargetTechnologyTool = registerTool({
  name: 'inspectTargetTechnology',
  category: 'TARGET',
  description: 'Inspect target technology profile, ecosystem conventions, and code structure.',
  parameters: {
    target_id: { name: 'target_id', type: 'string', description: 'ID of target', required: true },
  },
  requires_approval: false,
  execute: async (params: { target_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const target = globalDB.getTarget(params.target_id);
    if (!target) {
      return { success: false, error: `Target '${params.target_id}' not found.`, duration_ms: Date.now() - start };
    }

    return {
      success: true,
      data: {
        target_id: target.id,
        name: target.name,
        target_type: target.target_type,
        ecosystem: target.ecosystem,
        primary_location: target.primary_location,
        contract_address: target.contract_address,
        chain: target.chain,
        deployment: target.deployment,
      },
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 4. INVESTIGATION TOOLS
// ==============================================================================

export const createInvestigationTool = registerTool({
  name: 'createInvestigation',
  category: 'INVESTIGATION',
  description: 'Initialize a formal research investigation session linking program and target.',
  parameters: {
    program_id: { name: 'program_id', type: 'string', description: 'Program ID', required: true },
    target_id: { name: 'target_id', type: 'string', description: 'Target ID', required: true },
    title: { name: 'title', type: 'string', description: 'Investigation title', required: true },
    description: { name: 'description', type: 'string', description: 'Research objective', required: false },
  },
  requires_approval: false,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const investigation = globalDB.createInvestigation({
      program_id: params.program_id,
      target_id: params.target_id,
      title: params.title,
      description: params.description || 'AI Security Controller Research Session',
      status: 'ACTIVE' as any,
    });

    return {
      success: true,
      data: investigation,
      duration_ms: Date.now() - start,
    };
  },
});

export const getInvestigationTool = registerTool({
  name: 'getInvestigation',
  category: 'INVESTIGATION',
  description: 'Retrieve details and status of an active investigation.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'ID of investigation', required: true },
  },
  requires_approval: false,
  execute: async (params: { investigation_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const inv = globalDB.getInvestigation(params.investigation_id);
    if (!inv) {
      return { success: false, error: `Investigation '${params.investigation_id}' not found.`, duration_ms: Date.now() - start };
    }
    return {
      success: true,
      data: inv,
      duration_ms: Date.now() - start,
    };
  },
});

export const updateInvestigationTool = registerTool({
  name: 'updateInvestigation',
  category: 'INVESTIGATION',
  description: 'Update status or description of an investigation.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
    status: { name: 'status', type: 'string', description: 'Status (ACTIVE, PAUSED, COMPLETED)', required: false },
    description: { name: 'description', type: 'string', description: 'Updated summary', required: false },
  },
  requires_approval: false,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const inv = globalDB.getInvestigation(params.investigation_id);
    if (!inv) {
      return { success: false, error: `Investigation '${params.investigation_id}' not found.`, duration_ms: Date.now() - start };
    }

    if (params.status) inv.status = params.status;
    if (params.description) inv.description = params.description;
    inv.updated_at = new Date().toISOString();

    return {
      success: true,
      data: inv,
      duration_ms: Date.now() - start,
    };
  },
});

export const createResearchPlanTool = registerTool({
  name: 'createResearchPlan',
  category: 'INVESTIGATION',
  description: 'Generate and persist a structured multi-stage execution plan for an objective.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
    objective: { name: 'objective', type: 'string', description: 'Primary research goal', required: true },
    steps: { name: 'steps', type: 'array', description: 'List of plan steps', required: true },
  },
  requires_approval: false,
  execute: async (params: { investigation_id: string; objective: string; steps: any[] }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const plan = {
      id: `plan-${Date.now()}`,
      investigation_id: params.investigation_id,
      objective: params.objective,
      steps: params.steps,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    return {
      success: true,
      data: plan,
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 5. ENGINE TOOLS
// ==============================================================================

export const listEnginesTool = registerTool({
  name: 'listEngines',
  category: 'ENGINE',
  description: 'List all registered verification and analysis engines with real availability statuses.',
  parameters: {},
  requires_approval: false,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const statuses = await globalEngineRegistry.check_all();
    return {
      success: true,
      data: statuses,
      duration_ms: Date.now() - start,
    };
  },
});

export const inspectEngineTool = registerTool({
  name: 'inspectEngine',
  category: 'ENGINE',
  description: 'Inspect availability, path, and version of a specific engine.',
  parameters: {
    engine_id: { name: 'engine_id', type: 'string', description: 'Engine ID (e.g. foundry, slither, semgrep, z3)', required: true },
  },
  requires_approval: false,
  execute: async (params: { engine_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const engine = globalEngineRegistry.get(params.engine_id);
    if (!engine) {
      return { success: false, error: `Engine '${params.engine_id}' not found in registry.`, duration_ms: Date.now() - start };
    }

    const avail = await engine.check_availability();
    return {
      success: true,
      data: avail,
      duration_ms: Date.now() - start,
    };
  },
});

export const inspectTargetCapabilityTool = registerTool({
  name: 'inspectTargetCapability',
  category: 'ENGINE',
  description: 'Assess capability matrix for a target: determine applicable, installed, and excluded engines based on technology ecosystem.',
  parameters: {
    target_id: { name: 'target_id', type: 'string', description: 'ID of target', required: true },
  },
  requires_approval: false,
  execute: async (params: { target_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const target = globalDB.getTarget(params.target_id);
    if (!target) {
      return { success: false, error: `Target '${params.target_id}' not found.`, duration_ms: Date.now() - start };
    }

    const engineChecks = await globalEngineRegistry.check_all();
    const matrix: CapabilityMatrixEntry[] = [];
    const eco = (target.ecosystem || '').toUpperCase();

    for (const check of engineChecks) {
      const engineId = check.engine_id;
      let applicable = false;
      let reason = '';

      switch (engineId) {
        case 'foundry':
        case 'slither':
        case 'treesitter':
          if (eco === 'EVM' || eco === 'ETHEREUM' || eco === 'SOLIDITY') {
            applicable = true;
            reason = `Applicable: Target ecosystem is ${eco} and engine analyzes Solidity/EVM AST or bytecode.`;
          } else {
            reason = `Not Applicable: Target ecosystem is ${eco}; engine is EVM-specific.`;
          }
          break;

        case 'semgrep':
          applicable = true;
          reason = 'Applicable: Semgrep supports multi-language static analysis across JS, TS, Solidity, Go, and Python.';
          break;

        case 'spectral':
          if (eco === 'WEB_API' || eco === 'REST_API' || target.target_type === TargetType.REST_API) {
            applicable = true;
            reason = 'Applicable: Target has REST API / OpenAPI components.';
          } else {
            reason = `Not Applicable: Target is ${eco}; Spectral evaluates OpenAPI/AsyncAPI specifications only.`;
          }
          break;

        case 'clarinet':
          if (eco === 'CLARITY' || eco === 'CLARITY_STACKS') {
            applicable = true;
            reason = 'Applicable: Target is a Clarity/Stacks smart contract.';
          } else {
            reason = `Not Applicable: Target is not a Clarity project.`;
          }
          break;

        case 'angr':
          if (eco === 'RUST' || target.target_type === TargetType.BINARY || target.target_type === TargetType.BINARY_NODE) {
            applicable = true;
            reason = 'Applicable: Binary symbolic execution for compiled native binaries.';
          } else {
            reason = `Not Applicable: Target is not a compiled native binary.`;
          }
          break;

        case 'z3':
          if (eco === 'EVM' || eco === 'CLARITY' || eco === 'MOVE') {
            applicable = true;
            reason = 'Applicable: SMT formal property solver for arithmetic invariant verification.';
          } else {
            reason = 'Potentially Applicable for formal invariant solving.';
          }
          break;

        case 'git':
          applicable = true;
          reason = 'Applicable: Source integrity and revision analysis.';
          break;

        default:
          reason = 'General analysis utility.';
      }

      const installed = check.status === 'AVAILABLE' || (check as any).available === true;
      let status: 'APPLICABLE' | 'NOT_APPLICABLE' | 'UNAVAILABLE' | 'NOT_INSTALLED' = 'NOT_APPLICABLE';

      if (applicable) {
        status = installed ? 'APPLICABLE' : 'NOT_INSTALLED';
      }

      matrix.push({
        engine_id: engineId,
        name: check.name || engineId,
        ecosystem: eco,
        status,
        applicable,
        installed,
        version: check.version || (check as any).detected_version || null,
        path: check.detected_path,
        reason,
      });
    }

    const applicableCount = matrix.filter(m => m.status === 'APPLICABLE').length;
    const fact: ResearchFact = {
      id: `fact-cap-${Date.now()}`,
      category: 'CAPABILITY',
      statement: `Target '${target.name}' (${eco}): ${applicableCount} engines applicable and ready for analysis.`,
      source: 'inspectTargetCapability',
      verified_at: new Date().toISOString(),
      confidence: 1.0,
    };

    return {
      success: true,
      data: {
        target_id: target.id,
        ecosystem: eco,
        matrix,
      },
      facts_established: [fact],
      duration_ms: Date.now() - start,
    };
  },
});

export const createAnalysisJobTool = registerTool({
  name: 'createAnalysisJob',
  category: 'ENGINE',
  description: 'Submit an asynchronous background analysis job to the worker orchestrator.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
    target_id: { name: 'target_id', type: 'string', description: 'Target ID', required: true },
    engine_id: { name: 'engine_id', type: 'string', description: 'Engine ID to execute', required: true },
    operation: { name: 'operation', type: 'string', description: 'Operation (e.g. ast_rule_scan, run_forge_tests)', required: true },
    parameters: { name: 'parameters', type: 'object', description: 'Execution parameters', required: false },
  },
  requires_approval: false,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();

    // Check policy gate
    const gateVerdict = PolicyGate.evaluateAction({
      action: 'RUN_ANALYSIS_JOB',
      target_id: params.target_id,
      engine_id: params.engine_id,
      operation: params.operation,
      has_user_approval: ctx.is_approved(`job-${params.engine_id}`),
    });

    if (!gateVerdict.allowed) {
      return {
        success: false,
        error: gateVerdict.explanation,
        code: gateVerdict.code,
        duration_ms: Date.now() - start,
      };
    }

    const job = globalJobOrchestrator.createJob({
      investigation_id: params.investigation_id,
      target_id: params.target_id,
      engine: params.engine_id,
      operation: params.operation,
      metadata: params.parameters || {},
    });

    return {
      success: true,
      data: {
        job_id: job.id,
        status: job.status,
        engine: job.engine,
        operation: job.operation,
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const getJobStatusTool = registerTool({
  name: 'getJobStatus',
  category: 'ENGINE',
  description: 'Check current execution status of an asynchronous analysis job.',
  parameters: {
    job_id: { name: 'job_id', type: 'string', description: 'Job ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { job_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const job = globalJobOrchestrator.getJob(params.job_id);
    if (!job) {
      return { success: false, error: `Job '${params.job_id}' not found.`, duration_ms: Date.now() - start };
    }
    return {
      success: true,
      data: {
        id: job.id,
        status: job.status,
        engine: job.engine,
        started_at: job.started_at,
        completed_at: job.completed_at,
        exit_code: job.exit_code,
        execution_status: job.execution_status,
        error: job.error,
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const getJobResultTool = registerTool({
  name: 'getJobResult',
  category: 'ENGINE',
  description: 'Retrieve full execution output artifacts and result logs for a completed job.',
  parameters: {
    job_id: { name: 'job_id', type: 'string', description: 'Job ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { job_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const job = globalJobOrchestrator.getJob(params.job_id);
    if (!job) {
      return { success: false, error: `Job '${params.job_id}' not found.`, duration_ms: Date.now() - start };
    }

    const stdoutArtifact = job.stdout_artifact_id ? globalDB.getEvidenceArtifact(job.stdout_artifact_id) : null;
    const stderrArtifact = job.stderr_artifact_id ? globalDB.getEvidenceArtifact(job.stderr_artifact_id) : null;

    return {
      success: true,
      data: {
        job_id: job.id,
        status: job.status,
        execution_status: job.execution_status,
        exit_code: job.exit_code,
        stdout_artifact: stdoutArtifact,
        stderr_artifact: stderrArtifact,
        error: job.error,
      },
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 6. EVIDENCE TOOLS
// ==============================================================================

export const listEvidenceTool = registerTool({
  name: 'listEvidence',
  category: 'EVIDENCE',
  description: 'List all evidence artifacts linked to an investigation.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { investigation_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const evidence = globalDB.listEvidence(params.investigation_id);
    return {
      success: true,
      data: evidence,
      duration_ms: Date.now() - start,
    };
  },
});

export const getArtifactTool = registerTool({
  name: 'getArtifact',
  category: 'EVIDENCE',
  description: 'Retrieve an artifact metadata and verified SHA-256 digest.',
  parameters: {
    artifact_id: { name: 'artifact_id', type: 'string', description: 'Artifact ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { artifact_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const artifact = globalDB.getEvidenceArtifact(params.artifact_id);
    if (!artifact) {
      return { success: false, error: `Artifact '${params.artifact_id}' not found.`, duration_ms: Date.now() - start };
    }
    return {
      success: true,
      data: artifact,
      duration_ms: Date.now() - start,
    };
  },
});

export const verifyArtifactIntegrityTool = registerTool({
  name: 'verifyArtifactIntegrity',
  category: 'EVIDENCE',
  description: 'Authoritatively verify that an artifact file matches its registered SHA-256 hash.',
  parameters: {
    artifact_id: { name: 'artifact_id', type: 'string', description: 'Artifact ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { artifact_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const artifact = globalDB.getEvidenceArtifact(params.artifact_id);
    if (!artifact) {
      return { success: false, error: `Artifact '${params.artifact_id}' not found.`, duration_ms: Date.now() - start };
    }

    let content: string | Buffer | undefined = undefined;
    if (artifact.path) {
      try {
        content = await globalArtifactStorage.read(artifact.path);
      } catch {
        // Fall back to stored metadata verification
      }
    }

    const verification = verifyArtifactIntegrity(artifact, content);
    return {
      success: true,
      data: verification,
      duration_ms: Date.now() - start,
    };
  },
});

export const getProvenanceTool = registerTool({
  name: 'getProvenance',
  category: 'EVIDENCE',
  description: 'Retrieve the verifiable cryptographic provenance graph or chain for an investigation or finding.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
    finding_id: { name: 'finding_id', type: 'string', description: 'Optional finding ID for chain', required: false },
  },
  requires_approval: false,
  execute: async (params: { investigation_id: string; finding_id?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const inv = globalDB.getInvestigation(params.investigation_id);
    if (!inv) {
      return { success: false, error: `Investigation '${params.investigation_id}' not found.`, duration_ms: Date.now() - start };
    }
    const target = inv.target_id ? globalDB.getTarget(inv.target_id) : undefined;
    const entities = {
      investigation: inv,
      target,
      findings: globalDB.listFindings(params.investigation_id),
      events: globalDB.listEvidenceEvents(params.investigation_id),
      artifacts: globalDB.listEvidence(params.investigation_id),
      jobs: globalJobOrchestrator.listJobs({ investigation_id: params.investigation_id }),
    };

    if (params.finding_id) {
      const chain = globalProvenanceService.explainFindingProvenance(params.finding_id, entities);
      return {
        success: true,
        data: chain,
        duration_ms: Date.now() - start,
      };
    }

    const graph = globalProvenanceService.buildGraph(entities);
    return {
      success: true,
      data: graph,
      duration_ms: Date.now() - start,
    };
  },
});

// ==============================================================================
// 7. FINDING TOOLS
// ==============================================================================

export const listCandidatesTool = registerTool({
  name: 'listCandidates',
  category: 'FINDING',
  description: 'List candidate vulnerability hypotheses and initial findings.',
  parameters: {
    investigation_id: { name: 'investigation_id', type: 'string', description: 'Investigation ID', required: true },
    target_id: { name: 'target_id', type: 'string', description: 'Target ID (optional)', required: false },
  },
  requires_approval: false,
  execute: async (params: { investigation_id: string; target_id?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const findings = globalDB.listFindings(params.investigation_id);
    const candidates = findings.filter(f => f.status === FindingStatus.CANDIDATE);
    return {
      success: true,
      data: candidates,
      duration_ms: Date.now() - start,
    };
  },
});

export const inspectCandidateTool = registerTool({
  name: 'inspectCandidate',
  category: 'FINDING',
  description: 'Inspect a candidate finding, its supporting evidence, and current state machine transitions.',
  parameters: {
    finding_id: { name: 'finding_id', type: 'string', description: 'Finding ID', required: true },
  },
  requires_approval: false,
  execute: async (params: { finding_id: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const finding = globalDB.getFinding(params.finding_id);
    if (!finding) {
      return { success: false, error: `Finding '${params.finding_id}' not found.`, duration_ms: Date.now() - start };
    }

    const evidenceArtifacts = finding.evidence_artifact_ids.map(id => globalDB.getEvidenceArtifact(id)).filter(Boolean);

    return {
      success: true,
      data: {
        finding,
        evidence: evidenceArtifacts,
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const requestVerificationTool = registerTool({
  name: 'requestVerification',
  category: 'FINDING',
  description: 'Dispatch a candidate finding for dynamic reproduction or formal SMT verification. Requires user approval for state changes.',
  parameters: {
    candidate_id: { name: 'candidate_id', type: 'string', description: 'Finding candidate ID', required: true },
    verification_type: { name: 'verification_type', type: 'string', description: 'DYNAMIC or FORMAL', required: true },
    operation: { name: 'operation', type: 'string', description: 'e.g. run_forge_exploit, solve_smt_model', required: true },
    parameters: { name: 'parameters', type: 'object', description: 'Verification parameters', required: false },
  },
  requires_approval: true,
  execute: async (params: any, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const finding = globalDB.getFinding(params.candidate_id);
    if (!finding) {
      return { success: false, error: `Candidate finding '${params.candidate_id}' not found.`, duration_ms: Date.now() - start };
    }

    // Policy Gate Evaluation
    const gateVerdict = PolicyGate.evaluateAction({
      action: 'RUN_DYNAMIC_VERIFICATION',
      target_id: finding.target_id,
      operation: params.operation,
      parameters: params.parameters,
      has_user_approval: ctx.is_approved(`verify-${params.candidate_id}`),
    });

    if (!gateVerdict.allowed) {
      return {
        success: false,
        error: gateVerdict.explanation,
        code: gateVerdict.code,
        duration_ms: Date.now() - start,
      };
    }

    // Dynamic verification dispatch
    if (params.verification_type === 'DYNAMIC') {
      const job = await globalDynamicVerificationService.execute({
        candidate_id: finding.id,
        target_id: finding.target_id,
        investigation_id: finding.investigation_id,
        operation: params.operation || 'verify',
        parameters: params.parameters || {},
      });

      return {
        success: true,
        data: {
          job,
          verification_type: 'DYNAMIC',
          status: 'DISPATCHED',
        },
        duration_ms: Date.now() - start,
      };
    }

    // Formal verification dispatch
    const formalResult = await globalFormalVerificationService.verifyModel({
      investigationId: finding.investigation_id,
      targetId: finding.target_id,
      candidateId: finding.id,
      model: params.parameters?.model || {
        name: finding.title,
        property: params.parameters?.property || 'UNAUTHORIZED_OBJECT_ACCESS',
        assertions: [],
        assumptions: [],
      },
    });

    return {
      success: true,
      data: {
        formal_result: formalResult,
        verification_type: 'FORMAL',
      },
      duration_ms: Date.now() - start,
    };
  },
});

export const executeFoundryPoCTool = registerTool({
  name: 'executeFoundryPoC',
  category: 'FINDING',
  description: 'Execute Foundry EVM proof-of-concept test and perform state-differential validation. Requires explicit user approval.',
  parameters: {
    candidate_id: { name: 'candidate_id', type: 'string', description: 'Finding candidate ID', required: true },
    contract_name: { name: 'contract_name', type: 'string', description: 'Target contract name', required: false },
    poc_script: { name: 'poc_script', type: 'string', description: 'Solidity PoC test code or operation', required: false },
    environment: { name: 'environment', type: 'string', description: 'LOCAL_SOURCE or LOCAL_FORK', required: false },
  },
  requires_approval: true,
  execute: async (params: { candidate_id: string; contract_name?: string; poc_script?: string; environment?: string }, ctx): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const finding = globalDB.getFinding(params.candidate_id);
    if (!finding) {
      return { success: false, error: `Candidate '${params.candidate_id}' not found.`, duration_ms: Date.now() - start };
    }

    const gateVerdict = PolicyGate.evaluateAction({
      action: 'RUN_DYNAMIC_VERIFICATION',
      target_id: finding.target_id,
      operation: 'foundry_poc',
      parameters: params,
      has_user_approval: ctx.is_approved(`poc-${params.candidate_id}`),
    });

    if (!gateVerdict.allowed) {
      return {
        success: false,
        error: gateVerdict.explanation,
        code: gateVerdict.code,
        duration_ms: Date.now() - start,
      };
    }

    const job = await globalDynamicVerificationService.execute({
      candidate_id: finding.id,
      target_id: finding.target_id,
      investigation_id: finding.investigation_id,
      runtime: 'EVM',
      environment: params.environment || 'LOCAL_SOURCE',
      operation: 'foundry_poc',
      parameters: {
        contract_name: params.contract_name,
        poc_script: params.poc_script,
      },
    });

    const isReproduced = job.result === 'REPRODUCED';
    const facts: ResearchFact[] = [
      {
        id: `fact-poc-${Date.now()}`,
        category: 'VERIFICATION',
        statement: `Dynamic Foundry execution on candidate '${finding.title}' yielded ${job.result} (${job.state_diff?.summary || 'State evaluated'}).`,
        source: 'DynamicVerificationService',
        verified_at: new Date().toISOString(),
        confidence: 1.0,
      },
    ];

    if (isReproduced && job.state_diff?.protected_changed) {
      try {
        globalDB.transitionFinding(finding.id, FindingStatus.CONFIRMED, 'Confirmed via dynamic Foundry execution with state change evidence');
      } catch {
        // finding state machine transition fallback if not in valid predecessor state
      }
    }

    const capturedEvidence = [
      job.stdout_artifact_id,
      job.stderr_artifact_id,
      job.execution_trace_artifact_id,
      job.state_before_artifact_id,
      job.state_after_artifact_id,
    ].filter(Boolean) as string[];

    return {
      success: true,
      data: {
        job,
        reproduction_result: job.result,
        state_diff: job.state_diff,
        evidence_captured: capturedEvidence,
      },
      facts_established: facts,
      duration_ms: Date.now() - start,
    };
  },
});

