/**
 * Phase 6 AI Security Control Plane Unit Test Suite
 * Intent Security Workbench - Phase 6
 *
 * Verifies:
 * 1. ToolRegistry: schema validation, tool registration, approval gates, typed execution.
 * 2. AISecurityController: objective intake, research plan generation, fact/hypothesis tracking,
 *    autonomous stepping, human-in-the-loop approval requests, scope boundary enforcement,
 *    and graceful degradation when AI keys are absent.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import {
  globalToolRegistry,
  AISecurityController,
  ResearchPhase,
  ControllerEventType,
  ControllerExecutionContext,
  ResearchFact,
  ResearchHypothesis,
  UserApprovalRequest,
} from '../../packages/agent-runtime/src/index.js';
import { globalDB } from '../../apps/api/db_store.js';
import { globalJobOrchestrator } from '../../packages/orchestrator/src/index.js';
import { TargetType, ScopeInclusionStatus, ScopeAssetType, Ecosystem, BountyPlatform, ProgramStatus, Severity, FindingStatus } from '../../packages/core/src/index.js';

describe('Phase 6 — AI Security Control Plane Core', () => {
  let controller: AISecurityController;

  beforeEach(() => {
    controller = new AISecurityController();
  });

  describe('1. ToolRegistry Architecture & Typed Discovery', () => {
    it('should have all standard security workbench tools registered', () => {
      const tools = globalToolRegistry.listTools();
      expect(tools.length).toBeGreaterThanOrEqual(10);

      const toolNames = tools.map(t => t.name);
      expect(toolNames).toContain('listTargets');
      expect(toolNames).toContain('registerTarget');
      expect(toolNames).toContain('acquireTargetSource');
      expect(toolNames).toContain('evaluateScope');
      expect(toolNames).toContain('inspectEngine');
      expect(toolNames).toContain('inspectTargetCapability');
      expect(toolNames).toContain('verifyArtifactIntegrity');
      expect(toolNames).toContain('getProvenance');
      expect(toolNames).toContain('listCandidates');
      expect(toolNames).toContain('inspectCandidate');
      expect(toolNames).toContain('requestVerification');
    });

    it('should properly flag dangerous tools that require user approval', () => {
      const dispatchTool = globalToolRegistry.getTool('requestVerification');
      expect(dispatchTool).toBeDefined();
      expect(dispatchTool?.requires_approval).toBe(true);

      const listTool = globalToolRegistry.getTool('listTargets');
      expect(listTool).toBeDefined();
      expect(listTool?.requires_approval).toBe(false);
    });

    it('should categorize tools across workbench capabilities', () => {
      const targetTools = globalToolRegistry.getToolsByCategory('TARGET');
      expect(targetTools.length).toBeGreaterThan(0);
      expect(targetTools.some(t => t.name === 'listTargets')).toBe(true);

      const engineTools = globalToolRegistry.getToolsByCategory('ENGINE');
      expect(engineTools.length).toBeGreaterThan(0);
      expect(engineTools.some(t => t.name === 'inspectEngine')).toBe(true);

      const evidenceTools = globalToolRegistry.getToolsByCategory('EVIDENCE');
      expect(evidenceTools.length).toBeGreaterThan(0);
      expect(evidenceTools.some(t => t.name === 'verifyArtifactIntegrity')).toBe(true);
    });

    it('should fail cleanly when invoking an unknown tool', async () => {
      const ctx: ControllerExecutionContext = {
        session_id: 'sess-1',
        investigation_id: 'inv-test-1',
        is_approved: () => false,
      };
      const result = await globalToolRegistry.invokeTool('nonExistentTool', {}, ctx);
      expect(result.success).toBe(false);
      expect(result.error).toContain('not registered in the AI Security Controller');
    });

    it('should enforce parameter validation when required arguments are missing', async () => {
      const ctx: ControllerExecutionContext = {
        session_id: 'sess-1',
        investigation_id: 'inv-test-1',
        is_approved: () => false,
      };
      const result = await globalToolRegistry.invokeTool('acquireTargetSource', {}, ctx);
      expect(result.success).toBe(false);
      expect(result.error).toContain("Missing required parameter 'target_id'");
    });
  });

  describe('2. Scope Enforcement & Policy Gates in Tools', () => {
    it('should evaluate and record scope status correctly', async () => {
      // Configure a program with scope entry
      const program = globalDB.createProgram({
        name: 'Bounty Program Alpha',
        platform: BountyPlatform.CUSTOM,
        program_url: 'https://security.example.com/policy',
        status: ProgramStatus.ACTIVE,
      });

      globalDB.createScopeEntry({
        program_id: program.id,
        asset_identifier: 'https://staging.example.com',
        asset_type: ScopeAssetType.URL,
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        notes: 'Staging API authorized for security evaluation',
      });

      // Register a target
      const target = globalDB.createTarget({
        name: 'Safe API Target',
        program_id: program.id,
        target_type: TargetType.REST_API,
        ecosystem: Ecosystem.WEB_API,
        primary_location: 'https://staging.example.com',
      });

      const ctx: ControllerExecutionContext = {
        session_id: 'sess-scope',
        investigation_id: 'inv-scope-test',
        program_id: program.id,
        target_id: target.id,
        is_approved: () => false,
      };

      const result = await globalToolRegistry.invokeTool('evaluateScope', {
        program_id: program.id,
        target_identifier: 'https://staging.example.com',
      }, ctx);

      expect(result.success).toBe(true);
      expect(result.data).toBeDefined();
      expect(result.facts_established).toBeDefined();
      expect(result.facts_established!.length).toBeGreaterThan(0);
    });
  });

  describe('3. AISecurityController Lifecycle & Objective Formulation', () => {
    it('should execute objective and establish structured plan with facts', async () => {
      // Create target and investigation in DB
      const target = globalDB.createTarget({
        name: 'DeFi Lending Vault',
        program_id: 'prog-test-fixtures',
        target_type: TargetType.SMART_CONTRACT,
        ecosystem: Ecosystem.EVM,
        primary_location: 'https://github.com/example/vault',
      });

      const investigation = globalDB.createInvestigation({
        name: 'Lending Vault Security Analysis',
        target_id: target.id,
        status: 'OPEN' as any,
      });

      const state = await controller.executeObjective({
        objective: 'Analyze Vault contract for access control and invariant violations',
        investigation_id: investigation.id,
        target_id: target.id,
      });

      expect(state).toBeDefined();
      expect(state.investigation_id).toBe(investigation.id);
      expect(state.plan).toBeDefined();
      expect(state.plan?.steps.length).toBeGreaterThanOrEqual(3);
      expect(state.current_objective).toContain('Analyze Vault contract');
      expect(state.decisions.length).toBeGreaterThanOrEqual(1);

      // Verify retrieval by investigation ID
      const retrieved = controller.getState(investigation.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.investigation_id).toBe(investigation.id);
    });

    it('should step through plan phases deterministically and establish facts', async () => {
      const target = globalDB.createTarget({
        name: 'Token Staking Contract',
        program_id: 'prog-test-fixtures',
        target_type: TargetType.SMART_CONTRACT,
        ecosystem: Ecosystem.EVM,
        primary_location: 'https://github.com/example/staking',
      });

      const investigation = globalDB.createInvestigation({
        name: 'Staking Security Audit',
        target_id: target.id,
        status: 'OPEN' as any,
      });

      await controller.executeObjective({
        objective: 'Review staking contract invariants',
        investigation_id: investigation.id,
        target_id: target.id,
      });

      // Step execution
      const updatedState = await controller.step(investigation.id);
      expect(updatedState).toBeDefined();
      expect(updatedState.decisions.length).toBeGreaterThan(1);
      expect(updatedState.facts).toBeDefined();
    });

    it('should separate facts from hypotheses rigorously', async () => {
      const target = globalDB.createTarget({
        name: 'Perpetuals Exchange Contract',
        program_id: 'prog-test-fixtures',
        target_type: TargetType.SMART_CONTRACT,
        ecosystem: Ecosystem.EVM,
        primary_location: 'https://github.com/example/perps',
      });

      const investigation = globalDB.createInvestigation({
        name: 'Perps Verification',
        target_id: target.id,
        status: 'OPEN' as any,
      });

      const state = await controller.executeObjective({
        objective: 'Audit liquidation mechanics',
        investigation_id: investigation.id,
        target_id: target.id,
      });

      // Push an explicit hypothesis
      const hyp: ResearchHypothesis = {
        id: 'hyp-1',
        title: 'Fee calculation underflow',
        premise: 'Liquidation fee calculation may round down to zero on small positions',
        target_id: target.id,
        supporting_fact_ids: [],
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        status: 'ACTIVE',
        requires_verification: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      state.hypotheses.push(hyp);

      expect(state.hypotheses.length).toBe(1);
      expect(state.hypotheses[0].premise).toContain('round down to zero');

      // Facts must be separated and not conflated
      for (const fact of state.facts) {
        expect(fact.statement).not.toContain('round down to zero');
        expect(fact.confidence).toBe(1.0);
      }
    });

    it('should pause and request user approval for high-risk actions', async () => {
      const target = globalDB.createTarget({
        name: 'Core Settlement Contract',
        program_id: 'prog-test-fixtures',
        target_type: TargetType.SMART_CONTRACT,
        ecosystem: Ecosystem.EVM,
        primary_location: 'https://github.com/example/settlement',
      });

      const investigation = globalDB.createInvestigation({
        name: 'Settlement Exploit Verification',
        target_id: target.id,
        status: 'OPEN' as any,
      });

      const state = await controller.executeObjective({
        objective: 'Verify candidate exploit',
        investigation_id: investigation.id,
        target_id: target.id,
      });

      // Register a pending approval request
      const approvalReq: UserApprovalRequest = {
        id: `appr-test-1`,
        action: 'requestVerification',
        description: 'Execute dynamic Foundry exploit test on candidate BOLA finding',
        target_id: target.id,
        sensitive: true,
        required_policy_check: 'RESEARCHER_APPROVAL',
        status: 'PENDING',
        created_at: new Date().toISOString(),
      };
      state.approvals.push(approvalReq);

      // Stepping should now be halted until approved
      await controller.step(investigation.id);
      expect(state.current_phase).toBe(ResearchPhase.BLOCKED);
      expect(state.current_activity).toContain('Waiting for researcher approval');

      // User approves
      const resolvedState = await controller.approveAction(investigation.id, approvalReq.id, true, 'Authorized by lead security auditor');
      expect(resolvedState.approvals[0].status).toBe('APPROVED');
      expect(resolvedState.current_phase).not.toBe(ResearchPhase.BLOCKED);
    });

    it('should reject denied approvals and record denial rationale', async () => {
      const target = globalDB.createTarget({
        name: 'Vault External Probe',
        program_id: 'prog-test-fixtures',
        target_type: TargetType.REST_API,
        ecosystem: Ecosystem.WEB_API,
        primary_location: 'https://staging.example.com',
      });

      const investigation = globalDB.createInvestigation({
        name: 'Staging Probe',
        target_id: target.id,
        status: 'OPEN' as any,
      });

      const state = await controller.executeObjective({
        objective: 'Test endpoint behavior',
        investigation_id: investigation.id,
        target_id: target.id,
      });

      const approvalReq: UserApprovalRequest = {
        id: `appr-test-2`,
        action: 'requestVerification',
        description: 'Execute dynamic request against staging endpoint',
        target_id: target.id,
        sensitive: true,
        required_policy_check: 'RESEARCHER_APPROVAL',
        status: 'PENDING',
        created_at: new Date().toISOString(),
      };
      state.approvals.push(approvalReq);

      // User denies
      const resolvedState = await controller.approveAction(investigation.id, approvalReq.id, false, 'Staging system undergoing maintenance');
      expect(resolvedState.approvals[0].status).toBe('REJECTED');
      expect(resolvedState.current_phase).toBe(ResearchPhase.BLOCKED);
      expect(resolvedState.blockers.some(b => b.code === 'RESEARCHER_REJECTED')).toBe(true);
    });
  });

  describe('Investigation identity binding', () => {
    it('adopts the store-assigned investigation id when auto-creating one', async () => {
      // Regression: the controller used to keep a synthetic `inv-ai-<ts>` id even
      // after the store created the investigation under its own id, so dispatched
      // jobs referenced an investigation that did not exist.
      const program = globalDB.createProgram({
        name: 'AI Identity Program',
        platform: BountyPlatform.CUSTOM,
        scope: ['https://github.com/example/ai-identity'],
        metadata: {},
      });
      const target = globalDB.createTarget({
        program_id: program.id,
        name: 'ai-identity-target',
        target_type: TargetType.REPOSITORY,
        ecosystem: Ecosystem.WEB_API,
        repository_url: 'https://github.com/example/ai-identity',
        metadata: {},
      });

      const state = await controller.executeObjective({
        objective: 'Assess authorization risk in handlers',
        program_id: program.id,
        target_id: target.id,
        auto_advance: false,
      });

      // The controller's id must correspond to a real persisted investigation.
      const persisted = globalDB.getInvestigation(state.investigation_id);
      expect(persisted).toBeDefined();
      expect(persisted!.id).toBe(state.investigation_id);
      expect(persisted!.program_id).toBe(program.id);
      expect(persisted!.target_id).toBe(target.id);

      // State must be retrievable under the same id the controller reports.
      expect(controller.getState(state.investigation_id)).toBeDefined();

      // The requested alias and canonical id must not produce duplicate states.
      const listed = controller.getAllStates().filter(s => s.investigation_id === state.investigation_id);
      expect(listed).toHaveLength(1);
    });

    it('honours an explicitly supplied investigation id', async () => {
      const program = globalDB.createProgram({
        name: 'AI Explicit Id Program',
        platform: BountyPlatform.CUSTOM,
        scope: ['https://github.com/example/explicit'],
        metadata: {},
      });
      const target = globalDB.createTarget({
        program_id: program.id,
        name: 'explicit-target',
        target_type: TargetType.REPOSITORY,
        ecosystem: Ecosystem.WEB_API,
        repository_url: 'https://github.com/example/explicit',
        metadata: {},
      });
      const investigation = globalDB.createInvestigation({
        program_id: program.id,
        target_id: target.id,
        title: 'Explicit investigation',
        description: 'created by test',
      });

      const state = await controller.executeObjective({
        objective: 'Review explicit investigation',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: false,
      });

      expect(state.investigation_id).toBe(investigation.id);
      expect(globalDB.getInvestigation(investigation.id)).toBeDefined();
    });
  });

  describe('Live hunt loop', () => {
    // These tests build a real local git repository containing a BOLA-vulnerable
    // handler, so acquisition, scheduling and job execution all run for real.
    // Without a reachable repository the loop would stop at acquisition and the
    // assertions below would pass vacuously.
    let repoDir: string;

    const seedVulnerableRepo = (): string => {
      const dir = path.join(process.cwd(), '.test_fixtures', `ai_hunt_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
      fs.mkdirSync(dir, { recursive: true });
      execFileSync('git', ['init'], { cwd: dir });
      execFileSync('git', ['config', 'user.name', 'Workbench Test'], { cwd: dir });
      execFileSync('git', ['config', 'user.email', 'test@workbench.internal'], { cwd: dir });
      fs.writeFileSync(
        path.join(dir, 'api.js'),
        [
          "const express = require('express');",
          'const router = express.Router();',
          '// BOLA: no ownership check between document and requester',
          "router.get('/documents/:id', async (req, res) => {",
          '  const doc = await db.documents.findOne({ _id: req.params.id });',
          '  return res.json(doc);',
          '});',
          'module.exports = router;',
        ].join('\n')
      );
      execFileSync('git', ['add', '-A'], { cwd: dir });
      execFileSync('git', ['commit', '-m', 'vulnerable handlers'], { cwd: dir });
      return dir;
    };

    const seedProgramTargetInvestigation = (label: string) => {
      const program = globalDB.createProgram({
        name: `${label} Program`,
        platform: BountyPlatform.CUSTOM,
        external_identifier: `slug-${label}`,
        scope: [repoDir],
        metadata: {},
      });
      const target = globalDB.createTarget({
        program_id: program.id,
        name: `${label}-target`,
        target_type: TargetType.REPOSITORY,
        ecosystem: Ecosystem.WEB_API,
        repository_url: repoDir,
        metadata: {},
      });
      const investigation = globalDB.createInvestigation({
        program_id: program.id,
        target_id: target.id,
        title: `${label} investigation`,
        description: label,
      });
      return { program, target, investigation };
    };

    beforeEach(() => {
      repoDir = seedVulnerableRepo();
    });

    afterEach(() => {
      try {
        fs.rmSync(repoDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    });

    it('schedules analysis jobs against the real investigation, not a program-derived id', async () => {
      // Regression: the planner derived `inv-<program_id>`, orphaning every job.
      const { program, target, investigation } = seedProgramTargetInvestigation('job-id');

      await controller.executeObjective({
        objective: 'Hunt broken object level authorization in REST handlers',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: true,
        max_steps: 14,
      });

      const jobs = globalJobOrchestrator.listJobs({ investigation_id: investigation.id });
      expect(jobs.length).toBeGreaterThan(0);

      for (const job of jobs) {
        expect(job.investigation_id).toBe(investigation.id);
        expect(job.investigation_id).not.toBe(`inv-${program.id}`);
      }

      // Jobs must not be left stranded in QUEUED.
      expect(jobs.filter(j => j.status === 'QUEUED')).toHaveLength(0);
    }, 180000);

    it('executes scheduled jobs and records the real outcome as a verified fact', async () => {
      const { program, target, investigation } = seedProgramTargetInvestigation('facts');

      const state = await controller.executeObjective({
        objective: 'Hunt broken object level authorization in REST handlers',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: true,
        max_steps: 14,
      });

      const jobs = globalJobOrchestrator.listJobs({ investigation_id: investigation.id });
      expect(jobs.length).toBeGreaterThan(0);

      const executionFacts = state.facts.filter(f => f.category === 'EXECUTION');
      expect(executionFacts.length).toBeGreaterThan(0);
      expect(executionFacts[0].statement).toContain('exit code');
    }, 180000);

    it('surfaces engine findings as CANDIDATE findings with evidence attached', async () => {
      const { program, target, investigation } = seedProgramTargetInvestigation('candidates');

      await controller.executeObjective({
        objective: 'Hunt broken object level authorization in REST handlers',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: true,
        max_steps: 14,
      });

      const findings = globalDB.listFindings(investigation.id);
      expect(findings.length).toBeGreaterThan(0);

      for (const finding of findings) {
        // A static hit is a lead, never a confirmed vulnerability.
        expect(finding.status).toBe(FindingStatus.CANDIDATE);
        expect(finding.investigation_id).toBe(investigation.id);
      }

      // Every finding must cite machine-verifiable evidence.
      expect(findings.some(f => f.evidence_artifact_ids.length > 0)).toBe(true);
    }, 180000);

    it('scopes the approval key to the resource the tool gates on', async () => {
      // Regression: the controller granted the bare tool name while the tool
      // checked `verify-<candidate_id>`, so approval never opened the gate.
      const { program, target, investigation } = seedProgramTargetInvestigation('approvalkey');

      const state = await controller.executeObjective({
        objective: 'Hunt broken object level authorization in REST handlers',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: true,
        max_steps: 16,
      });

      const pending = state.approvals.filter(a => a.status === 'PENDING');
      expect(pending.length).toBeGreaterThan(0);

      for (const req of pending) {
        expect(req.approval_key).toBeTruthy();
        // The gate is keyed per resource, never on the bare tool name.
        expect(req.approval_key).not.toBe(req.action);
      }

      // Approving must actually mark the request resolved.
      const first = pending[0];
      const after = await controller.approveAction(investigation.id, first.id, true, 'authorized');
      expect(after.approvals.find(a => a.id === first.id)!.status).toBe('APPROVED');
    }, 180000);

    it('does not stack duplicate approval requests for the same resource', async () => {
      const { program, target, investigation } = seedProgramTargetInvestigation('dedup');

      await controller.executeObjective({
        objective: 'Hunt broken object level authorization in REST handlers',
        investigation_id: investigation.id,
        program_id: program.id,
        target_id: target.id,
        auto_advance: true,
        max_steps: 16,
      });

      const state = controller.getState(investigation.id)!;
      const pending = state.approvals.filter(a => a.status === 'PENDING');
      const keys = pending.map(a => a.approval_key || a.action);
      expect(new Set(keys).size).toBe(keys.length);
    }, 180000);
  });
});
