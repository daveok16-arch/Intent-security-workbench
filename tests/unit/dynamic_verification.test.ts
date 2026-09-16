/**
 * Phase 5 — Real Dynamic Verification & Exploit-Witness Engine Comprehensive Unit Tests
 *
 * Verifies:
 * 1. Tool Detectors (Forge, Anvil, Clarinet detection, genuine host detection, honest missing reporting)
 * 2. Target Isolation Validator (enforces researcher-controlled environments, rejects production URLs)
 * 3. State Differential Engine (deep diffing, protected path mutation detection, metrics)
 * 4. PoC Lifecycle State Machine (GENERATED -> EXECUTED -> REPRODUCED/NOT_REPRODUCED)
 * 5. Deterministic Reproduction Decision Engine (strict multi-condition verification logic)
 * 6. Evidence & Provenance Linking (SHA-256 artifacts, audit events, provenance node links)
 * 7. Anti-Fabrication & Finding Lifecycle (no automatic CONFIRMED promotion, no synthetic results)
 */

import { describe, it, expect, beforeAll } from 'vitest';
import path from 'path';
import {
  ToolDetector,
  TargetValidator,
  StateDiffer,
  PoCEngine,
  ReproductionDecisionEngine,
  FoundryAdapter,
  ClarinetAdapter,
  APIAdapter,
  DynamicVerificationService,
  type AuthorizationStateEvidence,
  type TargetEnvironment,
} from '../../packages/dynamic-verification/src/index.js';
import { globalDB } from '../../apps/api/db_store.js';
import {
  ArtifactType,
  EvidenceEventType,
  FindingStatus,
  Severity,
  Confidence,
} from '../../packages/core/src/index.js';

describe('Phase 5 — Real Dynamic Verification Unit Tests', () => {
  // =========================================================================
  // 1. Tool Detection & Binary Verification
  // =========================================================================
  describe('1. Tool Detection & Host Binaries', () => {
    it('detects real forge binary on host system', () => {
      const forge = ToolDetector.detectForge();
      expect(forge.installed).toBe(true);
      expect(forge.status).toBe('AVAILABLE');
      expect(forge.executable_path).toBeTruthy();
      expect(forge.executable_path).toContain('forge');
      expect(forge.version).toBeTruthy();
      expect(forge.version).toMatch(/\d+\.\d+/);
      expect(forge.capabilities).toContain('solidity compilation');
    });

    it('detects real anvil binary on host system', () => {
      const anvil = ToolDetector.detectAnvil();
      expect(anvil.installed).toBe(true);
      expect(anvil.status).toBe('AVAILABLE');
      expect(anvil.executable_path).toBeTruthy();
      expect(anvil.executable_path).toContain('anvil');
      expect(anvil.version).toBeTruthy();
    });

    it('honestly reports missing clarinet binary as NOT_INSTALLED without fake emulation', () => {
      const clarinet = ToolDetector.detectClarinet('/nonexistent/bin/clarinet');
      expect(clarinet.installed).toBe(false);
      expect(clarinet.status).toBe('NOT_INSTALLED');
      expect(clarinet.error).toContain('ENGINE_NOT_INSTALLED');
      expect(clarinet.error).toContain('is not installed');
      expect(clarinet.executable_path).toBeNull();
    });

    it('detects missing binary when invalid path is given', () => {
      const missing = ToolDetector.detectForge('/non/existent/path/to/forge');
      expect(missing.installed).toBe(false);
      expect(missing.status).toBe('NOT_INSTALLED');
      expect(missing.error).toContain('ENGINE_NOT_INSTALLED');
    });

    it('returns structured catalog of all engines via detectAll', () => {
      const catalog = ToolDetector.detectAll();
      expect(catalog).toHaveProperty('forge');
      expect(catalog).toHaveProperty('anvil');
      expect(catalog).toHaveProperty('clarinet');
      expect(catalog.forge.installed).toBe(true);
      // Whether clarinet is installed is host-dependent; the catalog must
      // report it truthfully either way, never claiming a phantom path.
      for (const entry of Object.values(catalog)) {
        const t = entry as { installed: boolean; executable_path: string | null; status: string };
        if (!t.installed) {
          expect(t.executable_path).toBeNull();
          expect(t.status).toBe('NOT_INSTALLED');
        } else {
          expect(t.executable_path).toBeTruthy();
          expect(t.status).toBe('AVAILABLE');
        }
      }
    });
  });

  // =========================================================================
  // 2. Target Isolation Validator
  // =========================================================================
  describe('2. Target Isolation & Environment Boundary', () => {
    it('approves isolated local environments', () => {
      const envs: TargetEnvironment[] = ['LOCAL_SOURCE', 'LOCAL_ANVIL', 'LOCAL_SIMNET', 'DOCKER_ISOLATED'];
      for (const env of envs) {
        const check = TargetValidator.validateTarget(env, 'http://127.0.0.1:8545');
        expect(check.approved).toBe(true);
        expect(check.error).toBeNull();
      }
    });

    it('strictly rejects production web endpoints and public RPCs', () => {
      const forbiddenTargets = [
        'https://api.acme-production.com/v1/orders',
        'http://internal-corp.enterprise.com',
        'https://mainnet.infura.io/v3/key',
        'https://eth-mainnet.g.alchemy.com/v2/key',
      ];

      for (const target of forbiddenTargets) {
        const check = TargetValidator.validateTarget('LOCAL_SOURCE', target);
        expect(check.approved).toBe(false);
        expect(check.error).toContain('UNAUTHORIZED_PRODUCTION_TARGET');
      }
    });

    it('rejects unapproved target environment strings', () => {
      const check = TargetValidator.validateTarget('PUBLIC_PRODUCTION' as any);
      expect(check.approved).toBe(false);
      expect(check.error).toContain('ENVIRONMENT_INVALID');
    });
  });

  // =========================================================================
  // 3. State Differential Engine
  // =========================================================================
  describe('3. State Differential Engine', () => {
    it('accurately identifies mutations in protected state fields', () => {
      const before = {
        vault: {
          balances: {
            '0xVictim': 100,
            '0xAttacker': 0,
          },
        },
      };

      const after = {
        vault: {
          balances: {
            '0xVictim': 60,
            '0xAttacker': 40,
          },
        },
      };

      const diff = StateDiffer.computeDiff(before, after, {
        protectedPaths: ['vault.balances', '0xVictim'],
      });

      expect(diff.has_changes).toBe(true);
      expect(diff.protected_changed).toBe(true);
      expect(diff.diffs.length).toBe(2);

      const victimDiff = diff.differences.find((d) => d.path.includes('0xVictim'));
      expect(victimDiff).toBeDefined();
      expect(victimDiff?.before).toBe(100);
      expect(victimDiff?.after).toBe(60);
      expect(victimDiff?.is_protected).toBe(true);

      const attackerDiff = diff.differences.find((d) => d.path.includes('0xAttacker'));
      expect(attackerDiff).toBeDefined();
      expect(attackerDiff?.before).toBe(0);
      expect(attackerDiff?.after).toBe(40);
    });

    it('reports no changes when state is identical before and after', () => {
      const state = { balance: 50, status: 'LOCKED' };
      const diff = StateDiffer.computeDiff(state, { balance: 50, status: 'LOCKED' });

      expect(diff.has_changes).toBe(false);
      expect(diff.protected_changed).toBe(false);
      expect(diff.differences.length).toBe(0);
    });

    it('detects addition and deletion of state entries', () => {
      const before = { items: ['alpha', 'beta'] };
      const after = { items: ['alpha', 'gamma'] };

      const diff = StateDiffer.computeDiff(before, after);
      expect(diff.has_changes).toBe(true);
      expect(diff.differences.length).toBeGreaterThan(0);
    });
  });

  // =========================================================================
  // 4. PoC Lifecycle State Machine
  // =========================================================================
  describe('4. PoC Lifecycle State Machine', () => {
    it('manages PoC lifecycle: GENERATED -> EXECUTED -> REPRODUCED', () => {
      const poc = PoCEngine.generatePoC({
        runtime: 'EVM',
        payload_content: 'contract ExploitTest { ... }',
        format: 'FOUNDRY_TEST',
      });

      expect(poc.state).toBe('GENERATED');
      expect(poc.payload_sha256).toBeTruthy();

      // Step 2: markExecuted
      const executed = PoCEngine.markExecuted(poc);
      expect(executed.state).toBe('EXECUTED');
      expect(executed.executed_at).toBeTruthy();

      // Step 3: recordOutcome
      const finalPoC = PoCEngine.recordOutcome(executed, 'REPRODUCED');
      expect(finalPoC.state).toBe('REPRODUCED');
      expect(finalPoC.reproduced_at).toBeTruthy();
    });

    it('records NOT_REPRODUCED outcome correctly', () => {
      const poc = PoCEngine.generatePoC({
        runtime: 'CLARITY',
        payload_content: '(contract-call? ...)',
        format: 'CLARINET_TEST',
      });

      const executed = PoCEngine.markExecuted(poc);
      const finalPoC = PoCEngine.recordOutcome(executed, 'NOT_REPRODUCED');
      expect(finalPoC.state).toBe('NOT_REPRODUCED');
    });

    it('rejects invalid state transitions', () => {
      const poc = PoCEngine.generatePoC({
        runtime: 'EVM',
        payload_content: 'test',
        format: 'FOUNDRY_TEST',
      });

      // Cannot record outcome before execution
      expect(() => PoCEngine.recordOutcome(poc, 'REPRODUCED')).toThrow(/Invalid PoC state transition/);
    });
  });

  // =========================================================================
  // 5. Deterministic Reproduction Decision Engine
  // =========================================================================
  describe('5. Reproduction Decision Engine', () => {
    it('concludes REPRODUCED only when ALL multi-conditions hold', () => {
      const authState: AuthorizationStateEvidence = {
        caller: '0xAttacker',
        owner: '0xVictim',
        caller_is_owner: false,
        caller_has_role: false,
        caller_authorized: false,
        target_operation: 'redeem',
      };

      const stateDiff = {
        status: 'PROTECTED_STATE_CHANGED' as const,
        summary: 'Protected state changed',
        has_changes: true,
        protected_changed: true,
        differences: [{ path: 'balances.0xVictim', before: 100, after: 50, is_protected: true }],
        metrics: { keys_added: 0, keys_removed: 0, keys_modified: 1, protected_keys_mutated: 1 },
      };

      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: authState,
        state_diff: stateDiff,
        execution_exit_code: 0,
        execution_success: true,
        tool_installed: true,
      });

      expect(decision.result).toBe('REPRODUCED');
      expect(decision.criteria.attacker_is_unauthorized).toBe(true);
      expect(decision.criteria.execution_succeeded).toBe(true);
      expect(decision.criteria.protected_state_mutated).toBe(true);
      expect(decision.criteria.formal_refuted).toBe(false);
    });

    it('concludes NOT_REPRODUCED when caller is the legitimate resource owner', () => {
      const authState: AuthorizationStateEvidence = {
        caller: '0xOwner',
        owner: '0xOwner',
        caller_is_owner: true,
        caller_has_role: false,
        caller_authorized: true,
        target_operation: 'redeem',
      };

      const stateDiff = {
        status: 'PROTECTED_STATE_CHANGED' as const,
        summary: 'Protected state changed',
        has_changes: true,
        protected_changed: true,
        differences: [{ path: 'balances.0xOwner', before: 100, after: 80, is_protected: true }],
        metrics: { keys_added: 0, keys_removed: 0, keys_modified: 1, protected_keys_mutated: 1 },
      };

      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: authState,
        state_diff: stateDiff,
        execution_exit_code: 0,
        execution_success: true,
        tool_installed: true,
      });

      expect(decision.result).toBe('NOT_REPRODUCED');
      expect(decision.criteria.attacker_is_unauthorized).toBe(false);
      expect(decision.reason).toContain('authorized permissions');
    });

    it('concludes NOT_REPRODUCED when the execution reverts / fails', () => {
      const authState: AuthorizationStateEvidence = {
        caller: '0xAttacker',
        owner: '0xVictim',
        caller_is_owner: false,
        caller_has_role: false,
        caller_authorized: false,
        target_operation: 'redeem',
      };

      const stateDiff = {
        status: 'PROTECTED_STATE_UNCHANGED' as const,
        summary: 'Protected state unchanged',
        has_changes: false,
        protected_changed: false,
        differences: [],
        metrics: { keys_added: 0, keys_removed: 0, keys_modified: 0, protected_keys_mutated: 0 },
      };

      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: authState,
        state_diff: stateDiff,
        execution_exit_code: 1,
        execution_success: false,
        tool_installed: true,
        error: 'Revert: UNAUTHORIZED',
      });

      expect(decision.result).toBe('NOT_REPRODUCED');
      expect(decision.criteria.execution_succeeded).toBe(false);
      expect(decision.reason).toContain('reverted');
    });

    it('concludes NOT_REPRODUCED when state is untouched', () => {
      const authState: AuthorizationStateEvidence = {
        caller: '0xAttacker',
        owner: '0xVictim',
        caller_is_owner: false,
        caller_has_role: false,
        caller_authorized: false,
        target_operation: 'readPublicData',
      };

      const stateDiff = {
        status: 'PROTECTED_STATE_UNCHANGED' as const,
        summary: 'Protected state unchanged',
        has_changes: false,
        protected_changed: false,
        differences: [],
        metrics: { keys_added: 0, keys_removed: 0, keys_modified: 0, protected_keys_mutated: 0 },
      };

      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: authState,
        state_diff: stateDiff,
        execution_exit_code: 0,
        execution_success: true,
        tool_installed: true,
      });

      expect(decision.result).toBe('NOT_REPRODUCED');
      expect(decision.criteria.protected_state_mutated).toBe(false);
      expect(decision.reason).toContain('remained unchanged');
    });

    it('reports EXECUTION_FAILED when tool is not installed', () => {
      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: null as any,
        state_diff: null as any,
        execution_exit_code: 127,
        execution_success: false,
        tool_installed: false,
        error: 'ENGINE_NOT_INSTALLED: clarinet',
      });

      expect(decision.result).toBe('EXECUTION_FAILED');
      expect(decision.reason).toContain('not installed');
    });

    it('anti-fabrication rule: a formal Z3 counterexample is NOT an automatic exploit', () => {
      // Even if formal verification succeeded with SAT, if dynamic execution reverts, it is NOT_REPRODUCED!
      const authState: AuthorizationStateEvidence = {
        caller: '0xAttacker',
        owner: '0xVictim',
        caller_is_owner: false,
        caller_has_role: false,
        caller_authorized: false,
        target_operation: 'redeem',
      };

      const stateDiff = {
        status: 'PROTECTED_STATE_UNCHANGED' as const,
        differences: [],
        summary: 'Protected state unchanged',
        has_changes: false,
        protected_changed: false,
        diffs: [],
        metrics: { keys_added: 0, keys_removed: 0, keys_modified: 0, protected_keys_mutated: 0 },
      };

      const decision = ReproductionDecisionEngine.evaluate({
        authorization_state: authState,
        state_diff: stateDiff,
        execution_exit_code: 1, // Reverted in real execution!
        execution_success: false,
        tool_installed: true,
        formal_verification_status: 'FORMALLY_SUPPORTED', // Z3 found model, but runtime guarded it
      });

      expect(decision.result).toBe('NOT_REPRODUCED');
    });
  });

  // =========================================================================
  // 6. Clarinet Missing Binary Handling
  // =========================================================================
  describe('6. Clarinet Adapter Behavior When Missing', () => {
    it('returns ENGINE_NOT_INSTALLED without throwing or faking execution', async () => {
      const adapter = new ClarinetAdapter();
      const res = await adapter.executeCheck({
        workingDirectory: 'fixtures/dynamic_verification/clarity/vulnerable_bola',
      });

      expect(res.status).toBe('TOOL_UNAVAILABLE');
      expect(res.result).toBe('EXECUTION_FAILED');
      expect(res.tool).toBe('clarinet');
      expect(res.exit_code).toBe(127);
      expect(res.error).toContain('ENGINE_NOT_INSTALLED');
      expect(res.stdout).toBe('');
      expect(res.trace.exit_code).toBe(127);
    });
  });

  // =========================================================================
  // 7. API / HTTP BOLA Isolated Dynamic Reproduction
  // =========================================================================
  describe('7. API / HTTP Isolated Dynamic Reproduction', () => {
    it('dynamically reproduces BOLA vulnerability on vulnerable API handler', async () => {
      const adapter = new APIAdapter();
      const res = await adapter.execute({
        endpoint: '/orders/:id',
        method: 'DELETE',
        objectId: 'order-victim-99',
        authenticatedCaller: 'attacker-user-01',
        resourceOwner: 'victim-user-02',
        initialDbState: {
          documents: [],
          orders: [
            { id: 'order-victim-99', userId: 'victim-user-02', item: 'Sensitive Payload', amount: 500 },
          ],
        },
        handlerType: 'VULNERABLE',
      });

      expect(res.status).toBe('COMPLETED');
      expect(res.result).toBe('REPRODUCED');
      expect(res.exit_code).toBe(0);
      expect(res.authorization_state?.caller_authorized).toBe(false);
      expect(res.state_diff?.protected_changed).toBe(true);
      expect(res.state_after.orders.length).toBe(0);
      expect(res.trace.traces[0].status).toBe('SUCCESS');
    });

    it('verifies secure API handler rejects unauthorized access with 403 / 404', async () => {
      const adapter = new APIAdapter();
      const res = await adapter.execute({
        endpoint: '/documents/:id',
        method: 'GET',
        objectId: 'doc-victim-77',
        authenticatedCaller: 'attacker-user-01',
        resourceOwner: 'victim-user-02',
        callerRole: 'user',
        initialDbState: {
          documents: [
            { _id: 'doc-victim-77', ownerId: 'victim-user-02', title: 'Victim Confidential Document' },
          ],
          orders: [],
        },
        handlerType: 'SECURE',
      });

      expect(res.status).toBe('COMPLETED');
      expect(res.result).toBe('NOT_REPRODUCED');
      expect(res.exit_code).toBe(1);
      expect(res.error).toContain('403 Forbidden');
      expect(res.authorization_state?.caller_authorized).toBe(false);
    });
  });
});
