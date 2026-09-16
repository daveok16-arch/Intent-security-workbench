/**
 * Phase 5 — Real Dynamic Verification & Exploit-Witness Integration Tests
 *
 * Requirements:
 * 1. Execute actual Foundry tests against real vulnerable and secure EVM fixtures.
 * 2. Verify state differentials (victim balance decremented, attacker balance incremented in vulnerable fixture).
 * 3. Verify that secure fixture execution reverts and results in NOT_REPRODUCED.
 * 4. Verify that DynamicVerificationService executes jobs via JobOrchestrator and persists
 *    immutable evidence artifacts (STDOUT, STDERR, EXECUTION_TRACE, STATE_BEFORE, STATE_AFTER) with SHA-256.
 * 5. Verify that provenance graphs are updated with nodes and edges.
 * 6. Verify that candidate findings transition safely to CORROBORATED without skipping to CONFIRMED.
 * 7. Verify that Clarinet reports ENGINE_NOT_INSTALLED cleanly without faking.
 * 8. Verify API and isolated HTTP/API-based BOLA reproduction.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import path from 'path';
import fs from 'fs';
import {
  ToolDetector,
  FoundryAdapter,
  ClarinetAdapter,
  APIAdapter,
  DynamicVerificationService,
  TargetValidator,
} from '../../packages/dynamic-verification/src/index.js';
import { globalDB, DatabaseStore } from '../../apps/api/db_store.js';
import {
  globalEvidenceEventManager,
  globalProvenanceService,
} from '../../packages/evidence/src/index.js';
import {
  ArtifactType,
  EvidenceEventType,
  FindingStatus,
  JobStatus,
  Severity,
  Confidence,
  BountyPlatform,
  TargetType,
  Ecosystem,
  InvestigationStatus,
} from '../../packages/core/src/index.js';

describe('Phase 5 — Dynamic Verification & Exploit-Witness Integration Suite', () => {
  const vulnerableFixtureDir = path.resolve('fixtures/dynamic_verification/evm/vulnerable_bola');
  const secureFixtureDir = path.resolve('fixtures/dynamic_verification/evm/secure_bola');

  // =========================================================================
  // 1. Real Foundry Execution on Vulnerable EVM BOLA Fixture
  // =========================================================================
  describe('1. Real Foundry Execution on Vulnerable EVM BOLA Fixture', () => {
    it('executes real forge test, observes balance theft, and confirms REPRODUCED verdict', async () => {
      const adapter = new FoundryAdapter();
      const executionResult = await adapter.executeTest({
        workingDirectory: vulnerableFixtureDir,
        testFilter: 'testExploitBOLA',
      });

      expect(executionResult.status).toBe('COMPLETED');
      expect(executionResult.exit_code).toBe(0);
      expect(executionResult.tool).toBe('forge');
      expect(executionResult.tool_version).toBeTruthy();
      expect(executionResult.stdout).toContain('testExploitBOLA');
      expect(executionResult.stdout).toContain('PASS');

      // Check state differential:
      // In VaultVulnerable, victim had 5 ether, attacker stole 2 ether.
      // Final state: victim = 3 ether, attacker = 2 ether.
      expect(executionResult.state_before).toBeDefined();
      expect(executionResult.state_after).toBeDefined();
      expect(executionResult.state_before?.balances?.victim).toBe(5);
      expect(executionResult.state_before?.balances?.attacker).toBe(0);
      expect(executionResult.state_after?.balances?.victim).toBe(3);
      expect(executionResult.state_after?.balances?.attacker).toBe(2);

      // Verify state diff
      expect(executionResult.state_diff).toBeDefined();
      expect(executionResult.state_diff?.has_changes).toBe(true);
      expect(executionResult.state_diff?.protected_changed).toBe(true);

      // Verify traces and gas metrics
      expect(executionResult.trace.traces.length).toBeGreaterThan(0);
      const exploitTrace = executionResult.trace.traces.find((t) => t.function_name === 'testExploitBOLA');
      expect(exploitTrace).toBeDefined();
      expect(exploitTrace?.status).toBe('SUCCESS');
      expect(exploitTrace?.gas_used).toBeGreaterThan(0);

      // Deterministic reproduction verdict
      expect(executionResult.result).toBe('REPRODUCED');
      expect(executionResult.failure_reason).toBeNull();
    });
  });

  // =========================================================================
  // 2. Real Foundry Execution on Secure EVM Baseline Fixture
  // =========================================================================
  describe('2. Real Foundry Execution on Secure EVM Baseline Fixture', () => {
    it('executes real forge test on secure vault, confirms revert on unauthorized access, and yields NOT_REPRODUCED', async () => {
      const adapter = new FoundryAdapter();
      const executionResult = await adapter.executeTest({
        workingDirectory: secureFixtureDir,
        testFilter: 'testUnauthorizedWithdrawReverts',
      });

      expect(executionResult.status).toBe('COMPLETED');
      expect(executionResult.exit_code).toBe(0);
      expect(executionResult.stdout).toContain('testUnauthorizedWithdrawReverts');
      expect(executionResult.stdout).toContain('PASS');

      // Check state before and after: victim balance remains exactly 5 ether
      expect(executionResult.state_before?.balances?.victim).toBe(5);
      expect(executionResult.state_after?.balances?.victim).toBe(5);
      expect(executionResult.state_after?.balances?.attacker).toBe(0);

      // Verdict must be NOT_REPRODUCED because unauthorized exploit was prevented
      expect(executionResult.result).toBe('NOT_REPRODUCED');
    });
  });

  // =========================================================================
  // 3. DynamicVerificationService End-to-End Orchestration & Evidence Chain
  // =========================================================================
  describe('3. DynamicVerificationService End-to-End Orchestration', () => {
    it('runs dynamic verification through service, creates immutable artifacts, and updates provenance', async () => {
      const service = new DynamicVerificationService();

      // Seed program, target, investigation, and candidate in globalDB
      const program = globalDB.createProgram({
        name: 'DeFi Security Program',
        platform: BountyPlatform.IMMUNEFI,
        program_url: 'https://immunefi.com/bug-bounty/defi/',
        scope: [{ target: 'https://github.com/defi/vault', type: 'smart_contract', in_scope: true }],
      });

      const target = globalDB.createTarget({
        program_id: program.id,
        name: 'Vault Contract',
        type: TargetType.SMART_CONTRACT,
        ecosystem: Ecosystem.ETHEREUM,
        primary_location: vulnerableFixtureDir,
      });

      const investigation = globalDB.createInvestigation({
        name: 'BOLA Investigation in Vault Contract',
        target_id: target.id,
      });

      const candidate = globalDB.createFinding({
        investigation_id: investigation.id,
        rule_id: 'RULE_EVM_BOLA_UNGUARDED_CALL',
        title: 'Broken Object Level Authorization in VaultVulnerable.redeem',
        description: 'Caller parameter controls target user balance without ownership validation',
        severity: Severity.HIGH,
        confidence: Confidence.HIGH,
        location: {
          file_path: 'src/VaultVulnerable.sol',
          start_line: 28,
          end_line: 35,
        },
      });

      expect(candidate.status).toBe(FindingStatus.CANDIDATE);

      // Execute dynamic verification via service
      const job = await service.startDynamicVerification({
        investigation_id: investigation.id,
        candidate_id: candidate.id,
        runtime: 'EVM',
        environment: 'LOCAL_SOURCE',
        working_directory: vulnerableFixtureDir,
        test_filter: 'testExploitBOLA',
      });

      expect(job).toBeDefined();
      expect(job.id).toBeTruthy();
      expect(job.status).toBe('COMPLETED');
      expect(job.result).toBe('REPRODUCED');
      expect(job.exit_code).toBe(0);

      // Verify immutable evidence artifacts
      expect(job.stdout_artifact_id).toBeTruthy();
      expect(job.execution_trace_artifact_id).toBeTruthy();
      expect(job.state_before_artifact_id).toBeTruthy();
      expect(job.state_after_artifact_id).toBeTruthy();

      const stdoutArtifact = globalDB.evidence.get(job.stdout_artifact_id!);
      expect(stdoutArtifact).toBeDefined();
      expect(stdoutArtifact?.type).toBe(ArtifactType.LOG_FILE);
      expect(stdoutArtifact?.sha256).toBeTruthy();

      const traceArtifact = globalDB.evidence.get(job.execution_trace_artifact_id!);
      expect(traceArtifact).toBeDefined();
      expect(traceArtifact?.type).toBe(ArtifactType.EXECUTION_TRACE);
      expect(traceArtifact?.sha256).toBeTruthy();

      // Verify finding status transition:
      // Promoted safely to CORROBORATED, never blindly to CONFIRMED
      const updatedCandidate = globalDB.getFinding(candidate.id);
      expect(updatedCandidate).toBeDefined();
      expect(updatedCandidate?.status).toBe(FindingStatus.CORROBORATED);
      expect(updatedCandidate?.status).not.toBe(FindingStatus.CONFIRMED);

      // Verify provenance graph links
      const graph = globalProvenanceService.getGraph();
      expect(graph.nodes.has(`dynamic-job-${job.id}`)).toBe(true);
      expect(graph.nodes.has(`finding-${candidate.id}`)).toBe(true);
      expect(graph.nodes.has(`artifact-${job.stdout_artifact_id}`)).toBe(true);
    });
  });

  // =========================================================================
  // 4. Boundary Protection: Rejection of Unauthorized Remote Targets
  // =========================================================================
  describe('4. Boundary Protection & Production Target Rejection', () => {
    it('immediately rejects dynamic verification against public web targets', async () => {
      const service = new DynamicVerificationService();

      await expect(
        service.startDynamicVerification({
          investigation_id: 'inv-test-boundary',
          target_url: 'https://mainnet.infura.io/v3/secret',
          environment: 'LOCAL_SOURCE',
          runtime: 'EVM',
        })
      ).rejects.toThrow(/UNAUTHORIZED_PRODUCTION_TARGET/);
    });
  });

  // =========================================================================
  // 5. Honest Clarinet Missing Binary Handling in Service
  // =========================================================================
  describe('5. Clarinet Tool Missing Handling in Service', () => {
    it('returns TOOL_UNAVAILABLE with ENGINE_NOT_INSTALLED when Clarinet is missing', async () => {
      const clarinet = ToolDetector.detectClarinet();
      if (clarinet.installed) {
        // Clarinet is present on this host, so the missing-binary path cannot be
        // exercised. The invariant under test is that a missing tool is reported
        // honestly, which the unit tests cover against a pinned absent path.
        return;
      }

      const service = new DynamicVerificationService();

      const job = await service.startDynamicVerification({
        investigation_id: 'inv-clarity-test',
        runtime: 'CLARITY',
        environment: 'LOCAL_SOURCE',
        working_directory: 'fixtures/dynamic_verification/clarity/vulnerable_bola',
      });

      expect(job.status).toBe('TOOL_UNAVAILABLE');
      expect(job.result).toBe('EXECUTION_FAILED');
      expect(job.failure_reason).toContain('ENGINE_NOT_INSTALLED');
      expect(job.exit_code).toBe(127);
    });
  });

  // =========================================================================
  // 6. Isolated API / HTTP Dynamic Reproduction
  // =========================================================================
  describe('6. API / HTTP Isolated Dynamic Reproduction', () => {
    it('verifies dynamic reproduction on API BOLA endpoint with state differential', async () => {
      const service = new DynamicVerificationService();

      const job = await service.startDynamicVerification({
        investigation_id: 'inv-api-test',
        runtime: 'HTTP',
        environment: 'LOCAL_SOURCE',
        endpoint: '/api/v1/orders/:id',
        method: 'DELETE',
        objectId: 'order-101',
        authenticatedCaller: 'user-attacker',
        resourceOwner: 'user-victim',
        initialDbState: {
          orders: [{ id: 'order-101', userId: 'user-victim', item: 'Secret Vault Key' }],
          documents: [],
        },
        handlerType: 'VULNERABLE',
      });

      expect(job.status).toBe('COMPLETED');
      expect(job.result).toBe('REPRODUCED');
      expect(job.state_diff?.protected_changed).toBe(true);
      expect(job.state_after?.orders).toHaveLength(0);
    });
  });
});
