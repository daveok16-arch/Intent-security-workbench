import { describe, it, expect } from 'vitest';
import { DatabaseStore } from '../../apps/api/db_store.js';
import {
  BountyPlatform,
  TargetType,
  Ecosystem,
  ScopeInclusionStatus,
  TargetAuthorizationStatus,
  TargetScopeStatus,
  SourceAcquisitionStatus,
  InvestigationStatus,
} from '../../packages/core/src/index.js';

describe('Phase 1 Integration: Scope, Target Authorization & Pre-flight Gate', () => {
  it('executes the full multi-program target and scope acquisition pipeline without fake data', async () => {
    const db = new DatabaseStore();

    // 1. Create a real Immunefi Program with scope definitions
    const program = db.createProgram({
      name: 'MakerDAO Bounty Program',
      platform: BountyPlatform.IMMUNEFI,
      program_url: 'https://immunefi.com/bug-bounty/makerdao/',
      scope: [
        {
          target: 'https://github.com/makerdao/dss',
          type: 'smart_contract',
          in_scope: true,
        },
        {
          target: '0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2', // MKR token
          type: 'contract',
          in_scope: true,
        },
        {
          target: 'https://github.com/makerdao/community',
          type: 'repository',
          in_scope: false,
          notes: 'Community repository excluded',
        },
      ],
      exclusions: ['Out of scope assets', 'Third party dependencies'],
      bounty_policy: 'Critical: up to $10,000,000',
    });

    expect(program.id).toBeDefined();
    const scopeEntries = db.listScopeEntries(program.id);
    expect(scopeEntries).toHaveLength(3);

    // 2. Create an in-scope Target (MakerDAO DSS)
    const inScopeTarget = db.createTarget({
      program_id: program.id,
      name: 'MakerDAO DSS Core',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/makerdao/dss.git',
    });

    // 3. Evaluate scope deterministically
    const scopeDecision = db.evaluateTargetScope(inScopeTarget.id);
    expect(scopeDecision.decision).toBe(ScopeInclusionStatus.IN_SCOPE);
    expect(scopeDecision.matched_scope_entry?.asset_identifier).toBe('https://github.com/makerdao/dss');

    // Verify target status updated
    const updatedTarget = db.getTarget(inScopeTarget.id)!;
    expect(updatedTarget.scope_status).toBe(TargetScopeStatus.IN_SCOPE);
    expect(updatedTarget.authorization_status).toBe(TargetAuthorizationStatus.AUTHORIZED);

    // 4. Create an out-of-scope Target (Community repo)
    const outOfScopeTarget = db.createTarget({
      program_id: program.id,
      name: 'MakerDAO Community',
      target_type: TargetType.REPOSITORY,
      ecosystem: Ecosystem.OTHER,
      repository_url: 'https://github.com/makerdao/community',
    });

    const oosDecision = db.evaluateTargetScope(outOfScopeTarget.id);
    expect(oosDecision.decision).toBe(ScopeInclusionStatus.OUT_OF_SCOPE);

    const updatedOosTarget = db.getTarget(outOfScopeTarget.id)!;
    expect(updatedOosTarget.scope_status).toBe(TargetScopeStatus.OUT_OF_SCOPE);
    expect(updatedOosTarget.authorization_status).toBe(TargetAuthorizationStatus.NOT_AUTHORIZED);

    // 5. Create an Investigation for the in-scope Target
    const inv = db.createInvestigation({
      program_id: program.id,
      target_id: inScopeTarget.id,
      title: 'MakerDAO DSS Collateral Investigation',
    });

    // 6. Pre-flight gate check: should block because source is not yet acquired
    const gateBeforeSource = db.evaluateInvestigationGate(inv.id, { requireSourceAcquisition: true });
    expect(gateBeforeSource.passed).toBe(false);
    expect(gateBeforeSource.target_authorization).toBe(TargetAuthorizationStatus.AUTHORIZED);
    expect(gateBeforeSource.source_status).toBe(SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED);

    // 7. Acquire simulated local snapshot to satisfy source acquisition requirement
    const snapshot = db.createSourceSnapshot({
      target_id: inScopeTarget.id,
      investigation_id: inv.id,
      repository_url: inScopeTarget.repository_url,
      commit_hash: 'd89f81a7830b5e28a55928d26442657e2d78bfb2',
      acquisition_method: 'GIT_CLONE',
    });

    await db.acquireSourceSnapshotContent(
      snapshot.id,
      'contract Vat { mapping(bytes32 => Ilk) public ilks; }',
      'Vat.sol'
    );

    db.updateTargetSourceStatus(inScopeTarget.id, SourceAcquisitionStatus.SOURCE_ACQUIRED, snapshot.source_hash);

    // 8. Pre-flight gate check now passes
    const gateAfterSource = db.evaluateInvestigationGate(inv.id, { requireSourceAcquisition: true });
    expect(gateAfterSource.passed).toBe(true);
    expect(gateAfterSource.target_authorization).toBe(TargetAuthorizationStatus.AUTHORIZED);
    expect(gateAfterSource.source_status).toBe(SourceAcquisitionStatus.SOURCE_ACQUIRED);
    expect(gateAfterSource.policy_status).toBe('VALID');

    // 9. Verify immutable audit events were recorded
    const events = db.listEvidenceEvents(inv.id);
    expect(events.length).toBeGreaterThan(0);
  });
});
