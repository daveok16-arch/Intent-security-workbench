/**
 * Regression tests for mass assignment on the authorization-critical fields.
 *
 * Background: `updateTarget` spread the caller's body into the stored record,
 * and `PATCH /api/targets/:id` passed `req.body` through unfiltered. A single
 * unauthenticated request could set `authorization_status`, `scope_status` and
 * `source_acquisition_status`, which are exactly the fields the investigation
 * pre-flight gate reads. That let a caller declare an out-of-scope production
 * asset AUTHORIZED and then proceed. `POST /api/targets` had the same problem:
 * it forwarded `source_acquisition_status` and `source_hash` at creation.
 */

import { describe, it, expect } from 'vitest';
import {
  DatabaseStore,
  sanitizeTargetWrite,
  sanitizeProgramWrite,
} from '../../apps/api/db_store.js';
import {
  TargetAuthorizationStatus,
  TargetScopeStatus,
  SourceAcquisitionStatus,
  Ecosystem,
  TargetType,
  InvestigationGateService,
} from '../../packages/core/src/index.js';

function store() {
  const db = new DatabaseStore();
  const program = db.createProgram({ name: 'p', platform: 'CUSTOM' as any });
  return { db, program };
}

describe('Target authorization fields are server-controlled', () => {
  it('ignores authorization fields supplied at creation time', () => {
    const { db, program } = store();
    const target = db.createTarget({
      program_id: program.id,
      name: 'production-asset',
      target_type: TargetType.REPOSITORY,
      ecosystem: Ecosystem.WEB_API,
      repository_url: 'https://github.com/someone/out-of-scope',
      // Hostile claims that must not stick.
      authorization_status: TargetAuthorizationStatus.AUTHORIZED,
      scope_status: TargetScopeStatus.IN_SCOPE,
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
      source_hash: 'deadbeef',
    } as any);

    expect(target.authorization_status).toBe(TargetAuthorizationStatus.NOT_EVALUATED);
    expect(target.scope_status).toBe(TargetScopeStatus.NOT_EVALUATED);
    expect(target.source_acquisition_status).toBe(SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED);
    expect(target.source_hash).toBeUndefined();
  });

  it('rejects a direct updateTarget that tries to set authorization fields', () => {
    const { db, program } = store();
    const t = db.createTarget({
      program_id: program.id, name: 't',
      target_type: TargetType.REPOSITORY, ecosystem: Ecosystem.WEB_API,
    });

    expect(() =>
      db.updateTarget(t.id, { authorization_status: TargetAuthorizationStatus.AUTHORIZED } as any)
    ).toThrow(/server-controlled target field/i);
    expect(() =>
      db.updateTarget(t.id, { scope_status: TargetScopeStatus.IN_SCOPE } as any)
    ).toThrow(/server-controlled target field/i);
    expect(() =>
      db.updateTarget(t.id, { source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED } as any)
    ).toThrow(/server-controlled target field/i);
    expect(() => db.updateTarget(t.id, { source_hash: 'forged' } as any))
      .toThrow(/server-controlled target field/i);

    // Nothing changed.
    expect(db.getTarget(t.id)!.authorization_status).toBe(TargetAuthorizationStatus.NOT_EVALUATED);
  });

  it('strips authorization fields but allows benign edits', () => {
    const { value, rejected } = sanitizeTargetWrite({
      name: 'renamed',
      commit_hash: 'abc123',
      authorization_status: 'AUTHORIZED',
      scope_status: 'IN_SCOPE',
      source_acquisition_status: 'SOURCE_ACQUIRED',
      source_hash: 'deadbeef',
      id: 'tgt-hijack',
    });

    expect(value).toEqual({ name: 'renamed', commit_hash: 'abc123' });
    expect(rejected.sort()).toEqual([
      'authorization_status', 'id', 'scope_status',
      'source_acquisition_status', 'source_hash',
    ]);
  });

  it('keeps the pre-flight gate honest for a target that was never authorized', () => {
    const { db, program } = store();
    const t = db.createTarget({
      program_id: program.id, name: 'unauthorized',
      target_type: TargetType.REPOSITORY, ecosystem: Ecosystem.WEB_API,
    });

    // Simulate the pre-fix attack: the caller's body is filtered, so the
    // dangerous keys never reach the record.
    const { value } = sanitizeTargetWrite({
      authorization_status: 'AUTHORIZED',
      scope_status: 'IN_SCOPE',
      source_acquisition_status: 'SOURCE_ACQUIRED',
    });
    db.updateTarget(t.id, value as any);

    const persisted = db.getTarget(t.id)!;
    const gate = InvestigationGateService.evaluateGate({
      program,
      target: persisted,
      requireSourceAcquisition: false,
      strictFreshness: false,
    });
    expect(gate.allowed).toBe(false);
    expect(persisted.authorization_status).not.toBe(TargetAuthorizationStatus.AUTHORIZED);
  });

  it('still lets the legitimate scope transition authorize an in-scope target', () => {
    const { db, program } = store();
    db.createScopeEntry({
      program_id: program.id,
      asset_type: 'REPOSITORY' as any,
      asset_identifier: 'https://github.com/real/in-scope',
      inclusion_status: 'IN_SCOPE' as any,
    });
    const t = db.createTarget({
      program_id: program.id, name: 'in-scope',
      target_type: TargetType.REPOSITORY, ecosystem: Ecosystem.WEB_API,
      repository_url: 'https://github.com/real/in-scope',
    });

    db.evaluateTargetScope(t.id);

    const after = db.getTarget(t.id)!;
    expect(after.authorization_status).toBe(TargetAuthorizationStatus.AUTHORIZED);
    expect(after.scope_status).toBe(TargetScopeStatus.IN_SCOPE);
  });
});

describe('Program status fields are server-controlled', () => {
  it('rejects a direct updateProgram that tries to set status or freshness', () => {
    const { db, program } = store();
    expect(() => db.updateProgram(program.id, { status: 'ACTIVE' } as any))
      .toThrow(/server-controlled program field/i);
    expect(() => db.updateProgram(program.id, { freshness_status: 'CURRENT' } as any))
      .toThrow(/server-controlled program field/i);
  });

  it('strips status fields but allows benign program edits', () => {
    const { value, rejected } = sanitizeProgramWrite({
      name: 'renamed program',
      bounty_policy: 'updated',
      status: 'ACTIVE',
      freshness_status: 'CURRENT',
      id: 'prog-hijack',
    });
    expect(value).toEqual({ name: 'renamed program', bounty_policy: 'updated' });
    expect(rejected.sort()).toEqual(['freshness_status', 'id', 'status']);
  });
});