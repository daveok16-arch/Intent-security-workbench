import { describe, it, expect } from 'vitest';
import {
  InvestigationGateService,
  Program,
  Target,
  ProgramStatus,
  ProgramFreshnessStatus,
  BountyPlatform,
  TargetType,
  Ecosystem,
  TargetAuthorizationStatus,
  TargetScopeStatus,
  SourceAcquisitionStatus,
} from '../../packages/core/src/index.js';

describe('InvestigationGateService (Pre-flight Authorization & Scope Enforcement)', () => {
  const validProgram: Program = {
    id: 'prog-aave',
    name: 'Aave Protocol Bounty',
    platform: BountyPlatform.IMMUNEFI,
    status: ProgramStatus.ACTIVE,
    policy_version: '3.0.0',
    freshness_status: ProgramFreshnessStatus.CURRENT,
    scope: [],
    exclusions: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const validTarget: Target = {
    id: 'tgt-aave-pool',
    program_id: 'prog-aave',
    name: 'Aave V3 Pool',
    target_type: TargetType.SMART_CONTRACT,
    ecosystem: Ecosystem.EVM,
    repository_url: 'https://github.com/aave/aave-v3-core',
    commit_hash: 'a1b2c3d4e5f67890123456789abcdef012345678',
    source_hash: '3e25960a79dbc69b674cd4ec67a72c62',
    authorization_status: TargetAuthorizationStatus.AUTHORIZED,
    scope_status: TargetScopeStatus.IN_SCOPE,
    source_acquisition_status: SourceAcquisitionStatus.SOURCE_ACQUIRED,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  it('passes all pre-flight checks when program is active, target is authorized and source is acquired', () => {
    const result = InvestigationGateService.evaluateGate({
      program: validProgram,
      target: validTarget,
      requireSourceAcquisition: true,
      strictFreshness: true,
    });

    expect(result.passed).toBe(true);
    expect(result.target_authorization).toBe(TargetAuthorizationStatus.AUTHORIZED);
    expect(result.scope_status).toBe(TargetScopeStatus.IN_SCOPE);
    expect(result.source_status).toBe(SourceAcquisitionStatus.SOURCE_ACQUIRED);
    expect(result.checks.every(c => c.passed)).toBe(true);
  });

  it('blocks investigation when target authorization is UNKNOWN or NOT_AUTHORIZED', () => {
    const unauthorizedTarget: Target = {
      ...validTarget,
      authorization_status: TargetAuthorizationStatus.NOT_AUTHORIZED,
      scope_status: TargetScopeStatus.OUT_OF_SCOPE,
    };

    const result = InvestigationGateService.evaluateGate({
      program: validProgram,
      target: unauthorizedTarget,
    });

    expect(result.passed).toBe(false);
    const authCheck = result.checks.find(c => c.name === 'Target Authorization');
    expect(authCheck?.passed).toBe(false);
    expect(authCheck?.message).toContain('NOT_AUTHORIZED');
  });

  it('blocks investigation when source code is not yet acquired', () => {
    const unacquiredTarget: Target = {
      ...validTarget,
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED,
    };

    const result = InvestigationGateService.evaluateGate({
      program: validProgram,
      target: unacquiredTarget,
      requireSourceAcquisition: true,
    });

    expect(result.passed).toBe(false);
    const sourceCheck = result.checks.find(c => c.name === 'Source Code Acquisition');
    expect(sourceCheck?.passed).toBe(false);
  });

  it('blocks investigation when security program policy is STALE or EXPIRED under strict freshness', () => {
    const staleProgram: Program = {
      ...validProgram,
      freshness_status: ProgramFreshnessStatus.EXPIRED,
    };

    const result = InvestigationGateService.evaluateGate({
      program: staleProgram,
      target: validTarget,
      strictFreshness: true,
    });

    expect(result.passed).toBe(false);
    const freshnessCheck = result.checks.find(c => c.name === 'Program Policy Freshness');
    expect(freshnessCheck?.passed).toBe(false);
    expect(freshnessCheck?.message).toContain('EXPIRED');
  });
});
