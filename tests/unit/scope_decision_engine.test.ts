import { describe, it, expect } from 'vitest';
import {
  ScopeDecisionService,
  Program,
  Target,
  ScopeEntry,
  ScopeInclusionStatus,
  ScopeAssetType,
  BountyPlatform,
  ProgramStatus,
  ProgramFreshnessStatus,
  TargetType,
  Ecosystem,
  TargetAuthorizationStatus,
  TargetScopeStatus,
} from '../../packages/core/src/index.js';

describe('ScopeDecisionService (Phase 1 Target & Scope Subsystem)', () => {
  const baseProgram: Program = {
    id: 'prog-uniswap',
    name: 'Uniswap Bug Bounty',
    platform: BountyPlatform.IMMUNEFI,
    status: ProgramStatus.ACTIVE,
    policy_version: '2.1.0',
    freshness_status: ProgramFreshnessStatus.CURRENT,
    scope: [],
    exclusions: [],
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  it('matches exact GitHub repository URLs regardless of trailing slashes or .git suffix', () => {
    const scopeEntries: ScopeEntry[] = [
      {
        id: 'scope-1',
        program_id: 'prog-uniswap',
        asset_type: ScopeAssetType.REPOSITORY,
        asset_identifier: 'https://github.com/Uniswap/v3-core',
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const target: Target = {
      id: 'tgt-1',
      program_id: 'prog-uniswap',
      name: 'Uniswap V3 Core',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'git@github.com:Uniswap/v3-core.git',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = ScopeDecisionService.evaluate({
      program: baseProgram,
      target,
      scopeEntries,
    });

    expect(result.decision).toBe(ScopeInclusionStatus.IN_SCOPE);
    expect(result.matched_scope_entry?.id).toBe('scope-1');
    expect(result.policy_version).toBe('2.1.0');
  });

  it('matches EVM addresses case-insensitively', () => {
    const scopeEntries: ScopeEntry[] = [
      {
        id: 'scope-eth-1',
        program_id: 'prog-uniswap',
        asset_type: ScopeAssetType.SMART_CONTRACT,
        asset_identifier: '0x1f9840a85d5af5bf1d1762f925bdaddc4201f984', // lowercase
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const target: Target = {
      id: 'tgt-uni-token',
      program_id: 'prog-uniswap',
      name: 'UNI Token Contract',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      contract_address: '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984', // Checksum mixed case
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = ScopeDecisionService.evaluate({
      program: baseProgram,
      target,
      scopeEntries,
    });

    expect(result.decision).toBe(ScopeInclusionStatus.IN_SCOPE);
    expect(result.matched_scope_entry?.id).toBe('scope-eth-1');
  });

  it('prioritizes explicit OUT_OF_SCOPE over general matching (Precedence Rule)', () => {
    const scopeEntries: ScopeEntry[] = [
      {
        id: 'scope-in-repo',
        program_id: 'prog-uniswap',
        asset_type: ScopeAssetType.REPOSITORY,
        asset_identifier: 'https://github.com/Uniswap/v3-periphery',
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        id: 'scope-out-mock',
        program_id: 'prog-uniswap',
        asset_type: ScopeAssetType.SMART_CONTRACT,
        asset_identifier: '0x0000000000000000000000000000000000000001',
        inclusion_status: ScopeInclusionStatus.OUT_OF_SCOPE,
        notes: 'Mock contract explicitly excluded',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const target: Target = {
      id: 'tgt-excluded',
      program_id: 'prog-uniswap',
      name: 'Mock Periphery',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/Uniswap/v3-periphery',
      contract_address: '0x0000000000000000000000000000000000000001',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = ScopeDecisionService.evaluate({
      program: baseProgram,
      target,
      scopeEntries,
    });

    expect(result.decision).toBe(ScopeInclusionStatus.OUT_OF_SCOPE);
    expect(result.matched_scope_entry?.id).toBe('scope-out-mock');
  });

  it('returns UNKNOWN when an asset is not registered in the scope entries (Safety Rule: UNKNOWN != IN_SCOPE)', () => {
    const scopeEntries: ScopeEntry[] = [
      {
        id: 'scope-1',
        program_id: 'prog-uniswap',
        asset_type: ScopeAssetType.REPOSITORY,
        asset_identifier: 'https://github.com/Uniswap/v3-core',
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const target: Target = {
      id: 'tgt-unrelated',
      program_id: 'prog-uniswap',
      name: 'Unrelated Project',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/OtherOrg/other-repo',
      contract_address: '0x9999999999999999999999999999999999999999',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = ScopeDecisionService.evaluate({
      program: baseProgram,
      target,
      scopeEntries,
    });

    expect(result.decision).toBe(ScopeInclusionStatus.UNKNOWN);
    expect(result.matched_scope_entry).toBeNull();
    expect(result.reason).toContain('Target asset does not match any documented scope rule');
  });

  it('rejects targets associated with SUSPENDED or ARCHIVED programs', () => {
    const suspendedProgram: Program = {
      ...baseProgram,
      status: ProgramStatus.SUSPENDED,
    };

    const scopeEntries: ScopeEntry[] = [
      {
        id: 'scope-1',
        program_id: suspendedProgram.id,
        asset_type: ScopeAssetType.REPOSITORY,
        asset_identifier: 'https://github.com/Uniswap/v3-core',
        inclusion_status: ScopeInclusionStatus.IN_SCOPE,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const target: Target = {
      id: 'tgt-1',
      program_id: suspendedProgram.id,
      name: 'Uniswap V3 Core',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/Uniswap/v3-core',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const result = ScopeDecisionService.evaluate({
      program: suspendedProgram,
      target,
      scopeEntries,
    });

    expect(result.decision).toBe(ScopeInclusionStatus.OUT_OF_SCOPE);
    expect(result.reason).toContain('Program is not in ACTIVE state');
  });
});
