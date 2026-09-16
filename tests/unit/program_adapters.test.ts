import { describe, it, expect } from 'vitest';
import {
  globalProgramAdapterRegistry,
  ImmunefiProgramAdapter,
  HackenProofProgramAdapter,
  CantinaProgramAdapter,
  HackerOneProgramAdapter,
  CustomProgramAdapter,
} from '../../adapters/programs/index.js';
import {
  BountyPlatform,
  ScopeInclusionStatus,
  ScopeAssetType,
} from '../../packages/core/src/index.js';

describe('Program Adapters (Multi-Platform Scope Ingestion & Normalization)', () => {
  it('registers all required security bounty platform adapters', () => {
    const platforms = globalProgramAdapterRegistry.list_supported_platforms();
    expect(platforms).toContain(BountyPlatform.IMMUNEFI);
    expect(platforms).toContain(BountyPlatform.HACKENPROOF);
    expect(platforms).toContain(BountyPlatform.CANTINA);
    expect(platforms).toContain(BountyPlatform.HACKERONE);
    expect(platforms).toContain(BountyPlatform.CUSTOM);
  });

  it('Immunefi adapter correctly normalizes GitHub repository and smart contract scope tables', () => {
    const adapter = globalProgramAdapterRegistry.get(BountyPlatform.IMMUNEFI);
    const rawScope = [
      {
        target: 'https://github.com/compound-finance/compound-protocol',
        type: 'smart_contract',
        in_scope: true,
      },
      {
        target: '0xc00e94Cb662C3520282E6f5717214004A7f26888',
        type: 'contract',
        in_scope: true,
        chain: 'ethereum',
      },
      {
        target: 'https://staging.compound.finance',
        type: 'web',
        in_scope: false,
        notes: 'Staging website out of scope',
      },
    ];

    const normalized = adapter.normalize_scope(rawScope, 'prog-compound');
    expect(normalized).toHaveLength(3);
    expect(normalized[0].asset_type).toBe(ScopeAssetType.REPOSITORY);
    expect(normalized[0].inclusion_status).toBe(ScopeInclusionStatus.IN_SCOPE);
    expect(normalized[1].asset_type).toBe(ScopeAssetType.SMART_CONTRACT);
    expect(normalized[2].inclusion_status).toBe(ScopeInclusionStatus.OUT_OF_SCOPE);
  });

  it('HackenProof adapter extracts exclusions and standardizes rules', () => {
    const adapter = globalProgramAdapterRegistry.get(BountyPlatform.HACKENPROOF);
    const rawExclusions = [
      'Denial of Service attacks',
      'Phishing or Social Engineering',
      'Automated scanner traffic without rate limiting',
    ];

    const extracted = adapter.extractExclusions(rawExclusions);
    expect(extracted).toHaveLength(3);
    expect(extracted[0]).toBe('Denial of Service attacks');
  });

  it('Cantina adapter normalizes competitive audit scope items', () => {
    const adapter = globalProgramAdapterRegistry.get(BountyPlatform.CANTINA);
    const rawScope = [
      {
        repository: 'https://github.com/solana-labs/solana-program-library',
        commit: '7b8f9e0123456789abcdef0123456789abcdef01',
      },
    ];

    const normalized = adapter.normalize_scope(rawScope, 'prog-solana-audit');
    expect(normalized).toHaveLength(1);
    expect(normalized[0].asset_type).toBe(ScopeAssetType.REPOSITORY);
    expect(normalized[0].asset_identifier).toBe('https://github.com/solana-labs/solana-program-library');
  });
});
