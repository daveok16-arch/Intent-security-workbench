import { describe, it, expect } from 'vitest';
import { SourceAcquisitionStatus, TargetType, Ecosystem } from '../../packages/core/src/index.js';
import { DatabaseStore } from '../../apps/api/db_store.js';

describe('Source Snapshot & Target Verification (Phase 0 Requirement 10 & 11)', () => {
  it('should initialize targets in SOURCE_NOT_ACQUIRED state by default', () => {
    const db = new DatabaseStore();
    const prog = db.createProgram({
      name: 'Immunefi Bounty 01',
      platform: 'IMMUNEFI' as any,
      external_identifier: 'immunefi-01',
      scope: ['0x123...'],
      exclusions: [],
      bounty_policy: '',
      disclosure_policy: '',
      technology: ['Solidity'],
      metadata: {},
    });

    const target = db.createTarget({
      program_id: prog.id,
      name: 'VaultStaking',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.EVM,
      repository_url: 'https://github.com/example/vault',
      deployment_information: { address: '0x1234567890abcdef' },
      metadata: {},
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED,
    });

    expect(target.source_acquisition_status).toBe(SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED);
    expect(target.source_hash).toBeUndefined();
  });

  it('should record real source acquisition status transition and hash', () => {
    const db = new DatabaseStore();
    const prog = db.createProgram({
      name: 'Cantina Audit Scope',
      platform: 'CANTINA' as any,
      external_identifier: 'cantina-01',
      scope: ['src/'],
      exclusions: [],
      bounty_policy: '',
      disclosure_policy: '',
      technology: ['Rust'],
      metadata: {},
    });

    const target = db.createTarget({
      program_id: prog.id,
      name: 'SolanaDEX',
      target_type: TargetType.SMART_CONTRACT,
      ecosystem: Ecosystem.SOLANA_RUST,
      repository_url: 'https://github.com/example/solana-dex',
      commit_hash: 'c0ffee1234567890abcdef',
      deployment_information: {},
      metadata: {},
      source_acquisition_status: SourceAcquisitionStatus.SOURCE_NOT_ACQUIRED,
    });

    const updated = db.updateTargetSourceStatus(
      target.id,
      SourceAcquisitionStatus.SOURCE_ACQUIRED,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );

    expect(updated.source_acquisition_status).toBe(SourceAcquisitionStatus.SOURCE_ACQUIRED);
    expect(updated.source_hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});
