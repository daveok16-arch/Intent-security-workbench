/**
 * Program Adapter Contracts for Intent Security Workbench
 * Phase 1 Scope & Target Authorization Subsystem
 * 
 * Supports modular multi-program integration without hardcoding any single platform.
 * Immunefi, HackenProof, Cantina, HackerOne, and Custom adapters.
 */

import {
  BountyPlatform,
  Program,
  ScopeEntry,
  ScopeInclusionStatus,
  ScopeAssetType,
  ProgramStatus,
} from '../../packages/core/src/index.js';

export interface IProgramAdapter {
  readonly platform: BountyPlatform;
  platform_name(): BountyPlatform;
  validate_program(program: Partial<Program>): { valid: boolean; errors: string[] };
  validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] };
  fetch_program_metadata(identifier: string): Promise<{ supported: boolean; data?: Partial<Program>; error?: string }>;
  fetch_scope(identifier: string): Promise<{ supported: boolean; scope?: ScopeEntry[]; error?: string }>;
  normalize_scope(rawScope: any[], programId?: string): ScopeEntry[];
  normalizeScope(rawScope: string[]): string[];
  normalizePolicy(rawPolicy: string): string;
  extractExclusions(rawExclusions: string[]): string[];
  get_policy(identifier: string): Promise<string>;
  get_last_updated(identifier: string): Promise<string | null>;
  is_live_fetch_supported(): boolean;
}

export abstract class BaseProgramAdapter implements IProgramAdapter {
  abstract readonly platform: BountyPlatform;

  public platform_name(): BountyPlatform {
    return this.platform;
  }

  public validate_program(program: Partial<Program>): { valid: boolean; errors: string[] } {
    return this.validateProgram(program);
  }

  public validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    return { valid: errors.length === 0, errors };
  }

  public async fetch_program_metadata(identifier: string): Promise<{ supported: boolean; data?: Partial<Program>; error?: string }> {
    return {
      supported: false,
      error: `Live metadata fetching from platform ${this.platform} is unavailable without direct API credentials. Researcher must supply verified program specification.`,
    };
  }

  public async fetch_scope(identifier: string): Promise<{ supported: boolean; scope?: ScopeEntry[]; error?: string }> {
    return {
      supported: false,
      error: `Live scope synchronization for platform ${this.platform} is unavailable. Researcher must import authoritative scope entries.`,
    };
  }

  public is_live_fetch_supported(): boolean {
    return false;
  }

  public async get_policy(identifier: string): Promise<string> {
    return this.normalizePolicy('');
  }

  public async get_last_updated(identifier: string): Promise<string | null> {
    return null;
  }

  public normalizeScope(rawScope: string[]): string[] {
    return (rawScope || []).map(s => (typeof s === 'string' ? s.trim() : JSON.stringify(s))).filter(Boolean);
  }

  public normalizePolicy(rawPolicy: string): string {
    return (rawPolicy || '').trim();
  }

  public extractExclusions(rawExclusions: string[]): string[] {
    return (rawExclusions || []).map(e => (typeof e === 'string' ? e.trim() : JSON.stringify(e))).filter(Boolean);
  }

  public normalize_scope(rawScope: any[], programId: string = 'prog-default'): ScopeEntry[] {
    if (!Array.isArray(rawScope)) return [];
    const now = new Date().toISOString();

    return rawScope.map((item, idx) => {
      if (typeof item === 'string') {
        const trimmed = item.trim();
        let assetType = ScopeAssetType.OTHER;
        let normId = trimmed;

        if (trimmed.startsWith('http') || trimmed.startsWith('git@') || trimmed.includes('github.com') || trimmed.includes('gitlab.com')) {
          assetType = ScopeAssetType.REPOSITORY;
        } else if (trimmed.startsWith('0x') && trimmed.length === 42) {
          assetType = ScopeAssetType.CONTRACT;
        } else if (trimmed.includes('.') && !trimmed.includes(' ')) {
          assetType = ScopeAssetType.DOMAIN;
        }

        return {
          id: `scope-${Date.now()}-${idx}-${Math.random().toString(36).substring(2, 6)}`,
          program_id: programId,
          asset_type: assetType,
          asset_identifier: normId,
          inclusion_status: ScopeInclusionStatus.IN_SCOPE,
          created_at: now,
          updated_at: now,
        };
      } else if (typeof item === 'object' && item !== null) {
        const assetId = item.asset_identifier || item.target || item.repository || item.address || item.name || '';
        
        let assetType: ScopeAssetType = ScopeAssetType.REPOSITORY;
        if (assetId.includes('github.com') || assetId.includes('gitlab.com') || item.repository) {
          assetType = ScopeAssetType.REPOSITORY;
        } else if (item.asset_type === 'smart_contract' || item.asset_type === 'SMART_CONTRACT' || item.asset_type === ScopeAssetType.SMART_CONTRACT) {
          assetType = ScopeAssetType.SMART_CONTRACT;
        } else if (item.asset_type === 'contract' || item.asset_type === 'CONTRACT' || item.asset_type === ScopeAssetType.CONTRACT) {
          assetType = ScopeAssetType.SMART_CONTRACT;
        } else if (item.type === 'smart_contract' || item.type === 'contract' || (assetId.startsWith('0x') && assetId.length === 42)) {
          assetType = ScopeAssetType.SMART_CONTRACT;
        } else if (item.type === 'repository' || item.asset_type === ScopeAssetType.REPOSITORY) {
          assetType = ScopeAssetType.REPOSITORY;
        } else if (item.type === 'web' || item.type === 'domain' || item.asset_type === ScopeAssetType.DOMAIN || (assetId.startsWith('http') && !assetId.includes('github.com'))) {
          assetType = ScopeAssetType.DOMAIN;
        } else if (item.asset_type) {
          assetType = item.asset_type;
        }

        let inclusionStatus = ScopeInclusionStatus.IN_SCOPE;
        if (item.inclusion_status) {
          inclusionStatus = item.inclusion_status;
        } else if (item.in_scope === false || item.out_of_scope === true) {
          inclusionStatus = ScopeInclusionStatus.OUT_OF_SCOPE;
        } else if (item.in_scope === true) {
          inclusionStatus = ScopeInclusionStatus.IN_SCOPE;
        }

        return {
          id: item.id || `scope-${Date.now()}-${idx}-${Math.random().toString(36).substring(2, 6)}`,
          program_id: item.program_id || programId,
          asset_type: assetType,
          asset_identifier: assetId,
          inclusion_status: inclusionStatus,
          environment: item.environment,
          technology: item.technology,
          source_reference: item.source_reference,
          restrictions: item.restrictions || [],
          notes: item.notes,
          effective_from: item.effective_from,
          effective_to: item.effective_to,
          metadata: item.metadata || {},
          created_at: item.created_at || now,
          updated_at: item.updated_at || now,
        };
      }

      return {
        id: `scope-${Date.now()}-${idx}`,
        program_id: programId,
        asset_type: ScopeAssetType.OTHER,
        asset_identifier: String(item),
        inclusion_status: ScopeInclusionStatus.UNKNOWN,
        created_at: now,
        updated_at: now,
      };
    });
  }
}

export class ImmunefiAdapter extends BaseProgramAdapter {
  readonly platform = BountyPlatform.IMMUNEFI;

  override validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    if (!program.program_url && !program.metadata?.immunefi_url && !program.external_id) {
      errors.push('Immunefi program URL or external slug is required for authoritative provenance.');
    }
    return { valid: errors.length === 0, errors };
  }

  normalizePolicy(rawPolicy: string): string {
    return rawPolicy ? rawPolicy.trim() : 'Standard Immunefi Vulnerability Disclosure Policy & Rules of Engagement apply.';
  }
}

export class HackenProofAdapter extends BaseProgramAdapter {
  readonly platform = BountyPlatform.HACKENPROOF;

  override validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    return { valid: errors.length === 0, errors };
  }

  normalizePolicy(rawPolicy: string): string {
    return rawPolicy ? rawPolicy.trim() : 'HackenProof Responsible Disclosure Policy & Bounty Guidelines apply.';
  }
}

export class CantinaAdapter extends BaseProgramAdapter {
  readonly platform = BountyPlatform.CANTINA;

  override validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    return { valid: errors.length === 0, errors };
  }

  normalizePolicy(rawPolicy: string): string {
    return rawPolicy ? rawPolicy.trim() : 'Cantina Security Review & Competition Rules apply.';
  }
}

export class HackerOneAdapter extends BaseProgramAdapter {
  readonly platform = BountyPlatform.HACKERONE;

  override validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    return { valid: errors.length === 0, errors };
  }

  normalizePolicy(rawPolicy: string): string {
    return rawPolicy ? rawPolicy.trim() : 'HackerOne Vulnerability Disclosure Guidelines apply.';
  }
}

export class CustomProgramAdapter extends BaseProgramAdapter {
  readonly platform = BountyPlatform.CUSTOM;

  override validateProgram(program: Partial<Program>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!program.name || program.name.trim().length === 0) {
      errors.push('Program name is required.');
    }
    return { valid: errors.length === 0, errors };
  }

  normalizePolicy(rawPolicy: string): string {
    return rawPolicy || 'Custom private authorization policy provided by target owner.';
  }
}

export class ProgramAdapterRegistry {
  private adapters: Map<BountyPlatform, IProgramAdapter> = new Map();

  constructor() {
    this.register(new ImmunefiAdapter());
    this.register(new HackenProofAdapter());
    this.register(new CantinaAdapter());
    this.register(new HackerOneAdapter());
    this.register(new CustomProgramAdapter());
  }

  public register(adapter: IProgramAdapter): void {
    this.adapters.set(adapter.platform, adapter);
  }

  public get(platform: BountyPlatform): IProgramAdapter {
    const adapter = this.adapters.get(platform);
    if (!adapter) {
      return this.adapters.get(BountyPlatform.CUSTOM)!;
    }
    return adapter;
  }

  public list(): IProgramAdapter[] {
    return Array.from(this.adapters.values());
  }
  public list_supported_platforms(): BountyPlatform[] {
    return Array.from(this.adapters.keys());
  }
}

export const globalProgramAdapterRegistry = new ProgramAdapterRegistry();

export function getProgramAdapter(platform: BountyPlatform): IProgramAdapter {
  return globalProgramAdapterRegistry.get(platform);
}

// Aliases for compatibility
export const ImmunefiProgramAdapter = ImmunefiAdapter;
export const HackenProofProgramAdapter = HackenProofAdapter;
export const CantinaProgramAdapter = CantinaAdapter;
export const HackerOneProgramAdapter = HackerOneAdapter;
export const CustomProgramAdapterAlias = CustomProgramAdapter;

