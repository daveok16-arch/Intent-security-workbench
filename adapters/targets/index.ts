/**
 * Target Ecosystem Adapters for Intent Security Workbench
 * Phase 0 Foundational Architecture
 * 
 * Modular target handlers for EVM, Solana/Rust, Clarity/Stacks, Move, and Web/API targets.
 */

import { Ecosystem, Target, TargetType, SourceAcquisitionStatus } from '../../packages/core/src/index.js';

export interface ITargetAdapter {
  readonly ecosystem: Ecosystem;
  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] };
  extractSourceIdentifiers(target: Target): { repo?: string; commit?: string; network?: string };
  verifyTargetCompatibility(engineRequirements: string[]): boolean;
}

export class EVMTargetAdapter implements ITargetAdapter {
  readonly ecosystem = Ecosystem.EVM;

  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!target.name) errors.push('Target name is required.');
    if (target.target_type === TargetType.SMART_CONTRACT && !target.deployment_information?.address && !target.repository_url) {
      errors.push('EVM Smart contract target requires either a contract address or a source repository URL.');
    }
    return { valid: errors.length === 0, errors };
  }

  extractSourceIdentifiers(target: Target) {
    return {
      repo: target.repository_url,
      commit: target.commit_hash,
      network: target.deployment_information?.network || 'mainnet',
    };
  }

  verifyTargetCompatibility(engineRequirements: string[]): boolean {
    return engineRequirements.includes('EVM');
  }
}

export class SolanaRustTargetAdapter implements ITargetAdapter {
  readonly ecosystem = Ecosystem.SOLANA_RUST;

  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!target.name) errors.push('Target name is required.');
    return { valid: errors.length === 0, errors };
  }

  extractSourceIdentifiers(target: Target) {
    return {
      repo: target.repository_url,
      commit: target.commit_hash,
      program_id: target.deployment_information?.program_id,
    };
  }

  verifyTargetCompatibility(engineRequirements: string[]): boolean {
    return engineRequirements.includes('SOLANA_RUST');
  }
}

export class ClarityStacksTargetAdapter implements ITargetAdapter {
  readonly ecosystem = Ecosystem.CLARITY_STACKS;

  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!target.name) errors.push('Target name is required.');
    return { valid: errors.length === 0, errors };
  }

  extractSourceIdentifiers(target: Target) {
    return {
      repo: target.repository_url,
      commit: target.commit_hash,
      contract_principal: target.deployment_information?.contract_principal,
    };
  }

  verifyTargetCompatibility(engineRequirements: string[]): boolean {
    return engineRequirements.includes('CLARITY_STACKS');
  }
}

export class MoveTargetAdapter implements ITargetAdapter {
  readonly ecosystem = Ecosystem.MOVE;

  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!target.name) errors.push('Target name is required.');
    return { valid: errors.length === 0, errors };
  }

  extractSourceIdentifiers(target: Target) {
    return {
      repo: target.repository_url,
      commit: target.commit_hash,
      package_address: target.deployment_information?.package_address,
    };
  }

  verifyTargetCompatibility(engineRequirements: string[]): boolean {
    return engineRequirements.includes('MOVE');
  }
}

export class WebAPITargetAdapter implements ITargetAdapter {
  readonly ecosystem = Ecosystem.WEB_API;

  validateTarget(target: Partial<Target>): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!target.name) errors.push('Target name is required.');
    return { valid: errors.length === 0, errors };
  }

  extractSourceIdentifiers(target: Target) {
    return {
      repo: target.repository_url,
      commit: target.commit_hash,
      endpoint_base: target.deployment_information?.endpoint_base,
    };
  }

  verifyTargetCompatibility(engineRequirements: string[]): boolean {
    return engineRequirements.includes('WEB_API');
  }
}

export function getTargetAdapter(ecosystem: Ecosystem): ITargetAdapter {
  switch (ecosystem) {
    case Ecosystem.EVM:
      return new EVMTargetAdapter();
    case Ecosystem.SOLANA_RUST:
      return new SolanaRustTargetAdapter();
    case Ecosystem.CLARITY_STACKS:
      return new ClarityStacksTargetAdapter();
    case Ecosystem.MOVE:
      return new MoveTargetAdapter();
    case Ecosystem.WEB_API:
    default:
      return new WebAPITargetAdapter();
  }
}
