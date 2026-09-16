/**
 * Real Tool Detectors for Dynamic Verification
 * Intent Security Workbench - Phase 5
 *
 * Requirements:
 * - Detect real binaries on host system:
 *   - EVM: forge --version, anvil --version
 *   - Clarity: clarinet --version
 * - Record: executable, absolute path, version, availability, installation status
 * - If unavailable: report ENGINE_NOT_INSTALLED
 * - Never emulate these tools.
 * - Never return successful execution when the binary is missing.
 */

import { execSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';
import { ToolDetectionResult } from './types.js';

export class ToolDetector {
  /**
   * Check if an executable exists on the host PATH or in standard tool directories.
   */
  static findExecutable(nameOrPath: string): string | null {
    return resolveExecutable(nameOrPath);
  }

  /**
   * Detect real Forge binary (part of Foundry).
   */
  static detectForge(customPath?: string): ToolDetectionResult {
    const executable = customPath || 'forge';
    const foundPath = this.findExecutable(executable);

    if (!foundPath) {
      return {
        tool: 'forge',
        executable,
        installed: false,
        version: null,
        executable_path: null,
        status: 'NOT_INSTALLED',
        error: 'ENGINE_NOT_INSTALLED: forge (Foundry) is not installed on host.',
        capabilities: ['solidity compilation', 'testing', 'trace analysis', 'invariant testing'],
      };
    }

    try {
      const output = execSync(`"${foundPath}" --version`, {
        encoding: 'utf-8',
        timeout: 4000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      // Extract version e.g., "forge Version: 1.8.1" or "forge 1.8.1" or "0.2.0"
      const match = output.match(/forge\s+(?:Version:\s*)?([^\s\n]+)/i) || output.match(/([0-9]+\.[0-9]+\.[0-9]+[^\s\n]*)/);
      const version = match ? match[1] : output.split('\n')[0].trim();

      return {
        tool: 'forge',
        executable,
        installed: true,
        version,
        executable_path: foundPath,
        status: 'AVAILABLE',
        error: null,
        capabilities: ['solidity compilation', 'testing', 'trace analysis', 'invariant testing'],
      };
    } catch (err: any) {
      return {
        tool: 'forge',
        executable,
        installed: false,
        version: null,
        executable_path: foundPath,
        status: 'ERROR',
        error: `ENGINE_EXECUTION_ERROR: forge failed to report version: ${err.message}`,
        capabilities: ['solidity compilation', 'testing', 'trace analysis', 'invariant testing'],
      };
    }
  }

  /**
   * Detect real Anvil binary (part of Foundry).
   */
  static detectAnvil(customPath?: string): ToolDetectionResult {
    const executable = customPath || 'anvil';
    const foundPath = this.findExecutable(executable);

    if (!foundPath) {
      return {
        tool: 'anvil',
        executable,
        installed: false,
        version: null,
        executable_path: null,
        status: 'NOT_INSTALLED',
        error: 'ENGINE_NOT_INSTALLED: anvil (Foundry local node) is not installed on host.',
        capabilities: ['local evm node', 'forking', 'rpc simulation', 'state manipulation'],
      };
    }

    try {
      const output = execSync(`"${foundPath}" --version`, {
        encoding: 'utf-8',
        timeout: 4000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      const match = output.match(/anvil\s+(?:Version:\s*)?([^\s\n]+)/i) || output.match(/([0-9]+\.[0-9]+\.[0-9]+[^\s\n]*)/);
      const version = match ? match[1] : output.split('\n')[0].trim();

      return {
        tool: 'anvil',
        executable,
        installed: true,
        version,
        executable_path: foundPath,
        status: 'AVAILABLE',
        error: null,
        capabilities: ['local evm node', 'forking', 'rpc simulation', 'state manipulation'],
      };
    } catch (err: any) {
      return {
        tool: 'anvil',
        executable,
        installed: false,
        version: null,
        executable_path: foundPath,
        status: 'ERROR',
        error: `ENGINE_EXECUTION_ERROR: anvil failed to report version: ${err.message}`,
        capabilities: ['local evm node', 'forking', 'rpc simulation', 'state manipulation'],
      };
    }
  }

  /**
   * Detect real Clarinet binary (for Clarity / Stacks).
   */
  static detectClarinet(customPath?: string): ToolDetectionResult {
    const executable = customPath || 'clarinet';
    const foundPath = this.findExecutable(executable);

    if (!foundPath) {
      return {
        tool: 'clarinet',
        executable,
        installed: false,
        version: null,
        executable_path: null,
        status: 'NOT_INSTALLED',
        error: 'ENGINE_NOT_INSTALLED: clarinet (Stacks Clarity runtime) is not installed on host.',
        capabilities: ['clarity contract check', 'simnet execution', 'clarity unit tests'],
      };
    }

    try {
      const output = execSync(`"${foundPath}" --version`, {
        encoding: 'utf-8',
        timeout: 4000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      const match = output.match(/clarinet\s+([^\s\n]+)/i) || output.match(/([0-9]+\.[0-9]+\.[0-9]+[^\s\n]*)/);
      const version = match ? match[1] : output.split('\n')[0].trim();

      return {
        tool: 'clarinet',
        executable,
        installed: true,
        version,
        executable_path: foundPath,
        status: 'AVAILABLE',
        error: null,
        capabilities: ['clarity contract check', 'simnet execution', 'clarity unit tests'],
      };
    } catch (err: any) {
      return {
        tool: 'clarinet',
        executable,
        installed: false,
        version: null,
        executable_path: foundPath,
        status: 'ERROR',
        error: `ENGINE_EXECUTION_ERROR: clarinet failed to report version: ${err.message}`,
        capabilities: ['clarity contract check', 'simnet execution', 'clarity unit tests'],
      };
    }
  }

  /**
   * Detect all dynamic verification tools and return structured catalog.
   */
  static detectAll(): Record<string, ToolDetectionResult> {
    return {
      forge: this.detectForge(),
      anvil: this.detectAnvil(),
      clarinet: this.detectClarinet(),
    };
  }
}
