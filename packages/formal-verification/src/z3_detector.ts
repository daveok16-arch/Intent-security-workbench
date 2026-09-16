/**
 * Host Z3 SMT Solver Detection
 * Intent Security Workbench - Phase 4
 *
 * Strictly executes `which z3` and `z3 --version`.
 * Never fabricates availability or simulates solver results.
 */

import { execSync, execFileSync } from 'child_process';
import fs from 'fs';
import { resolveExecutable } from '../../config/src/binary_resolver.js';
import { Z3HostInfo } from './types.js';

let cachedZ3Info: Z3HostInfo | null = null;

export class Z3Detector {
  /**
   * Detects the host Z3 executable and its genuine version.
   * Caches result after first check for performance, but forceRefresh can bypass cache.
   * If a customPath string is provided, validates that specific binary path.
   */
  static detect(customPathOrForce?: string | boolean, forceRefresh: boolean = false): Z3HostInfo {
    const customPath = typeof customPathOrForce === 'string' ? customPathOrForce : undefined;
    const shouldRefresh = typeof customPathOrForce === 'boolean' ? customPathOrForce : forceRefresh;

    if (!customPath && cachedZ3Info && !shouldRefresh) {
      return cachedZ3Info;
    }

    let executablePath: string | null = null;
    if (customPath) {
      if (fs.existsSync(customPath)) {
        executablePath = customPath;
      } else {
        return {
          installed: false,
          executable_path: null,
          version: null,
          raw_version_output: '',
          status: 'NOT_INSTALLED',
          error: `Specified path '${customPath}' not found or not executable on host.`,
        };
      }
    } else {
      executablePath = resolveExecutable('z3');
    }

    if (!executablePath) {
      const info: Z3HostInfo = {
        installed: false,
        executable_path: null,
        version: null,
        raw_version_output: '',
        status: 'NOT_INSTALLED',
        error: 'ENGINE_NOT_INSTALLED: z3 binary was not found on host system PATH.',
      };
      if (!customPath) cachedZ3Info = info;
      return info;
    }

    try {
      const versionOutput = execSync(`"${executablePath}" --version`, {
        encoding: 'utf-8',
        timeout: 4000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      const info: Z3HostInfo = {
        installed: true,
        executable_path: executablePath,
        version: versionOutput,
        raw_version_output: versionOutput,
        status: 'AVAILABLE',
        error: null,
      };
      if (!customPath) cachedZ3Info = info;
      return info;
    } catch (err: any) {
      const info: Z3HostInfo = {
        installed: false,
        executable_path: executablePath,
        version: null,
        raw_version_output: '',
        status: 'UNAVAILABLE',
        error: `ENGINE_EXECUTION_FAILED: z3 --version execution failed: ${err.message}`,
      };
      if (!customPath) cachedZ3Info = info;
      return info;
    }
  }

  static clearCache(): void {
    cachedZ3Info = null;
  }
}
