/**
 * Real Foundry (Forge) Execution Service
 * Intent Security Workbench - Phase 5
 *
 * The Foundry *toolkit* ships `forge`, `anvil`, `cast` and `chisel`; there is
 * no `foundry` binary. This service drives `forge test --json` against a
 * Foundry project and parses the structured per-test results.
 *
 * Nothing is fabricated: a missing forge, a non-project directory, or a
 * compilation failure all surface as honest failures with zero findings.
 */

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';

export type FoundryStatus = 'COMPLETED' | 'FAILED' | 'NOT_INSTALLED' | 'BROKEN';

export interface FoundryTestResult {
  suite: string;
  test_name: string;
  status: string;
  reason: string | null;
  gas?: number;
  duration?: string;
}

export interface FoundryExecutionDetails {
  status: FoundryStatus;
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  suites: string[];
  tests_passed: number;
  tests_failed: number;
  results: FoundryTestResult[];
  error?: string | null;
}

/**
 * Test names that indicate a fixture deliberately asserting exploitability.
 * A passing test whose name matches is evidence the flaw reproduces.
 */
const EXPLOIT_NAME_PATTERN = /exploit|attack|unauthorized|bypass|steal|drain|reentran|overflow|injection|bola|idor/i;

export class FoundryAnalysisService {
  private executable: string;

  constructor(executable = 'forge') {
    this.executable = executable;
  }

  async checkAvailability(): Promise<{
    available: boolean;
    status: FoundryStatus;
    path: string | null;
    version: string | null;
    error: string | null;
  }> {
    let detectedPath: string | null = null;
    try {
      detectedPath = resolveExecutable(this.executable);
    } catch {
      detectedPath = null;
    }

    if (!detectedPath) {
      return {
        available: false,
        status: 'NOT_INSTALLED',
        path: null,
        version: null,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
      };
    }

    try {
      // `forge --version` prints e.g. "forge 1.8.3 (abcdef 2026-01-01T00:00:00.000000000Z)"
      const versionOut = execFileSync(detectedPath, ['--version'], {
        encoding: 'utf-8',
        timeout: 60000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      const match = versionOut.match(/(\d+\.\d+\.\d+)/);
      const version = match ? match[1] : versionOut.split('\n')[0].trim();
      return { available: true, status: 'COMPLETED', path: detectedPath, version, error: null };
    } catch (err: any) {
      return {
        available: false,
        status: 'BROKEN',
        path: detectedPath,
        version: null,
        error: `Failed to execute '${this.executable} --version': ${err.message}`,
      };
    }
  }

  /** A usable Foundry project has a foundry.toml, or at least a test directory. */
  isFoundryProject(dir: string): boolean {
    return (
      fs.existsSync(path.join(dir, 'foundry.toml')) ||
      fs.existsSync(path.join(dir, 'test')) ||
      fs.existsSync(path.join(dir, 'src'))
    );
  }

  /**
   * Parses `forge test --json` output. Returns null when the payload is not a
   * per-suite result mapping.
   */
  parseForgeOutput(stdout: string): { results: FoundryTestResult[]; suites: string[] } | null {
    if (!stdout || !stdout.trim()) return null;

    let parsed: any;
    try {
      const start = stdout.indexOf('{');
      if (start === -1) return null;
      parsed = JSON.parse(stdout.slice(start));
    } catch {
      return null;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

    const results: FoundryTestResult[] = [];
    const suites: string[] = [];

    for (const [suite, suiteData] of Object.entries(parsed as Record<string, any>)) {
      suites.push(suite);
      const testResults = suiteData?.test_results;
      if (!testResults || typeof testResults !== 'object') continue;

      for (const [testName, res] of Object.entries(testResults as Record<string, any>)) {
        const kind = (res as any)?.kind || {};
        const unitGas = kind?.Unit?.gas ?? kind?.Fuzz?.gas;
        results.push({
          suite,
          test_name: testName.replace(/\(\)$/, ''),
          status: (res as any)?.status || 'Unknown',
          reason: (res as any)?.reason ?? null,
          gas: typeof unitGas === 'number' ? unitGas : undefined,
          duration: (res as any)?.duration,
        });
      }
    }

    // A usable document must contain at least one suite with a test_results map;
    // an unrelated JSON object with the same top-level shape is not a result set.
    const hasTestResults = Object.values(parsed as Record<string, any>).some(
      v => v && typeof v === 'object' && v.test_results && typeof v.test_results === 'object'
    );
    if (!hasTestResults) return null;

    return { results, suites };
  }

  /**
   * Runs `forge test --json` against a Foundry project directory.
   */
  async analyze(
    projectDir: string,
    options: { timeoutMs?: number; matchTest?: string } = {}
  ): Promise<FoundryExecutionDetails> {
    const avail = await this.checkAvailability();
    const base = (over: Partial<FoundryExecutionDetails>): FoundryExecutionDetails => ({
      status: 'FAILED',
      executable_path: avail.path,
      version: avail.version,
      command: `${avail.path || this.executable} test --json [cwd=${projectDir}]`,
      exit_code: 127,
      stdout: '',
      stderr: avail.error || `Executable '${this.executable}' is not installed.`,
      duration_ms: 0,
      suites: [],
      tests_passed: 0,
      tests_failed: 0,
      results: [],
      error: avail.error || 'ENGINE_NOT_INSTALLED',
      ...over,
    });

    if (!avail.available || !avail.path) return base({});

    if (!fs.existsSync(projectDir)) {
      return base({
        exit_code: 1,
        stderr: `Project directory not found: ${projectDir}`,
        error: `PROJECT_NOT_FOUND: ${projectDir}`,
      });
    }
    if (!this.isFoundryProject(projectDir)) {
      return base({
        exit_code: 1,
        stderr: `Not a Foundry project (no foundry.toml/src/test): ${projectDir}`,
        error: `NOT_A_FOUNDRY_PROJECT: ${projectDir}`,
      });
    }

    const args = ['test', '--json'];
    if (options.matchTest) args.push('--match-test', options.matchTest);
    const command = `${avail.path} ${args.join(' ')} [cwd=${projectDir}]`;

    const startMs = Date.now();
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    try {
      stdout = execFileSync(avail.path, args, {
        encoding: 'utf-8',
        timeout: options.timeoutMs ?? 600000,
        maxBuffer: 64 * 1024 * 1024,
        cwd: projectDir,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      exitCode = 0;
    } catch (err: any) {
      // forge exits 1 when a test fails; the JSON on stdout is still valid.
      exitCode = typeof err.status === 'number' ? err.status : 1;
      stdout = err.stdout ? err.stdout.toString() : '';
      stderr = err.stderr ? err.stderr.toString() : err.message;
    }

    const duration_ms = Date.now() - startMs;
    const parsed = this.parseForgeOutput(stdout);

    if (!parsed) {
      return {
        status: 'FAILED',
        executable_path: avail.path,
        version: avail.version,
        command,
        exit_code: exitCode === 0 ? 1 : exitCode,
        stdout,
        stderr: stderr || 'forge did not emit a parsable JSON result document.',
        duration_ms,
        suites: [],
        tests_passed: 0,
        tests_failed: 0,
        results: [],
        error: `FORGE_OUTPUT_UNPARSEABLE: no JSON result document was produced (likely a compilation failure). ${stderr.split('\n')[0] || ''}`.trim(),
      };
    }

    const tests_passed = parsed.results.filter(r => /^success$/i.test(r.status)).length;
    const tests_failed = parsed.results.filter(r => /^failure$/i.test(r.status)).length;

    return {
      status: 'COMPLETED',
      executable_path: avail.path,
      version: avail.version,
      command,
      exit_code: exitCode,
      stdout,
      stderr,
      duration_ms,
      suites: parsed.suites,
      tests_passed,
      tests_failed,
      results: parsed.results,
      error: null,
    };
  }

  /** True when a passing test name suggests a deliberate exploit assertion. */
  static looksLikeExploitTest(testName: string): boolean {
    return EXPLOIT_NAME_PATTERN.test(testName);
  }
}

export const globalFoundryService = new FoundryAnalysisService();