/**
 * Real Slither Solidity Static Analysis Service
 * Intent Security Workbench - Phase 2
 *
 * Drives the actual installed Slither CLI. Slither compiles the target with
 * solc and runs its detector suite, emitting a JSON envelope we parse into
 * engine findings. Nothing is fabricated: a missing binary, a compile failure,
 * or unparseable output all surface as honest failures with zero findings.
 */

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';

export type SlitherStatus = 'COMPLETED' | 'FAILED' | 'NOT_INSTALLED' | 'BROKEN';

export interface SlitherDetectorResult {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  reference?: string;
  elements: Array<{
    type: string;
    name: string;
    file: string;
    lines: number[];
    starting_column?: number;
  }>;
}

export interface SlitherExecutionDetails {
  status: SlitherStatus;
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  detectors: SlitherDetectorResult[];
  contracts_analyzed: number;
  error?: string | null;
}

/** Slither impact ranking, used to map detector impact onto platform severity. */
const IMPACT_SEVERITY: Record<string, string> = {
  High: 'HIGH',
  Medium: 'MEDIUM',
  Low: 'LOW',
  Informational: 'INFO',
  Optimization: 'INFO',
};

/**
 * Slither's own confidence ranking. Slither's "High" confidence means the
 * detector is sure the pattern exists, which we surface as MEDIUM confidence
 * because static presence is not the same as demonstrated exploitability.
 */
const DETECTOR_CONFIDENCE: Record<string, string> = {
  High: 'MEDIUM',
  Medium: 'LOW',
  Low: 'LOW',
};

/** Maps well-known detector ids onto CWE identifiers. */
const CHECK_TO_CWE: Record<string, string[]> = {
  'reentrancy-eth': ['CWE-841', 'CWE-362'],
  'reentrancy-no-eth': ['CWE-841', 'CWE-362'],
  'reentrancy-benign': ['CWE-841'],
  'reentrancy-events': ['CWE-841'],
  'reentrancy-unlimited-gas': ['CWE-841'],
  'arbitrary-send-eth': ['CWE-284'],
  'arbitrary-send-erc20': ['CWE-284'],
  'tx-origin': ['CWE-284', 'CWE-346'],
  'unchecked-lowlevel': ['CWE-252'],
  'unchecked-send': ['CWE-252'],
  'unchecked-transfer': ['CWE-252'],
  'unchecked-return': ['CWE-252'],
  'controlled-delegatecall': ['CWE-829'],
  'delegatecall-loop': ['CWE-829'],
  'suicidal': ['CWE-284'],
  'unprotected-upgrade': ['CWE-284'],
  'missing-zero-check': ['CWE-20'],
  'calls-loop': ['CWE-400'],
  'divide-before-multiply': ['CWE-682'],
  'incorrect-equality': ['CWE-697'],
  'weak-prng': ['CWE-338'],
  'timestamp': ['CWE-330'],
  'shadowing-state': ['CWE-710'],
  'locked-ether': ['CWE-667'],
  'solc-version': ['CWE-1104'],
  'low-level-calls': ['CWE-252'],
  'assembly': ['CWE-119'],
  'naming-convention': [],
};

export class SlitherAnalysisService {
  private executable: string;

  constructor(executable = 'slither') {
    this.executable = executable;
  }

  /**
   * Genuine availability check: resolve on PATH/standard dirs, then actually
   * execute `slither --version` so a broken install is reported as BROKEN.
   */
  async checkAvailability(): Promise<{
    available: boolean;
    status: SlitherStatus;
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
      const versionOut = execFileSync(detectedPath, ['--version'], {
        encoding: 'utf-8',
        timeout: 30000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      const version = versionOut.split('\n')[0].trim();
      return { available: true, status: 'AVAILABLE' as unknown as SlitherStatus, path: detectedPath, version, error: null };
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

  /**
   * Parses a Slither JSON envelope. Returns null when the payload is not a
   * Slither JSON object (e.g. a compile error printed to stdout).
   */
  parseSlitherOutput(stdout: string): { detectors: SlitherDetectorResult[]; success: boolean } | null {
    if (!stdout || !stdout.trim()) return null;

    let parsed: any;
    try {
      // Slither may prefix progress lines; the JSON object starts at the first brace.
      const start = stdout.indexOf('{');
      if (start === -1) return null;
      parsed = JSON.parse(stdout.slice(start));
    } catch {
      return null;
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    if (!parsed.results || typeof parsed.results !== 'object') return null;

    const rawDetectors = Array.isArray(parsed.results.detectors) ? parsed.results.detectors : [];

    const detectors: SlitherDetectorResult[] = rawDetectors.map((d: any) => {
      const elements = Array.isArray(d.elements)
        ? d.elements.map((el: any) => ({
            type: el?.type || 'unknown',
            name: el?.name || '',
            file:
              el?.source_mapping?.filename_relative ||
              el?.source_mapping?.filename_short ||
              el?.source_mapping?.filename_absolute ||
              '',
            lines: Array.isArray(el?.source_mapping?.lines) ? el.source_mapping.lines : [],
            starting_column: el?.source_mapping?.starting_column,
          }))
        : [];

      return {
        check: d.check || d.id || 'unknown-detector',
        impact: d.impact || 'Informational',
        confidence: d.confidence || 'Medium',
        description: (d.description || '').trim(),
        reference: d.reference || undefined,
        elements,
      };
    });

    return { detectors, success: parsed.success !== false };
  }

  /**
   * Runs a real Slither analysis against a Solidity project directory.
   */
  async analyze(
    targetDir: string,
    options: { timeoutMs?: number; args?: string[] } = {}
  ): Promise<SlitherExecutionDetails> {
    const avail = await this.checkAvailability();
    const commandFor = (extra: string[]) =>
      `${avail.path || this.executable} ${extra.join(' ')} [cwd=${targetDir}]`;

    if (!avail.available || !avail.path) {
      return {
        status: avail.status,
        executable_path: avail.path,
        version: avail.version,
        command: commandFor(['.']),
        exit_code: 127,
        stdout: '',
        stderr: avail.error || `Executable '${this.executable}' is not installed.`,
        duration_ms: 0,
        detectors: [],
        contracts_analyzed: 0,
        error: avail.error || 'ENGINE_NOT_INSTALLED',
      };
    }

    if (!fs.existsSync(targetDir)) {
      return {
        status: 'FAILED',
        executable_path: avail.path,
        version: avail.version,
        command: commandFor(['.']),
        exit_code: 1,
        stdout: '',
        stderr: `Target directory not found: ${targetDir}`,
        duration_ms: 0,
        detectors: [],
        contracts_analyzed: 0,
        error: `Target directory does not exist at ${targetDir}`,
      };
    }

    const args = ['.', '--json', '-', ...(options.args || [])];
    const command = commandFor(args);
    const startMs = Date.now();
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    try {
      stdout = execFileSync(avail.path, args, {
        encoding: 'utf-8',
        timeout: options.timeoutMs ?? 300000,
        maxBuffer: 64 * 1024 * 1024,
        cwd: targetDir,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      exitCode = 0;
    } catch (err: any) {
      // Slither exits non-zero when detectors fire or compilation fails; both
      // carry usable stdout, so capture rather than discard.
      exitCode = typeof err.status === 'number' ? err.status : 1;
      stdout = err.stdout ? err.stdout.toString() : '';
      stderr = err.stderr ? err.stderr.toString() : err.message;
    }

    const duration_ms = Date.now() - startMs;
    const parsed = this.parseSlitherOutput(stdout);

    // No parsable JSON envelope means the run did not produce analysis output.
    if (!parsed) {
      return {
        status: 'FAILED',
        executable_path: avail.path,
        version: avail.version,
        command,
        exit_code: exitCode === 0 ? 1 : exitCode,
        stdout,
        stderr: stderr || 'Slither did not emit a parsable JSON result envelope.',
        duration_ms,
        detectors: [],
        contracts_analyzed: 0,
        error: 'SLITHER_OUTPUT_UNPARSEABLE: no JSON result envelope was produced (likely a compilation failure).',
      };
    }

    const contractsAnalyzed = new Set(
      parsed.detectors.flatMap(d => d.elements.map(e => e.name)).filter(Boolean)
    ).size;

    return {
      status: 'COMPLETED' as any,
      executable_path: avail.path,
      version: avail.version,
      command,
      exit_code: exitCode,
      stdout,
      stderr,
      duration_ms,
      detectors: parsed.detectors,
      contracts_analyzed: contractsAnalyzed,
      error: null,
    };
  }

  static severityFor(impact: string): string {
    return IMPACT_SEVERITY[impact] || 'INFO';
  }

  static confidenceFor(confidence: string): string {
    return DETECTOR_CONFIDENCE[confidence] || 'LOW';
  }

  static cwesFor(check: string): string[] {
    return CHECK_TO_CWE[check] || [];
  }
}

export const globalSlitherService = new SlitherAnalysisService();