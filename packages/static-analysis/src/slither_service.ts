/**
 * Detects a solc version pin that would override the target's own pragma.
 *
 * `solc-select` stores a single global version in
 * `~/.solc-select/global-version`, and Slither uses it when the target does not
 * pin a compiler. Because that state is global and shared across every project
 * on the host, analysing one repository silently changed the compiler used for
 * the next one — a `pragma ^0.8.20` fixture compiled with 0.6.12 produced no
 * output and was reported as an unparseable failure.
 *
 * Returns the pinned version so the caller can report it in the failure message,
 * or null when nothing is pinned.
 */
function readGlobalSolcPin(): string | null {
  try {
    const home = process.env.HOME || os.homedir();
    const pinFile = path.join(home, '.solc-select', 'global-version');
    if (!fs.existsSync(pinFile)) return null;
    const value = fs.readFileSync(pinFile, 'utf-8').trim();
    return value || null;
  } catch {
    return null;
  }
}

/**
 * Locates the solc binary for a specific version via solc-select's artifact
 * layout, so a pinned compiler can be passed to Slither as a path (Slither's
 * `--solc` takes a path, not a version string).
 */
function resolveSolcBinary(version: string): string | null {
  const candidates: string[] = [];
  const home = process.env.HOME || os.homedir();
  for (const base of [
    process.env.SOLC_SELECT_PATH,
    path.join(home, '.solc-select'),
    path.join(home, '.local', 'share', 'solc-select'),
    '/usr/local/share/solc-select',
  ]) {
    if (!base) continue;
    candidates.push(
      path.join(base, 'artifacts', `solc-${version}`, `solc-${version}`),
      path.join(base, 'artifacts', `solc-${version}`),
    );
  }
  for (const c of candidates) {
    try {
      if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
    } catch {
      /* keep looking */
    }
  }
  // Fall back to a bare solc on PATH only when it is the version we need.
  const onPath = resolveExecutable(`solc-${version}`) || resolveExecutable('solc');
  return onPath || null;
}

/**
 * Resolves the Solidity compiler version the target actually requires from its
 * pragma, so the run does not depend on the host's global solc pin.
 */
function readRequiredSolc(targetDir: string): string | null {
  try {
    const entries = fs.readdirSync(targetDir, { recursive: true }) as string[];
    const versions: string[] = [];
    for (const rel of entries) {
      if (!String(rel).endsWith('.sol')) continue;
      if (String(rel).includes('node_modules')) continue;
      let text: string;
      try {
        text = fs.readFileSync(path.join(targetDir, String(rel)), 'utf-8');
      } catch {
        continue;
      }
      const m = text.match(/pragma\s+solidity\s+([^;]+);/);
      if (m) versions.push(m[1].trim());
    }
    if (versions.length === 0) return null;
    // Prefer an exact pin (`0.6.12`, `=0.8.20`) over a range.
    const exact = versions.find(v => /^=?\d+\.\d+\.\d+$/.test(v));
    if (exact) return exact.replace(/^=/, '');
    // Otherwise take the highest lower bound, e.g. ^0.8.20 -> 0.8.20.
    const bounds = versions
      .map(v => (v.match(/\d+\.\d+\.\d+/) || [])[0])
      .filter(Boolean) as string[];
    if (bounds.length === 0) return null;
    return bounds.sort(compareSemver).pop() || null;
  } catch {
    return null;
  }
}

function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

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
import os from 'os';
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

    // Pin the compiler from the target's own pragma rather than inheriting the
    // host's global solc-select version, which any other project can change.
    // Slither's `--solc` takes a path, so resolve the binary for that version.
    const requiredSolc = readRequiredSolc(targetDir);
    const solcBinary = requiredSolc ? resolveSolcBinary(requiredSolc) : null;
    const args = [
      '.',
      '--json',
      '-',
      ...(solcBinary ? ['--solc', solcBinary] : []),
      ...(options.args || []),
    ];
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
      const pin = readGlobalSolcPin();
      const pinNote = pin && requiredSolc && pin !== requiredSolc
        ? ` The host has a global solc pin of ${pin} while the target requires ${requiredSolc};` +
          ` ensure the required compiler is installed (solc-select install ${requiredSolc}).`
        : '';
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
        error:
          'SLITHER_OUTPUT_UNPARSEABLE: no JSON result envelope was produced (likely a compilation failure).' +
          pinNote,
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