/**
 * Real Angr Binary Analysis Service
 * Intent Security Workbench - Phase 2
 *
 * Angr is a Python library rather than a version-flag CLI, so analysis is
 * driven through `packages/dynamic-verification/angr_analyzer.py`. The driver
 * performs CFG recovery and dangerous-symbol resolution and returns JSON.
 *
 * Nothing is fabricated: a missing library, an unloadable binary, or an
 * unparsable driver response all surface as honest failures with zero findings.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn, execFileSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';

export type AngrStatus = 'COMPLETED' | 'FAILED' | 'NOT_INSTALLED' | 'TIMEOUT';

export interface AngrCallSite {
  symbol: string;
  addr: string;
}

export interface AngrAnalysisResult {
  ok: boolean;
  angr_version?: string;
  binary?: {
    path: string;
    arch: string;
    bits: number;
    entry: string;
    pie: boolean;
    nx: boolean;
  };
  functions?: number;
  imports?: string[];
  dangerous_imports?: string[];
  call_sites?: AngrCallSite[];
  warnings?: string[];
  error?: string;
}

export interface AngrExecutionDetails {
  status: AngrStatus;
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  result: AngrAnalysisResult | null;
  error?: string | null;
}

/** libc symbols whose presence in a binary warrants an audit finding. */
const DANGEROUS_SYMBOL_SEVERITY: Record<string, { severity: string; cwe: string[]; title: string }> = {
  strcpy: { severity: 'HIGH', cwe: ['CWE-120', 'CWE-787'], title: 'Unbounded string copy (strcpy)' },
  strcat: { severity: 'HIGH', cwe: ['CWE-120', 'CWE-787'], title: 'Unbounded string concatenation (strcat)' },
  sprintf: { severity: 'HIGH', cwe: ['CWE-120', 'CWE-787'], title: 'Unbounded formatted write (sprintf)' },
  vsprintf: { severity: 'HIGH', cwe: ['CWE-120', 'CWE-787'], title: 'Unbounded formatted write (vsprintf)' },
  gets: { severity: 'CRITICAL', cwe: ['CWE-242', 'CWE-120'], title: 'Unbounded read (gets)' },
  scanf: { severity: 'MEDIUM', cwe: ['CWE-120'], title: 'Unbounded formatted read (scanf)' },
  sscanf: { severity: 'MEDIUM', cwe: ['CWE-120'], title: 'Unbounded formatted read (sscanf)' },
  system: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Shell command execution (system)' },
  popen: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Shell command execution (popen)' },
  execl: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Process execution (execl)' },
  execlp: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Process execution (execlp)' },
  execv: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Process execution (execv)' },
  execvp: { severity: 'HIGH', cwe: ['CWE-78'], title: 'Process execution (execvp)' },
  memcpy: { severity: 'MEDIUM', cwe: ['CWE-120', 'CWE-787'], title: 'Memory copy (memcpy) with caller-supplied length' },
  memmove: { severity: 'MEDIUM', cwe: ['CWE-120', 'CWE-787'], title: 'Memory move (memmove) with caller-supplied length' },
  realpath: { severity: 'LOW', cwe: ['CWE-22'], title: 'Path resolution (realpath) may allow traversal' },
  getwd: { severity: 'LOW', cwe: ['CWE-22'], title: 'Working-directory disclosure (getwd)' },
};

export class AngrAnalysisService {
  private executable: string;
  private pythonPath: string;

  constructor(executable = 'angr', pythonPath = 'python3') {
    this.executable = executable;
    this.pythonPath = pythonPath;
  }

  /** Absolute path to the bundled analyzer driver script. */
  private driverPath(): string {
    const here = path.dirname(fileURLToPath(import.meta.url));
    return path.resolve(here, 'angr_analyzer.py');
  }

  /**
   * Availability reflects whether the `angr` module is importable. The `angr`
   * console script exists only when the wheel is installed, so a missing
   * import is reported as NOT_INSTALLED rather than BROKEN.
   */
  async checkAvailability(): Promise<{
    available: boolean;
    status: AngrStatus;
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
      const out = execFileSync(this.pythonPath, ['-c', 'import angr; print(angr.__version__)'], {
        encoding: 'utf-8',
        timeout: 60000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      const version = out.split('\n').pop()?.trim() || null;
      if (!version) throw new Error('no version output');
      return { available: true, status: 'COMPLETED', path: detectedPath, version, error: null };
    } catch (err: any) {
      const detail = (err.stderr ? err.stderr.toString() : '') || err.message;
      const isImportFailure = /ModuleNotFoundError|No module named/.test(detail);
      // A residual console script with no importable module is not a usable
      // install, so it must report NOT_INSTALLED with no path — never a path
      // alongside NOT_INSTALLED, which would look like a partial install.
      return {
        available: false,
        status: isImportFailure ? 'NOT_INSTALLED' : 'FAILED',
        path: isImportFailure ? null : detectedPath,
        version: null,
        error: isImportFailure
          ? `Python module 'angr' is not importable by '${this.pythonPath}': ${detail.split('\n').pop()}`
          : `Failed to query angr version: ${detail}`,
      };
    }
  }

  /**
   * Parses the driver's JSON response. Returns null when the payload is not a
   * JSON object with an `ok` discriminator.
   */
  parseAnalyzerOutput(stdout: string): AngrAnalysisResult | null {
    if (!stdout || !stdout.trim()) return null;
    try {
      const start = stdout.indexOf('{');
      if (start === -1) return null;
      const parsed = JSON.parse(stdout.slice(start));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      if (!('ok' in parsed)) return null;
      return parsed as AngrAnalysisResult;
    } catch {
      return null;
    }
  }

  /**
   * Runs CFG and symbol analysis on a real binary via the Python driver.
   */
  async analyze(
    binaryPath: string,
    options: { timeoutMs?: number } = {}
  ): Promise<AngrExecutionDetails> {
    const avail = await this.checkAvailability();
    const driver = this.driverPath();
    const command =
      `${this.pythonPath} ${driver} [binary=${binaryPath}]`;

    const base = (over: Partial<AngrExecutionDetails>): AngrExecutionDetails => ({
      status: 'FAILED',
      executable_path: avail.path,
      version: avail.version,
      command,
      exit_code: 127,
      stdout: '',
      stderr: avail.error || `Executable '${this.executable}' is not installed.`,
      duration_ms: 0,
      result: null,
      error: avail.error || 'ENGINE_NOT_INSTALLED',
      ...over,
    });

    if (!avail.available || !avail.path) return base({});
    if (!fs.existsSync(driver)) {
      return base({
        exit_code: 1,
        stderr: `Analyzer driver not found at ${driver}`,
        error: `ANGR_DRIVER_MISSING: ${driver}`,
      });
    }
    if (!fs.existsSync(binaryPath)) {
      return base({
        exit_code: 1,
        stderr: `Binary not found: ${binaryPath}`,
        error: `BINARY_NOT_FOUND: ${binaryPath}`,
      });
    }

    const timeoutMs = options.timeoutMs ?? 300000;
    const startMs = Date.now();

    const { stdout, stderr, exitCode, timedOut } = await new Promise<{
      stdout: string;
      stderr: string;
      exitCode: number;
      timedOut: boolean;
    }>((resolve) => {
      const child = spawn(this.pythonPath, [driver], {
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let out = '';
      let err = '';
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);

      child.stdout.on('data', (c) => {
        if (out.length < 8 * 1024 * 1024) out += c.toString();
      });
      child.stderr.on('data', (c) => {
        if (err.length < 8 * 1024 * 1024) err += c.toString();
      });
      child.on('error', (e) => {
        clearTimeout(timer);
        resolve({ stdout: out, stderr: `${err}${e.message}`, exitCode: 1, timedOut });
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ stdout: out, stderr: err, exitCode: code ?? 0, timedOut });
      });

      child.stdin.write(
        JSON.stringify({ binary_path: binaryPath, timeout_s: Math.ceil(timeoutMs / 1000) })
      );
      child.stdin.end();
    });

    const duration_ms = Date.now() - startMs;

    if (timedOut) {
      return base({
        status: 'TIMEOUT',
        exit_code: 124,
        stdout,
        stderr: stderr || `Angr analysis exceeded ${timeoutMs}ms`,
        duration_ms,
        error: `ANGR_TIMEOUT: analysis exceeded ${timeoutMs}ms`,
      });
    }

    const parsed = this.parseAnalyzerOutput(stdout);
    if (!parsed) {
      return base({
        exit_code: exitCode === 0 ? 1 : exitCode,
        stdout,
        stderr: stderr || 'Angr driver did not emit a parsable JSON result.',
        duration_ms,
        error: 'ANGR_OUTPUT_UNPARSEABLE: no JSON result was produced.',
      });
    }

    if (!parsed.ok) {
      return base({
        exit_code: exitCode === 0 ? 1 : exitCode,
        stdout,
        stderr: parsed.error || stderr,
        duration_ms,
        result: parsed,
        error: `ANGR_ANALYSIS_FAILED: ${parsed.error || 'unknown driver error'}`,
      });
    }

    return {
      status: 'COMPLETED',
      executable_path: avail.path,
      version: parsed.angr_version || avail.version,
      command,
      exit_code: 0,
      stdout,
      stderr,
      duration_ms,
      result: parsed,
      error: null,
    };
  }

  static symbolInfo(symbol: string) {
    return DANGEROUS_SYMBOL_SEVERITY[symbol] || null;
  }

  static isDangerous(symbol: string): boolean {
    return symbol in DANGEROUS_SYMBOL_SEVERITY;
  }
}

export const globalAngrService = new AngrAnalysisService();