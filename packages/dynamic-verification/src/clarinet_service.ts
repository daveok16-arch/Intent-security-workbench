/**
 * Real Clarinet Clarity Analysis Service
 * Intent Security Workbench - Phase 5
 *
 * Clarinet's `check` performs syntax, type and lint analysis over a Clarinet
 * project and emits a JSON diagnostics envelope. A bare `.clar` file is not a
 * project, so we materialise a throwaway project in a temp directory that
 * registers the contract, then run `check --output json` against it.
 *
 * Nothing is fabricated: a missing binary, a scaffold failure, or a non-JSON
 * envelope all surface as honest failures with zero findings.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';

export type ClarinetStatus = 'COMPLETED' | 'FAILED' | 'NOT_INSTALLED' | 'BROKEN';

export interface ClarinetDiagnostic {
  level: string;
  message: string;
  file: string;
  start_line?: number;
  start_column?: number;
  end_line?: number;
  end_column?: number;
  suggestion?: string | null;
}

export interface ClarinetExecutionDetails {
  status: ClarinetStatus;
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  diagnostics: ClarinetDiagnostic[];
  contracts_checked: number;
  error?: string | null;
}

/** Clarinet diagnostic levels mapped onto platform severity. */
const LEVEL_SEVERITY: Record<string, string> = {
  Error: 'HIGH',
  Warning: 'MEDIUM',
  Note: 'INFO',
  Info: 'INFO',
};

export class ClarinetAnalysisService {
  private executable: string;

  constructor(executable = 'clarinet') {
    this.executable = executable;
  }

  async checkAvailability(): Promise<{
    available: boolean;
    status: ClarinetStatus;
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
        timeout: 20000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      const version = versionOut.split('\n')[0].trim();
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

  /**
   * Parses the Clarinet JSON diagnostics envelope. Returns null when the
   * payload is not a Clarinet JSON object.
   */
  parseClarinetOutput(stdout: string): { diagnostics: ClarinetDiagnostic[]; success: boolean } | null {
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
    if (!('success' in parsed)) return null;

    const rawDiagnostics = parsed.diagnostics;
    const diagnostics: ClarinetDiagnostic[] = [];

    if (rawDiagnostics && typeof rawDiagnostics === 'object' && !Array.isArray(rawDiagnostics)) {
      for (const [file, entries] of Object.entries(rawDiagnostics as Record<string, any[]>)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const span = Array.isArray(entry?.spans) && entry.spans.length > 0 ? entry.spans[0] : {};
          diagnostics.push({
            level: entry?.level || 'Info',
            message: entry?.message || '',
            file,
            start_line: span.start_line,
            start_column: span.start_column,
            end_line: span.end_line,
            end_column: span.end_column,
            suggestion: entry?.suggestion ?? null,
          });
        }
      }
    }

    return { diagnostics, success: parsed.success !== false };
  }

  /**
   * Builds a throwaway Clarinet project around one or more `.clar` files.
   * Returns the project directory, or null when no contracts were found.
   */
  private scaffoldProject(
    sourceDir: string,
    workRoot: string
  ): { dir: string; contracts: string[]; fileMap: Map<string, string> } | null {
    const contractFiles: string[] = [];
    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
          walk(full);
        } else if (entry.name.endsWith('.clar')) {
          contractFiles.push(full);
        }
      }
    };
    walk(sourceDir);
    if (contractFiles.length === 0) return null;

    const projectDir = fs.mkdtempSync(path.join(workRoot, 'intent-clarinet-'));
    const contractsDir = path.join(projectDir, 'contracts');
    const settingsDir = path.join(projectDir, 'settings');
    fs.mkdirSync(contractsDir, { recursive: true });
    fs.mkdirSync(settingsDir, { recursive: true });

    // Devnet.toml is required by `clarinet check`; a minimal network/account
    // block is sufficient because analysis never touches the network.
    fs.writeFileSync(
      path.join(settingsDir, 'Devnet.toml'),
      [
        '[network]',
        'name = "devnet"',
        'deployment_fee_rate = 10',
        '',
        '[accounts.deployer]',
        'mnemonic = "twice kind fence tip hidden tilt action fragile skin nothing glory cousin green tomorrow spring wrist shed math olympic multiply hip blue scout claw"',
        'balance = 100_000_000_000_000',
        '',
      ].join('\n')
    );

    const registered: string[] = [];
    const fileMap = new Map<string, string>();
    const manifestLines = [
      '[project]',
      'name = "intent-analysis"',
      'description = "Temporary analysis project"',
      'telemetry = false',
      '',
    ];

    const usedNames = new Set<string>();
    contractFiles.forEach((file) => {
      const base = path.basename(file);
      // Clarity contract names must be valid identifiers (no leading digit,
      // no dots); keep the original stem readable and disambiguate collisions.
      let contractName = base
        .replace(/\.clar$/, '')
        .replace(/[^A-Za-z0-9_-]/g, '_')
        .replace(/^[^A-Za-z]+/, '');
      if (!contractName) contractName = 'contract';
      let unique = contractName;
      let n = 2;
      while (usedNames.has(unique)) unique = `${contractName}_${n++}`;
      usedNames.add(unique);

      const safeFile = `${unique}.clar`;
      const target = path.join(contractsDir, safeFile);
      fs.copyFileSync(file, target);
      manifestLines.push(`[contracts.${unique}]`, `path = "contracts/${safeFile}"`, '');
      registered.push(target);
      // Diagnostics reference the scaffolded copy; map it back to the real source.
      fileMap.set(target, path.resolve(file));
    });

    manifestLines.push(
      '[repl.analysis]',
      'passes = ["check_checker"]',
      'check_checker = { trusted_sender = false, trusted_caller = false, callee_filter = false }',
      ''
    );

    fs.writeFileSync(path.join(projectDir, 'Clarinet.toml'), manifestLines.join('\n'));
    return { dir: projectDir, contracts: registered, fileMap };
  }

  /**
   * Runs a real Clarinet check against a directory of `.clar` contracts.
   */
  async analyze(
    sourceDir: string,
    options: { timeoutMs?: number; keepWorkspace?: boolean } = {}
  ): Promise<ClarinetExecutionDetails> {
    const avail = await this.checkAvailability();
    const emptyResult = (over: Partial<ClarinetExecutionDetails>): ClarinetExecutionDetails => ({
      status: avail.status,
      executable_path: avail.path,
      version: avail.version,
      command: `${avail.path || this.executable} check --output json [cwd=${sourceDir}]`,
      exit_code: 127,
      stdout: '',
      stderr: avail.error || `Executable '${this.executable}' is not installed.`,
      duration_ms: 0,
      diagnostics: [],
      contracts_checked: 0,
      error: avail.error || 'ENGINE_NOT_INSTALLED',
      ...over,
    });

    if (!avail.available || !avail.path) return emptyResult({});

    if (!fs.existsSync(sourceDir)) {
      return emptyResult({
        status: 'FAILED',
        exit_code: 1,
        stderr: `Source directory not found: ${sourceDir}`,
        error: `Source directory does not exist at ${sourceDir}`,
      });
    }

    const workRoot = path.join(os.tmpdir(), 'intent-clarinet-work');
    fs.mkdirSync(workRoot, { recursive: true });

    let scaffold: { dir: string; contracts: string[]; fileMap: Map<string, string> } | null = null;
    try {
      scaffold = this.scaffoldProject(sourceDir, workRoot);
    } catch (err: any) {
      return emptyResult({
        status: 'FAILED',
        exit_code: 1,
        stderr: `Failed to scaffold Clarinet project: ${err.message}`,
        error: `CLARINET_SCAFFOLD_FAILED: ${err.message}`,
      });
    }

    if (!scaffold) {
      return emptyResult({
        status: 'FAILED',
        exit_code: 1,
        stderr: `No .clar contracts found under ${sourceDir}`,
        error: `NO_CLARITY_CONTRACTS_FOUND: no .clar files under ${sourceDir}`,
      });
    }

    const args = ['check', '--output', 'json'];
    const command = `${avail.path} ${args.join(' ')} [cwd=${scaffold.dir}]`;
    const startMs = Date.now();
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    try {
      stdout = execFileSync(avail.path, args, {
        encoding: 'utf-8',
        timeout: options.timeoutMs ?? 180000,
        maxBuffer: 32 * 1024 * 1024,
        cwd: scaffold.dir,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      exitCode = 0;
    } catch (err: any) {
      exitCode = typeof err.status === 'number' ? err.status : 1;
      stdout = err.stdout ? err.stdout.toString() : '';
      stderr = err.stderr ? err.stderr.toString() : err.message;
    }

    const duration_ms = Date.now() - startMs;

    if (!options.keepWorkspace) {
      try {
        fs.rmSync(scaffold.dir, { recursive: true, force: true });
      } catch {
        /* best-effort cleanup */
      }
    }

    const parsed = this.parseClarinetOutput(stdout);
    if (!parsed) {
      return {
        status: 'FAILED',
        executable_path: avail.path,
        version: avail.version,
        command,
        exit_code: exitCode === 0 ? 1 : exitCode,
        stdout,
        stderr: stderr || 'Clarinet did not emit a parsable JSON diagnostics envelope.',
        duration_ms,
        diagnostics: [],
        contracts_checked: 0,
        error: 'CLARINET_OUTPUT_UNPARSEABLE: no JSON diagnostics envelope was produced.',
      };
    }

    return {
      status: 'COMPLETED',
      executable_path: avail.path,
      version: avail.version,
      command,
      exit_code: exitCode,
      stdout,
      stderr,
      duration_ms,
      diagnostics: parsed.diagnostics.map(diag => ({
        ...diag,
        file: scaffold!.fileMap.get(diag.file) || diag.file,
      })),
      contracts_checked: scaffold.contracts.length,
      error: null,
    };
  }

  static severityFor(level: string): string {
    return LEVEL_SEVERITY[level] || 'INFO';
  }
}

export const globalClarinetService = new ClarinetAnalysisService();