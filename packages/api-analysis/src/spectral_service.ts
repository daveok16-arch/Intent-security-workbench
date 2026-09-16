/**
 * Real Spectral OpenAPI Linter Service
 * Intent Security Workbench - Phase 3
 *
 * Controlled integration with Stoplight Spectral CLI.
 * Captures real command invocation, version, exit code, stdout, stderr,
 * and records outputs as verifiable evidence artifacts.
 */

import { execFileSync, execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { resolveExecutable } from '../../config/src/binary_resolver.js';
import { EngineFinding } from '../../../engines/types.js';

export interface SpectralExecutionResult {
  available: boolean;
  executable: string;
  version: string | null;
  command: string;
  ruleset?: string;
  input_specification: string;
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
  findings: EngineFinding[];
  raw_output_json?: any;
  error?: string;
}

export class SpectralAnalysisService {
  private executable: string;

  constructor(executable = 'spectral') {
    this.executable = executable;
  }

  /**
   * Check if Spectral is installed and available on host.
   */
  async checkAvailability(): Promise<{ available: boolean; path: string | null; version: string | null; error?: string }> {
    try {
      let detectedPath: string | null = null;
      const resolved = resolveExecutable(this.executable);
      if (resolved) {
        detectedPath = resolved;
      } else {
        // Fall back to a project-local node_modules/.bin install.
        const localBin = path.join(process.cwd(), 'node_modules', '.bin', this.executable);
        if (fs.existsSync(localBin)) {
          detectedPath = localBin;
        }
      }

      if (!detectedPath) {
        return {
          available: false,
          path: null,
          version: null,
          error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        };
      }

      const versionRaw = execFileSync(detectedPath, ['--version'], {
        encoding: 'utf-8',
        timeout: 4000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      const versionMatch = versionRaw.match(/(\d+\.\d+\.\d+)/);
      const version = versionMatch ? versionMatch[1] : versionRaw;

      return {
        available: true,
        path: detectedPath,
        version,
      };
    } catch (err: any) {
      return {
        available: false,
        path: null,
        version: null,
        error: `Failed checking ${this.executable} availability: ${err.message}`,
      };
    }
  }

  /**
   * Run real Spectral CLI against an OpenAPI file.
   */
  async lintSpecification(
    specificationFilePath: string,
    rulesetPath?: string
  ): Promise<SpectralExecutionResult> {
    const avail = await this.checkAvailability();
    const command = `${avail.path || this.executable} lint "${specificationFilePath}" -f json${rulesetPath ? ` --ruleset "${rulesetPath}"` : ''}`;

    if (!avail.available || !avail.path) {
      return {
        available: false,
        executable: this.executable,
        version: null,
        command,
        ruleset: rulesetPath,
        input_specification: specificationFilePath,
        stdout: '',
        stderr: avail.error || 'ENGINE_NOT_INSTALLED: Spectral executable not available on host.',
        exit_code: 127,
        duration_ms: 0,
        findings: [],
        error: avail.error || 'ENGINE_NOT_INSTALLED',
      };
    }

    if (!fs.existsSync(specificationFilePath)) {
      return {
        available: true,
        executable: avail.path,
        version: avail.version,
        command,
        ruleset: rulesetPath,
        input_specification: specificationFilePath,
        stdout: '',
        stderr: `Specification file not found: ${specificationFilePath}`,
        exit_code: 1,
        duration_ms: 0,
        findings: [],
        error: `Specification file does not exist at ${specificationFilePath}`,
      };
    }

    const args = ['lint', specificationFilePath, '-f', 'json'];
    if (rulesetPath && fs.existsSync(rulesetPath)) {
      args.push('--ruleset', rulesetPath);
    }

    const startTime = Date.now();
    let stdout = '';
    let stderr = '';
    let exitCode = 0;

    try {
      stdout = execFileSync(avail.path, args, {
        encoding: 'utf-8',
        timeout: 30000,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      exitCode = 0;
    } catch (err: any) {
      exitCode = typeof err.status === 'number' ? err.status : 1;
      stdout = err.stdout ? err.stdout.toString() : '';
      stderr = err.stderr ? err.stderr.toString() : err.message;
    }

    const durationMs = Date.now() - startTime;
    const findings: EngineFinding[] = [];
    let rawJson: any = null;

    if (stdout.trim()) {
      try {
        rawJson = JSON.parse(stdout);
        if (Array.isArray(rawJson)) {
          for (const item of rawJson) {
            let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'INFO';
            if (item.severity === 0) severity = 'HIGH'; // Spectral 0 = error
            else if (item.severity === 1) severity = 'MEDIUM'; // Spectral 1 = warn
            else if (item.severity === 2) severity = 'LOW'; // Spectral 2 = info
            else severity = 'INFO';

            const lineStart = item.range?.start?.line !== undefined ? item.range.start.line + 1 : undefined;
            const lineEnd = item.range?.end?.line !== undefined ? item.range.end.line + 1 : undefined;

            findings.push({
              id: `spectral-${item.code}-${findings.length + 1}`,
              title: `[Spectral] ${item.message}`,
              description: item.message,
              severity,
              category: 'API_CONTRACT',
              confidence: 'CONFIRMED',
              file: item.source || specificationFilePath,
              line_start: lineStart,
              line_end: lineEnd,
              evidence: item.path ? item.path.join('.') : undefined,
              metadata: {
                rule_id: item.code || 'spectral-rule',
                spectral_path: item.path,
                severity_num: item.severity,
              },
            });
          }
        }
      } catch (e) {
        // Output was not JSON
      }
    }

    return {
      available: true,
      executable: avail.path,
      version: avail.version,
      command,
      ruleset: rulesetPath,
      input_specification: specificationFilePath,
      stdout,
      stderr,
      exit_code: exitCode,
      duration_ms: durationMs,
      findings,
      raw_output_json: rawJson,
    };
  }
}

export const globalSpectralService = new SpectralAnalysisService();
