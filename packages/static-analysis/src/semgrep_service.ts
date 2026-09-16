/**
 * Real Semgrep CLI Security Analysis Service
 * Intent Security Workbench - Phase 2
 *
 * Invokes the actual installed Semgrep CLI binary.
 * Enforces strict sandboxing, captures real stdout/stderr streams,
 * registers ground-truth artifacts, and parses genuine security findings.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { execSync, execFileSync } from 'child_process';
import {
  ArtifactType,
  Confidence,
  FindingStatus,
  Severity,
} from '../../core/src/index.js';
import {
  createEvidenceArtifact,
  globalArtifactStorage,
} from '../../evidence/src/index.js';
import { resolveExecutable } from '../../config/src/binary_resolver.js';
import {
  CandidateFinding,
  StaticRuleCategory,
} from './types.js';
import { globalSecurityRuleRegistry } from './rule_registry.js';

export interface SemgrepExecutionDetails {
  status: 'COMPLETED' | 'FAILED' | 'UNAVAILABLE' | 'NOT_INSTALLED';
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  stdout_artifact_id?: string;
  stderr_artifact_id?: string;
  duration_ms: number;
  raw_findings_count: number;
  error?: string | null;
}

export class SemgrepAnalysisService {
  private executable: string;

  constructor(executable = 'semgrep') {
    this.executable = executable;
  }

  /**
   * Genuine availability check using host PATH and semgrep --version.
   */
  async checkAvailability(): Promise<{
    available: boolean;
    status: 'AVAILABLE' | 'NOT_INSTALLED' | 'BROKEN';
    path: string | null;
    version: string | null;
    error: string | null;
  }> {
    let detectedPath: string | null = null;
    try {
      const out = resolveExecutable(this.executable);
      if (out) {
        detectedPath = out;
      }
    } catch {
      return {
        available: false,
        status: 'NOT_INSTALLED',
        path: null,
        version: null,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
      };
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

    // Query version directly from binary
    try {
      const versionOut = execFileSync(detectedPath, ['--version'], {
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      const version = versionOut.split('\n')[0].trim();
      return {
        available: true,
        status: 'AVAILABLE',
        path: detectedPath,
        version,
        error: null,
      };
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
   * Parses a Semgrep JSON envelope. Returns null when the output is not a
   * Semgrep JSON object at all.
   */
  private parseSemgrepOutput(stdout: string): { results: any[]; errors: any[] } | null {
    if (!stdout || !stdout.trim().startsWith('{')) return null;
    try {
      const firstBrace = stdout.indexOf('{');
      const parsed = JSON.parse(stdout.slice(firstBrace));
      return {
        results: Array.isArray(parsed.results) ? parsed.results : [],
        errors: Array.isArray(parsed.errors) ? parsed.errors : [],
      };
    } catch {
      return null;
    }
  }

  /**
   * Executes genuine Semgrep CLI against checked-out source code.
   */
  async executeScan(
    targetDir: string,
    sourceSnapshotId: string,
    investigationId?: string,
    targetId?: string,
    customRulesYaml?: string
  ): Promise<{
    execution: SemgrepExecutionDetails;
    candidates: CandidateFinding[];
    artifactIds: string[];
  }> {
    const startTime = Date.now();
    const artifactIds: string[] = [];
    const candidates: CandidateFinding[] = [];

    const avail = await this.checkAvailability();
    if (!avail.available || !avail.path) {
      return {
        execution: {
          status: avail.status === 'NOT_INSTALLED' ? 'NOT_INSTALLED' : 'UNAVAILABLE',
          executable_path: avail.path,
          version: avail.version,
          command: `${this.executable} --version`,
          exit_code: 127,
          stdout: '',
          stderr: avail.error || 'Semgrep executable not found',
          duration_ms: Date.now() - startTime,
          raw_findings_count: 0,
          error: avail.error,
        },
        candidates: [],
        artifactIds: [],
      };
    }

    // Prepare temporary rule file in secure temp directory
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'intent-semgrep-'));
    const rulesPath = path.join(tempDir, 'rules.yaml');
    const rulesYaml = customRulesYaml || globalSecurityRuleRegistry.generateSemgrepConfig();
    fs.writeFileSync(rulesPath, rulesYaml, 'utf-8');

    // Resolve to an absolute path: cwd is set to this directory below, so a
    // relative scan root would be resolved from inside itself and rejected.
    const scanRoot = path.resolve(targetDir);

    // Sandboxed execution arguments (structured array, no shell interpolation)
    const args = [
      '--config',
      rulesPath,
      '--json',
      '--quiet',
      '--disable-version-check',
      '--no-git-ignore',
      scanRoot,
    ];

    const commandStr = `${avail.path} ${args.join(' ')}`;
    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    let executionStatus: 'COMPLETED' | 'FAILED' = 'COMPLETED';

    // Environment sandboxing: strip sensitive secrets, provide clean minimal PATH
    const sandboxedEnv: Record<string, string> = {
      PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
      HOME: tempDir,
      TMPDIR: tempDir,
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      SEMGREP_SEND_METRICS: 'off',
    };

    try {
      stdout = execFileSync(avail.path, args, {
        cwd: targetDir,
        env: sandboxedEnv,
        encoding: 'utf-8',
        timeout: 60000, // 60s limit
        maxBuffer: 20 * 1024 * 1024, // 20MB buffer limit
      });
      exitCode = 0;
    } catch (err: any) {
      exitCode = typeof err.status === 'number' ? err.status : 1;
      stdout = err.stdout ? err.stdout.toString('utf-8') : '';
      stderr = err.stderr ? err.stderr.toString('utf-8') : err.message;
      // Semgrep exits 0 on a clean scan and 1 when findings are present; both
      // mean the scan really ran. Any other code is a genuine failure.
      // Its error envelope is also JSON, so presence of stdout alone is not
      // proof of success — only a parseable JSON object with no `errors`
      // entries counts as a completed scan.
      const parseable = this.parseSemgrepOutput(stdout);
      if (!parseable || parseable.errors.length > 0) {
        executionStatus = 'FAILED';
        if (!stderr && parseable && parseable.errors.length > 0) {
          stderr = parseable.errors.map((e: any) => e.message || JSON.stringify(e)).join('\n');
        }
      }
    } finally {
      // Clean up temporary rule file
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup error
      }
    }

    const durationMs = Date.now() - startTime;

    // Register raw process streams as evidence artifacts
    let stdoutArtifactId: string | undefined;
    let stderrArtifactId: string | undefined;

    if (investigationId) {
      try {
        const stdoutArtifact = createEvidenceArtifact({
          investigation_id: investigationId,
          target_id: targetId,
          artifact_type: ArtifactType.ENGINE_STDOUT,
          producer: 'semgrep',
          producer_version: avail.version || 'unknown',
          source_snapshot_id: sourceSnapshotId,
          command: commandStr,
          working_directory: targetDir,
          content: stdout || '<empty>',
          filename: `semgrep_stdout_${Date.now()}.json`,
          mime_type: 'application/json',
          metadata: { exit_code: exitCode, duration_ms: durationMs },
        });
        stdoutArtifactId = stdoutArtifact.id;
        artifactIds.push(stdoutArtifact.id);
      } catch (err) {
        console.error('Failed to store stdout artifact:', err);
      }

      if (stderr) {
        try {
          const stderrArtifact = createEvidenceArtifact({
            investigation_id: investigationId,
            target_id: targetId,
            artifact_type: ArtifactType.ENGINE_STDERR,
            producer: 'semgrep',
            producer_version: avail.version || 'unknown',
            source_snapshot_id: sourceSnapshotId,
            command: commandStr,
            working_directory: targetDir,
            content: stderr,
            filename: `semgrep_stderr_${Date.now()}.log`,
            mime_type: 'text/plain',
            metadata: { exit_code: exitCode, duration_ms: durationMs },
          });
          stderrArtifactId = stderrArtifact.id;
          artifactIds.push(stderrArtifact.id);
        } catch (err) {
          console.error('Failed to store stderr artifact:', err);
        }
      }
    }

    // Parse Semgrep JSON findings
    let rawFindingsCount = 0;
    try {
      if (stdout && stdout.trim().startsWith('{')) {
        const parsed = JSON.parse(stdout.slice(stdout.indexOf('{')));
        const results = parsed.results || [];
        rawFindingsCount = results.length;

        for (const item of results) {
          const ruleId = item.check_id;
          const rule = globalSecurityRuleRegistry.get(ruleId);
          const relPath = path.isAbsolute(item.path) ? path.relative(targetDir, item.path) : item.path;
          const candidateId = `cand-sg-${ruleId}-${crypto.randomBytes(4).toString('hex')}`;

          const candidate: CandidateFinding = {
            id: candidateId,
            investigation_id: investigationId || 'inv-unknown',
            target_id: targetId || 'tgt-unknown',
            title: ruleId,
            category: rule?.category || (item.extra?.metadata?.category as any) || (ruleId.includes('BOLA') ? StaticRuleCategory.BOLA : StaticRuleCategory.ACCESS_CONTROL),
            severity: rule?.severity || Severity.HIGH,
            status: FindingStatus.CANDIDATE, // STRICT INVARIANT: Always starts at CANDIDATE
            confidence: rule?.confidence || Confidence.MEDIUM,
            confidence_basis: `Semgrep rule ${ruleId} matched syntactic/dataflow pattern: ${item.extra?.message || 'pattern match'}`,
            engine: 'semgrep',
            engine_version: avail.version || '1.176.0',
            rule_id: ruleId,
            rule_version: rule?.version || '1.0.0',
            source_snapshot_id: sourceSnapshotId,
            file_path: relPath,
            line_start: item.start?.line || 1,
            line_end: item.end?.line || item.start?.line || 1,
            column_start: item.start?.col,
            column_end: item.end?.col,
            matched_code: item.extra?.lines || '',
            data_flow: item.extra?.dataflow_trace ? {
              source: 'taint_source',
              flow: ['parameter', 'sink'],
              authorization: 'MISSING',
              sink: item.extra?.message,
            } : undefined,
            evidence_artifact_ids: stdoutArtifactId ? [stdoutArtifactId] : [],
            cwe_ids: rule?.cwe_ids || (item.extra?.metadata?.cwe ? [item.extra.metadata.cwe] : []),
            owasp_categories: rule?.owasp_categories || (item.extra?.metadata?.owasp ? [item.extra.metadata.owasp] : []),
            remediation: rule?.remediation || 'Implement required security validations.',
            corroborated: false,
            status_history: [
              {
                from_status: null,
                to_status: FindingStatus.CANDIDATE,
                timestamp: new Date().toISOString(),
                actor: 'engine:semgrep',
                reason: 'Initial candidate creation from Semgrep rule match',
              },
            ],
            provenance: {
              source_snapshot_id: sourceSnapshotId,
              engine: 'semgrep',
              engine_version: avail.version || '1.176.0',
              rule_id: ruleId,
              rule_version: rule?.version || '1.0.0',
              matched_at: new Date().toISOString(),
              source_file: relPath,
              line: item.start?.line || 1,
            },
            metadata: {
              semgrep_metadata: item.extra?.metadata,
              dataflow_trace: item.extra?.dataflow_trace,
            },
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          };

          candidates.push(candidate);
        }
      }
    } catch (err: any) {
      console.error('Failed to parse Semgrep JSON output:', err);
    }

    return {
      execution: {
        status: executionStatus,
        executable_path: avail.path,
        version: avail.version,
        command: commandStr,
        exit_code: exitCode,
        stdout: stdout.slice(0, 5000), // Preview
        stderr: stderr.slice(0, 5000),
        stdout_artifact_id: stdoutArtifactId,
        stderr_artifact_id: stderrArtifactId,
        duration_ms: durationMs,
        raw_findings_count: rawFindingsCount,
        error: stderr ? stderr.slice(0, 500) : null,
      },
      candidates,
      artifactIds,
    };
  }
}

export const globalSemgrepService = new SemgrepAnalysisService();
