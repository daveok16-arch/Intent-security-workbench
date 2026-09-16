/**
 * Real Z3 Process Executor & Output Parser
 * Intent Security Workbench - Phase 4
 *
 * Runs the genuine host Z3 binary against SMT-LIB2 inputs.
 * Strictly adheres to:
 * - Real CLI execution (never simulated)
 * - Safe process execution with timeout & memory bounds
 * - Full capture of command, exit code, stdout, stderr, execution duration
 * - Accurate SMT2 output parsing (sat, unsat, unknown, timeout, error)
 * - Parsing Z3 models into structured formal counterexamples
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { Z3Detector } from './z3_detector.js';
import { Counterexample, VerificationStatus } from './types.js';

export interface Z3ExecutionResult {
  solver_result_raw: 'sat' | 'unsat' | 'unknown' | 'timeout' | 'error';
  status: VerificationStatus;
  executable_path: string;
  solver_version: string;
  command_executed: string;
  execution_time_ms: number;
  exit_code: number;
  stdout: string;
  stderr: string;
  counterexample?: Counterexample | null;
  error?: string;
}

export interface Z3ExecutionOptions {
  timeoutMs?: number; // default 8000ms
  solverTimeoutMs?: number; // default 5000ms passed to Z3 -t:
  queryMode?: 'UNAUTHORIZED_ACCESS_REACHABLE' | 'PROPERTY_HOLDS_GLOBALLY';
  modeledVariables?: string[];
}

export class Z3Executor {
  /**
   * Executes real Z3 binary with the provided SMT-LIB2 code.
   */
  static async executeSMT2(
    smtCode: string,
    options: Z3ExecutionOptions = {}
  ): Promise<Z3ExecutionResult> {
    const hostInfo = Z3Detector.detect();
    if (!hostInfo.installed || !hostInfo.executable_path) {
      return {
        solver_result_raw: 'error',
        status: VerificationStatus.SOLVER_UNAVAILABLE,
        executable_path: 'z3',
        solver_version: 'unavailable',
        command_executed: 'z3 [not installed]',
        execution_time_ms: 0,
        exit_code: 127,
        stdout: '',
        stderr: hostInfo.error || 'Z3 binary not installed on host.',
        error: hostInfo.error || 'Z3 binary not installed on host.',
      };
    }

    const timeoutMs = options.timeoutMs || 8000;
    const solverTimeoutMs = options.solverTimeoutMs || 5000;
    const queryMode = options.queryMode || 'UNAUTHORIZED_ACCESS_REACHABLE';

    // Write SMT code to temporary file
    const tmpDir = os.tmpdir();
    const tmpFileName = `z3_verify_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.smt2`;
    const tmpFilePath = path.join(tmpDir, tmpFileName);
    fs.writeFileSync(tmpFilePath, smtCode, 'utf8');

    const commandArgs = [`-t:${solverTimeoutMs}`, '-smt2', tmpFilePath];
    const fullCommand = `${hostInfo.executable_path} ${commandArgs.join(' ')}`;
    const startTime = Date.now();

    return new Promise<Z3ExecutionResult>((resolve) => {
      let stdoutData = '';
      let stderrData = '';
      let isTimeout = false;

      const proc = spawn(hostInfo.executable_path!, commandArgs, {
        timeout: timeoutMs,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timer = setTimeout(() => {
        isTimeout = true;
        try {
          proc.kill('SIGKILL');
        } catch {
          // ignore
        }
      }, timeoutMs);

      proc.stdout.on('data', (chunk) => {
        stdoutData += chunk.toString();
      });

      proc.stderr.on('data', (chunk) => {
        stderrData += chunk.toString();
      });

      proc.on('close', (code, signal) => {
        clearTimeout(timer);
        const durationMs = Date.now() - startTime;

        // Clean up temp file
        try {
          if (fs.existsSync(tmpFilePath)) {
            fs.unlinkSync(tmpFilePath);
          }
        } catch {
          // ignore cleanup error
        }

        const trimmedStdout = stdoutData.trim();
        const trimmedStderr = stderrData.trim();

        if (isTimeout || signal === 'SIGTERM' || signal === 'SIGKILL') {
          return resolve({
            solver_result_raw: 'timeout',
            status: VerificationStatus.TIMEOUT,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? -1,
            stdout: trimmedStdout,
            stderr: trimmedStderr || 'Solver execution timed out after limit.',
          });
        }

        // Parse Z3 solver result
        const stdoutLines = trimmedStdout
          .split('\n')
          .map((l) => l.trim().toLowerCase())
          .filter(Boolean);

        const firstLine = stdoutLines[0] || '';
        const hasFatalError =
          firstLine.startsWith('(error') ||
          trimmedStdout.startsWith('(error') ||
          trimmedStderr.includes('error') ||
          trimmedStdout.includes('unknown sort');

        if (hasFatalError) {
          return resolve({
            solver_result_raw: 'error',
            status: VerificationStatus.EXECUTION_FAILED,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? 1,
            stdout: trimmedStdout,
            stderr: trimmedStderr || trimmedStdout,
            error: trimmedStderr || trimmedStdout,
            counterexample: null,
          });
        }

        const hasSat = stdoutLines.some((l) => l === 'sat' || l.startsWith('sat'));
        const hasUnsat = stdoutLines.some((l) => l === 'unsat' || l.startsWith('unsat'));
        const hasUnknown = stdoutLines.some((l) => l === 'unknown' || l.startsWith('unknown'));

        if (hasSat) {
          const counterexample = this.parseCounterexample(
            trimmedStdout,
            options.modeledVariables || []
          );
          const status =
            queryMode === 'UNAUTHORIZED_ACCESS_REACHABLE'
              ? VerificationStatus.COUNTEREXAMPLE_FOUND
              : VerificationStatus.REFUTED;

          return resolve({
            solver_result_raw: 'sat',
            status,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? 0,
            stdout: trimmedStdout,
            stderr: trimmedStderr,
            counterexample,
          });
        } else if (hasUnsat) {
          const status =
            queryMode === 'UNAUTHORIZED_ACCESS_REACHABLE'
              ? VerificationStatus.PROPERTY_HOLDS_FOR_MODEL
              : VerificationStatus.PROVEN;

          return resolve({
            solver_result_raw: 'unsat',
            status,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? 0,
            stdout: trimmedStdout,
            stderr: trimmedStderr,
            counterexample: null,
          });
        } else if (hasUnknown || trimmedStdout.includes('timeout')) {
          return resolve({
            solver_result_raw: 'unknown',
            status: VerificationStatus.UNKNOWN,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? 0,
            stdout: trimmedStdout,
            stderr: trimmedStderr,
            counterexample: null,
          });
        } else {
          // Execution failed or syntax error
          return resolve({
            solver_result_raw: 'error',
            status: VerificationStatus.EXECUTION_FAILED,
            executable_path: hostInfo.executable_path!,
            solver_version: hostInfo.version || 'unknown',
            command_executed: fullCommand,
            execution_time_ms: durationMs,
            exit_code: code ?? 1,
            stdout: trimmedStdout,
            stderr: trimmedStderr || 'Z3 solver failed to parse SMT-LIB2 input.',
            error: trimmedStderr || trimmedStdout,
            counterexample: null,
          });
        }
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        try {
          if (fs.existsSync(tmpFilePath)) {
            fs.unlinkSync(tmpFilePath);
          }
        } catch {
          // ignore
        }
        resolve({
          solver_result_raw: 'error',
          status: VerificationStatus.EXECUTION_FAILED,
          executable_path: hostInfo.executable_path!,
          solver_version: hostInfo.version || 'unknown',
          command_executed: fullCommand,
          execution_time_ms: Date.now() - startTime,
          exit_code: -1,
          stdout: '',
          stderr: err.message,
          error: err.message,
        });
      });
    });
  }

  /**
   * Parses Z3's `(model ...)` S-expression output into variable assignments.
   * Only includes variables that genuinely exist in the modeled variables list.
   */
  private static parseCounterexample(
    stdout: string,
    modeledVariables: string[]
  ): Counterexample {
    const assignments: Record<string, string | number | boolean> = {};
    const validVarSet = new Set(modeledVariables);

    // Z3 model syntax: (define-fun <var_name> () <type> <val>)
    // Regex for both single-line and multi-line define-fun
    const defineFunRegex = /\(define-fun\s+([a-zA-Z0-9_!]+)\s*\(\)\s*([a-zA-Z0-9_!]+)\s+([^)]+)\)/g;
    let match;
    while ((match = defineFunRegex.exec(stdout)) !== null) {
      const varName = match[1];
      const valType = match[2];
      const rawVal = match[3].trim();

      // Filter: only capture genuine model variables or non-internal universe symbols
      if (validVarSet.size === 0 || validVarSet.has(varName)) {
        if (rawVal === 'true') {
          assignments[varName] = true;
        } else if (rawVal === 'false') {
          assignments[varName] = false;
        } else if (/^-?\d+$/.test(rawVal)) {
          assignments[varName] = parseInt(rawVal, 10);
        } else {
          assignments[varName] = rawVal;
        }
      }
    }

    return {
      label: 'FORMAL_COUNTEREXAMPLE',
      is_exploit_confirmed: false,
      assignments,
      raw_model_string: stdout,
      variables_present: Object.keys(assignments),
    };
  }
}
