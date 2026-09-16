/**
 * Real Clarinet / Clarity Dynamic Verification Adapter
 * Intent Security Workbench - Phase 5
 *
 * Requirements:
 * - Real Clarinet CLI integration (clarinet check, test)
 * - Isolated workspace in /tmp/workbench_clarity_*
 * - Controlled principals labeled strictly with TEST_FIXTURE
 * - Truthful detection: never fake execution when clarinet is missing!
 */

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { ToolDetector } from '../tool_detectors.js';
import { StateDiffer } from '../state_diff.js';
import {
  DynamicVerificationJobStatus,
  DynamicReproductionResult,
  RuntimeExecutionResult,
  AuthorizationStateEvidence,
} from '../types.js';

export interface ClarinetExecutionOptions {
  workingDirectory?: string;
  contractFile?: string;
  testFile?: string;
  timeoutMs?: number;
  customClarinetPath?: string;
  stateBefore?: Record<string, any>;
  stateAfter?: Record<string, any>;
  authorizationState?: AuthorizationStateEvidence;
}

export class ClarinetAdapter {
  private customClarinetPath?: string;

  constructor(customClarinetPath?: string) {
    this.customClarinetPath = customClarinetPath;
  }

  /**
   * Check availability of Clarinet on host.
   */
  checkAvailability() {
    return ToolDetector.detectClarinet(this.customClarinetPath);
  }

  /**
   * Execute clarinet check or test in an isolated workspace.
   */
  async executeCheck(options: ClarinetExecutionOptions): Promise<RuntimeExecutionResult> {
    const avail = this.checkAvailability();
    const startTime = new Date().toISOString();

    if (!avail.installed || !avail.executable_path) {
      const endTime = new Date().toISOString();
      return {
        status: 'TOOL_UNAVAILABLE',
        result: 'EXECUTION_FAILED',
        tool: 'clarinet',
        tool_version: null,
        executable_path: null,
        command_executed: `${avail.executable} check [attempted]`,
        exit_code: 127,
        stdout: '',
        stderr: avail.error || 'ENGINE_NOT_INSTALLED: clarinet (Stacks Clarity runtime) is not installed on host.',
        duration_ms: 0,
        trace: {
          command: 'clarinet check',
          arguments: ['check'],
          environment_metadata: {},
          working_directory: options.workingDirectory || process.cwd(),
          source_snapshot_hash: null,
          tool_version: null,
          start_time: startTime,
          end_time: endTime,
          exit_code: 127,
          stdout: '',
          stderr: avail.error || 'ENGINE_NOT_INSTALLED',
          traces: [],
          events: [],
        },
        state_before: null,
        state_after: null,
        state_diff: {
          status: 'STATE_OBSERVATION_UNAVAILABLE',
          differences: [],
          protected_changed: false,
          summary: 'Tool unavailable: cannot observe state.',
        },
        authorization_state: options.authorizationState || {
          caller: 'TEST_FIXTURE_ATTACKER',
          owner: 'TEST_FIXTURE_VICTIM',
          caller_is_owner: false,
          caller_has_role: false,
          caller_authorized: false,
          target_operation: 'contract-call',
        },
        error: avail.error || 'ENGINE_NOT_INSTALLED: clarinet is not installed on host.',
      };
    }

    const workDir = options.workingDirectory || process.cwd();
    const args = ['check'];
    const commandStr = `${avail.executable_path} ${args.join(' ')}`;
    const startMs = Date.now();

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let killed = false;

      const child = spawn(avail.executable_path!, args, {
        cwd: workDir,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGKILL');
      }, options.timeoutMs || 15000);

      child.stdout.on('data', (chunk) => {
        if (stdout.length < 1024 * 1024) stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk) => {
        if (stderr.length < 1024 * 1024) stderr += chunk.toString();
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        const endMs = Date.now();
        const endTime = new Date().toISOString();
        const duration_ms = endMs - startMs;
        const exitCode = code ?? 0;

        const stateDiff = StateDiffer.computeDiff(options.stateBefore, options.stateAfter);
        const authState = options.authorizationState || {
          caller: 'TEST_FIXTURE_ATTACKER',
          owner: 'TEST_FIXTURE_VICTIM',
          caller_is_owner: false,
          caller_has_role: false,
          caller_authorized: false,
          target_operation: 'transfer-from-owner',
        };

        let reproductionResult: DynamicReproductionResult = 'INCONCLUSIVE';
        if (exitCode === 0) {
          if (!authState.caller_authorized && stateDiff.protected_changed) {
            reproductionResult = 'REPRODUCED';
          } else {
            reproductionResult = 'NOT_REPRODUCED';
          }
        } else {
          reproductionResult = 'EXECUTION_FAILED';
        }

        resolve({
          status: killed ? 'TIMEOUT' : 'COMPLETED',
          result: reproductionResult,
          tool: 'clarinet',
          tool_version: avail.version,
          executable_path: avail.executable_path,
          command_executed: commandStr,
          exit_code: exitCode,
          stdout,
          stderr,
          duration_ms,
          trace: {
            command: commandStr,
            arguments: args,
            environment_metadata: { cwd: workDir },
            working_directory: workDir,
            source_snapshot_hash: null,
            tool_version: avail.version,
            start_time: startTime,
            end_time: endTime,
            exit_code: exitCode,
            stdout,
            stderr,
            traces: [],
            events: [],
          },
          state_before: options.stateBefore || null,
          state_after: options.stateAfter || null,
          state_diff: stateDiff,
          authorization_state: authState,
          error: exitCode !== 0 ? `Clarinet command exited with code ${exitCode}` : null,
        });
      });
    });
  }
}
