/**
 * Tree-sitter Security Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Real incremental concrete syntax tree parser and structural security analysis engine.
 * Powered by web-tree-sitter with precompiled WASM grammars.
 */

import path from 'path';
import fs from 'fs';
import { BaseEngine } from '../base_engine.js';
import {
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineAvailabilityStatus,
  EngineAvailability,
  EngineArtifact,
} from '../types.js';
import { globalTreeSitterService } from '../../packages/static-analysis/src/treesitter_service.js';
import { resolveExecutable } from '../../packages/config/src/binary_resolver.js';

export class TreeSitterEngine extends BaseEngine {
  readonly engine_id = 'treesitter';
  readonly name = 'Tree-sitter';
  readonly version = '0.20.8';
  readonly description = 'Incremental parsing system for building concrete syntax trees and running AST structural queries.';
  readonly executable: string;
  readonly capabilities = ['parsing', 'CST', 'syntax queries', 'structural_analysis', 'ast_artifacts'];
  readonly supported_target_types = ['SMART_CONTRACT', 'PROTOCOL', 'WEB_APPLICATION', 'REST_API', 'BINARY_NODE', 'LIBRARY'];
  readonly supported_languages = ['javascript', 'typescript', 'solidity', 'python', 'go', 'rust', 'c', 'cpp', 'java', 'ruby', 'bash'];

  private customWasmsDir?: string;

  constructor(executable = 'tree-sitter', customWasmsDir?: string) {
    super();
    this.executable = executable;
    this.customWasmsDir = customWasmsDir;
  }

  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();
    
    // Parsing runs on bundled WASM grammars, so the default 'tree-sitter'
    // identifier is nominal. A caller-supplied executable name is treated as a
    // real host dependency and must genuinely resolve.
    if (this.executable !== 'tree-sitter' && !resolveExecutable(this.executable)) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        capabilities: this.capabilities,
      };
    }

    try {
      const initialized = await globalTreeSitterService.init();
      const wasmsDir = this.customWasmsDir || globalTreeSitterService.wasmsDirectory;
      const hasWasms = fs.existsSync(wasmsDir);

      if (initialized && hasWasms) {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.AVAILABLE,
          executable: this.executable,
          detected_path: wasmsDir,
          version: this.version,
          checked_at,
          error: null,
          capabilities: this.capabilities,
        };
      }

      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.UNAVAILABLE,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: 'Tree-sitter WASM grammars directory not found.',
        capabilities: this.capabilities,
      };
    } catch (err: any) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.BROKEN,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Tree-sitter initialization failed: ${err.message}`,
        capabilities: this.capabilities,
      };
    }
  }

  async prepare(targetId: string, context: Record<string, any>): Promise<boolean> {
    const avail = await this.check_availability();
    return avail.status === EngineAvailabilityStatus.AVAILABLE;
  }

  async execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult> {
    const avail = await this.check_availability();
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    if (avail.status !== EngineAvailabilityStatus.AVAILABLE) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.UNAVAILABLE,
        target_id: targetId,
        investigation_id: context.investigation_id,
        command: `${this.executable} ${operation} [attempted]`,
        working_directory: context.working_directory || process.cwd(),
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: 0,
        exit_code: 127,
        stdout: '',
        stderr: avail.error || `Tree-sitter engine is not available.`,
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: `ENGINE_UNAVAILABLE: ${this.name} (${this.executable}) is not installed or available on host.`,
      };
    }

    const sourceDir = context.source_directory || context.working_directory || process.cwd();
    const sourceSnapshotId = context.source_snapshot_id || 'snap-unknown';
    const investigationId = context.investigation_id;

    try {
      const scan = await globalTreeSitterService.scanDirectory(
        sourceDir,
        sourceSnapshotId,
        investigationId,
        targetId
      );

      const findings: EngineFinding[] = scan.candidates.map(c => ({
        id: c.id,
        title: c.title,
        description: c.confidence_basis,
        severity: c.severity,
        category: c.category,
        cwe: c.cwe_ids,
        owasp: c.owasp_categories,
        confidence: c.confidence,
        file: c.file_path,
        line_start: c.line_start,
        line_end: c.line_end,
        evidence: c.matched_code,
        metadata: {
          structural_evidence: c.structural_evidence,
          data_flow: c.data_flow,
        },
      }));

      const artifacts: EngineArtifact[] = scan.artifactIds.map(id => this.describeArtifact(id, 'AST', `ast/${id}`));

      const stdout = JSON.stringify({
        engine: this.name,
        version: this.version,
        files_scanned: scan.results.length,
        parse_errors: scan.results.reduce((acc, r) => acc + r.error_count, 0),
        structural_matches_count: scan.candidates.length,
      }, null, 2);

      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.SUCCESS,
        target_id: targetId,
        investigation_id: investigationId,
        command: `web-tree-sitter parse ${sourceDir}`,
        working_directory: sourceDir,
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - startMs,
        exit_code: 0,
        stdout,
        stderr: '',
        findings,
        artifacts,
        environment: this.getEnvironmentInfo(avail.detected_path),
      };
    } catch (err: any) {
      return {
        id: `res-${this.engine_id}-${Date.now()}`,
        engine_id: this.engine_id,
        engine_name: this.name,
        engine_version: this.version,
        status: EngineResultStatus.FAILED,
        target_id: targetId,
        investigation_id: investigationId,
        command: `web-tree-sitter parse ${sourceDir}`,
        working_directory: sourceDir,
        started_at: startTime,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - startMs,
        exit_code: 1,
        stdout: '',
        stderr: err.message || 'Tree-sitter parse failure',
        findings: [],
        artifacts: [],
        environment: this.getEnvironmentInfo(avail.detected_path),
        error: `TREE_SITTER_EXECUTION_FAILED: ${err.message}`,
      };
    }
  }

  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[] {
    try {
      if (!rawOutput.stdout) return [];
      const parsed = JSON.parse(rawOutput.stdout);
      return parsed.findings || [];
    } catch {
      return [];
    }
  }

  async cleanup(context: Record<string, any>): Promise<void> {}
}
