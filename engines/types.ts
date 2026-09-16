/**
 * Engine Abstraction Layer Types
 * Intent Security Workbench - Phase 0.1
 *
 * Strict Invariant:
 * Engines must distinguish between AVAILABLE, NOT_INSTALLED, UNAVAILABLE, and BROKEN.
 * A missing engine must NEVER be represented as successful or available.
 */

import { Severity, Confidence } from '../packages/core/src/index.js';

export enum EngineAvailabilityStatus {
  AVAILABLE = 'AVAILABLE',
  NOT_INSTALLED = 'NOT_INSTALLED',
  UNAVAILABLE = 'UNAVAILABLE',
  BROKEN = 'BROKEN',
}

export enum EngineResultStatus {
  SUCCESS = 'SUCCESS',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
  UNAVAILABLE = 'UNAVAILABLE',
}

export enum EngineExecutionState {
  READY = 'READY',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

export interface EngineAvailability {
  engine_id: string;
  name: string;
  status: EngineAvailabilityStatus;
  executable: string;
  detected_path: string | null;
  version: string | null;
  checked_at: string;
  error: string | null;
  capabilities: string[];
}

export interface EngineFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity | string;
  category: string;
  cwe?: string[];
  owasp?: string[];
  confidence: Confidence | string;
  file: string;
  line_start?: number;
  line_end?: number;
  evidence?: string;
  metadata?: Record<string, any>;
}

export interface EngineArtifact {
  id: string;
  type: string;
  path: string;
  sha256: string;
  size: number;
  mime_type: string;
  created_at: string;
  metadata?: Record<string, any>;
}

export interface EngineResult {
  id: string;
  engine_id: string;
  engine_name: string;
  engine_version: string;
  status: EngineResultStatus;
  target_id: string;
  investigation_id?: string;
  command: string;
  working_directory: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  exit_code: number;
  stdout: string;
  stderr: string;
  findings: EngineFinding[];
  artifacts: EngineArtifact[];
  environment: {
    hostname: string;
    os: string;
    node_version: string;
    executable_path?: string | null;
    [key: string]: any;
  };
  error?: string | null;
}

export interface IEngine {
  readonly name: string;
  readonly engine_id: string;
  readonly version: string;
  readonly description: string;
  readonly capabilities: string[];
  readonly supported_target_types: string[];
  readonly supported_languages: string[];
  readonly executable: string;

  check_availability(): Promise<EngineAvailability>;
  get_version(): Promise<string | null>;
  prepare(targetId: string, context: Record<string, any>): Promise<boolean>;
  execute(targetId: string, operation: string, context: Record<string, any>): Promise<EngineResult>;
  parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[];
  cleanup(context: Record<string, any>): Promise<void>;
}
