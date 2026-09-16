/**
 * Authoritative Configuration Architecture Types
 * Intent Security Workbench - Environment & Configuration Hardening
 */

export enum ConfigurationClassification {
  REQUIRED_SECRET = 'REQUIRED_SECRET',
  OPTIONAL_SECRET = 'OPTIONAL_SECRET',
  REQUIRED_CONFIGURATION = 'REQUIRED_CONFIGURATION',
  OPTIONAL_CONFIGURATION = 'OPTIONAL_CONFIGURATION',
  DERIVED_CONFIGURATION = 'DERIVED_CONFIGURATION',
  TEST_ONLY = 'TEST_ONLY',
  DEPRECATED_UNUSED = 'DEPRECATED_UNUSED',
}

export type Environment = 'development' | 'production' | 'test';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR';

export type AIProviderType = 'none' | 'gemini' | 'grok' | 'openai' | 'anthropic' | 'custom';

/**
 * Public Configuration — Safe for browser/frontend exposure.
 * Never contains credentials, internal paths, or secrets.
 */
export interface PublicConfiguration {
  environment: Environment;
  api_url: string;
  ws_url: string;
  app_name: string;
  api_version: string;
  sandbox_enforced: boolean;
  ai_provider_configured: boolean;
  ai_provider_name: AIProviderType;
}

/**
 * Server Configuration — Backend-only runtime settings.
 */
export interface ServerConfiguration {
  host: string;
  port: number;
  environment: Environment;
  log_level: LogLevel;
  database_configured: boolean;
  redis_configured: boolean;
  anti_fabrication_mode: 'enforced';
}

/**
 * Worker Configuration — Isolated background job queue settings.
 */
export interface WorkerConfiguration {
  concurrency: number;
  redis_configured: boolean;
  execution_mode: 'IN_PROCESS' | 'DISTRIBUTED_REDIS';
  job_timeout_ms: number;
}

/**
 * Secret Configuration — Raw credentials/tokens/passwords.
 * MUST NEVER be serialized, logged, exposed to frontend, or sent in AI prompts.
 */
export interface SecretConfiguration {
  database_url?: string;
  redis_url?: string;
  gemini_api_key?: string;
  grok_api_key?: string;
  openai_api_key?: string;
  anthropic_api_key?: string;
}

/**
 * AI Provider Configuration — Model selection and capability metadata.
 */
export interface AIProviderConfiguration {
  provider: AIProviderType;
  model: string;
  endpoint?: string;
  temperature?: number;
  max_tokens?: number;
  is_configured: boolean;
}

/**
 * Sandbox Configuration — Execution restrictions and resource limits.
 */
export interface SandboxConfiguration {
  allow_arbitrary_shell: boolean;
  require_explicit_target_scope: boolean;
  network_egress_restricted: boolean;
  timeout_ms: number;
  strict_scope_check: boolean;
}

/**
 * Diagnostic Service States
 */
export type DiagnosticStatus = 'CONNECTED' | 'NOT_CONFIGURED' | 'ERROR';
export type SandboxDiagnosticStatus = 'READY' | 'ERROR';
export type GitDiagnosticStatus = 'AVAILABLE' | 'UNAVAILABLE';
export type AIProviderDiagnosticStatus = 'CONFIGURED' | 'NOT_CONFIGURED';
export type WorkerDiagnosticStatus = 'READY' | 'BLOCKED';

export interface ConfigurationDiagnostics {
  database: DiagnosticStatus;
  redis: DiagnosticStatus;
  sandbox: SandboxDiagnosticStatus;
  git: GitDiagnosticStatus;
  ai_provider: AIProviderDiagnosticStatus;
  worker: WorkerDiagnosticStatus;
  details: {
    database_mode: 'IN_MEMORY' | 'POSTGRESQL';
    worker_mode: 'IN_PROCESS' | 'DISTRIBUTED_REDIS';
    sandbox_policy_enforced: boolean;
    git_version: string | null;
    ai_provider: AIProviderType;
    ai_model: string;
  };
}

export interface VariableMetadata {
  name: string;
  classification: ConfigurationClassification;
  description: string;
  consumed_by: string;
  is_secret: boolean;
  safe_for_frontend: boolean;
  safe_default: string | number | boolean | null;
  required_in_production: boolean;
  feature_flag?: string;
}

export interface ConfigValidationError {
  variable: string;
  service: string;
  is_secret: boolean;
  message: string;
  resolution: string;
}
