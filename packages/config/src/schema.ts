/**
 * Authoritative Configuration Schema & Validation Engine
 * Intent Security Workbench - Environment & Configuration Hardening
 */

import {
  ConfigurationClassification,
  Environment,
  LogLevel,
  AIProviderType,
  PublicConfiguration,
  ServerConfiguration,
  WorkerConfiguration,
  SecretConfiguration,
  AIProviderConfiguration,
  SandboxConfiguration,
  VariableMetadata,
  ConfigValidationError,
} from './types.js';
import { isSecretKey, redactSecret, redactUriCredentials } from './redaction.js';

/**
 * Complete authoritative registry of all workbench environment variables.
 */
export const VARIABLE_INVENTORY: Record<string, VariableMetadata> = {
  DATABASE_URL: {
    name: 'DATABASE_URL',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'PostgreSQL connection string for persistent storage. Falls back to in-memory store if unset.',
    consumed_by: 'DatabaseStore (server/db)',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
  },
  REDIS_URL: {
    name: 'REDIS_URL',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'Redis connection string for distributed background task queue. In-process queue used if unset.',
    consumed_by: 'JobOrchestrator / Celery worker',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
  },
  API_PORT: {
    name: 'API_PORT',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'HTTP and WebSocket server listen port.',
    consumed_by: 'server.ts',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 3000,
    required_in_production: false,
  },
  API_HOST: {
    name: 'API_HOST',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Network interface bind address for the API server.',
    consumed_by: 'server.ts',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: '0.0.0.0',
    required_in_production: false,
  },
  ENVIRONMENT: {
    name: 'ENVIRONMENT',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Deployment execution tier: development, production, or test.',
    consumed_by: 'server.ts, apps/api/python, logging',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'development',
    required_in_production: false,
  },
  NODE_ENV: {
    name: 'NODE_ENV',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Node runtime execution mode (development/production/test).',
    consumed_by: 'Node.js runtime, Vite build system',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'development',
    required_in_production: false,
  },
  LOG_LEVEL: {
    name: 'LOG_LEVEL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Minimum logging severity: DEBUG, INFO, WARN, ERROR.',
    consumed_by: 'Logger / JobOrchestrator',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'INFO',
    required_in_production: false,
  },
  API_URL: {
    name: 'API_URL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Local or remote HTTP URL for CLI API querying.',
    consumed_by: 'cli.ts',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'http://127.0.0.1:3000',
    required_in_production: false,
  },
  VITE_API_URL: {
    name: 'VITE_API_URL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Client-side public base URL for API requests. Defaults to relative /api in browser.',
    consumed_by: 'Web UI (React frontend)',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: '',
    required_in_production: false,
  },
  VITE_WS_URL: {
    name: 'VITE_WS_URL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Client-side public WebSocket URL for live event streaming. Defaults to window.location.',
    consumed_by: 'Web UI (React frontend)',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: '',
    required_in_production: false,
  },
  DISABLE_HMR: {
    name: 'DISABLE_HMR',
    classification: ConfigurationClassification.TEST_ONLY,
    description: 'Internal sandbox flag to disable Vite Hot Module Reload in container execution.',
    consumed_by: 'vite.config.ts',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'false',
    required_in_production: false,
  },
  SANDBOX_ALLOW_ARBITRARY_SHELL: {
    name: 'SANDBOX_ALLOW_ARBITRARY_SHELL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Security invariant: must remain false to forbid unrestricted shell execution.',
    consumed_by: 'SandboxBoundaryEnforcer',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: false,
    required_in_production: true,
  },
  SANDBOX_TIMEOUT_MS: {
    name: 'SANDBOX_TIMEOUT_MS',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Max duration in ms before child execution processes are terminated.',
    consumed_by: 'SandboxBoundaryEnforcer',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 120000,
    required_in_production: false,
  },
  SANDBOX_STRICT_SCOPE_CHECK: {
    name: 'SANDBOX_STRICT_SCOPE_CHECK',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Security invariant: enforces explicit target scope validation prior to scanning.',
    consumed_by: 'SandboxSecurityEnforcer',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: true,
    required_in_production: true,
  },
  AI_PROVIDER: {
    name: 'AI_PROVIDER',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Selected AI provider engine: none, gemini, grok, openai, anthropic.',
    consumed_by: 'AI Security Controller / AIProviderService',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'none',
    required_in_production: false,
  },
  AI_MODEL: {
    name: 'AI_MODEL',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Model identifier for AI Security analysis (e.g. gemini-3.8-flash).',
    consumed_by: 'AI Security Controller',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'gemini-3.8-flash',
    required_in_production: false,
  },
  AI_ENDPOINT: {
    name: 'AI_ENDPOINT',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Custom proxy endpoint URL for AI model queries (optional).',
    consumed_by: 'AI Security Controller',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
  },
  AI_TEMPERATURE: {
    name: 'AI_TEMPERATURE',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Sampling temperature for deterministic security reasoning (default 0.1).',
    consumed_by: 'AI Security Controller',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 0.1,
    required_in_production: false,
  },
  AI_MAX_TOKENS: {
    name: 'AI_MAX_TOKENS',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Maximum response tokens limit for AI analysis outputs.',
    consumed_by: 'AI Security Controller',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 4096,
    required_in_production: false,
  },
  GEMINI_API_KEY: {
    name: 'GEMINI_API_KEY',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'Google Gemini API key for AI Security Controller. Required only when AI_PROVIDER=gemini.',
    consumed_by: 'server.ts / AIProviderService',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
    feature_flag: 'AI_PROVIDER=gemini',
  },
  AUTH_TOKEN: {
    name: 'AUTH_TOKEN',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description:
      'Bearer token required on every /api route and the /ws handshake. When unset, authentication is disabled and any reachable client has full access.',
    consumed_by: 'server.ts / authorizeRequest',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: true,
  },
  ALLOWED_ORIGINS: {
    name: 'ALLOWED_ORIGINS',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description:
      'Comma-separated browser origin allowlist. Supports exact origins and a leading-dot suffix match (".example.com"); "*" allows any origin.',
    consumed_by: 'server.ts / isOriginAllowed',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
  },
  PERSISTENCE_ENABLED: {
    name: 'PERSISTENCE_ENABLED',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description:
      'Persist domain records to disk so work survives a process restart. When false, all state is in-memory and is lost on restart.',
    consumed_by: 'apps/api/persistence.ts',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: true,
    required_in_production: false,
  },
  PERSISTENCE_DIR: {
    name: 'PERSISTENCE_DIR',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Directory holding the workbench state snapshot file.',
    consumed_by: 'apps/api/persistence.ts',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'storage/db',
    required_in_production: false,
  },
  PERSISTENCE_DEBOUNCE_MS: {
    name: 'PERSISTENCE_DEBOUNCE_MS',
    classification: ConfigurationClassification.OPTIONAL_CONFIGURATION,
    description: 'Debounce window in milliseconds for coalescing snapshot writes.',
    consumed_by: 'apps/api/persistence.ts',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 150,
    required_in_production: false,
  },
  GROK_API_KEY: {
    name: 'GROK_API_KEY',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'xAI Grok API key for AI Security Controller. Required only when AI_PROVIDER=grok.',
    consumed_by: 'AIProviderService',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
    feature_flag: 'AI_PROVIDER=grok',
  },
  OPENAI_API_KEY: {
    name: 'OPENAI_API_KEY',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'OpenAI API key for AI Security Controller. Required only when AI_PROVIDER=openai.',
    consumed_by: 'AIProviderService',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
    feature_flag: 'AI_PROVIDER=openai',
  },
  ANTHROPIC_API_KEY: {
    name: 'ANTHROPIC_API_KEY',
    classification: ConfigurationClassification.OPTIONAL_SECRET,
    description: 'Anthropic API key for AI Security Controller. Required only when AI_PROVIDER=anthropic.',
    consumed_by: 'AIProviderService',
    is_secret: true,
    safe_for_frontend: false,
    safe_default: null,
    required_in_production: false,
    feature_flag: 'AI_PROVIDER=anthropic',
  },
  PATH: {
    name: 'PATH',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Host system path for locating verification tool executables (z3, forge, semgrep).',
    consumed_by: 'Engine availability detection and subprocess execution',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: '/usr/local/bin:/usr/bin:/bin',
    required_in_production: true,
  },
  HOSTNAME: {
    name: 'HOSTNAME',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Host identifier for Git snapshot provenance tracking.',
    consumed_by: 'GitSourceProvider',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'workbench-engine',
    required_in_production: false,
  },
  GIT_COMMIT: {
    name: 'GIT_COMMIT',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Repository commit hash for /api/version telemetry.',
    consumed_by: 'apps/api/python, server.ts',
    is_secret: false,
    safe_for_frontend: true,
    safe_default: 'phase0-foundational',
    required_in_production: false,
  },
  FOUNDRY_DISABLE_AUTO_UPDATE: {
    name: 'FOUNDRY_DISABLE_AUTO_UPDATE',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Prevents forge from attempting network updates during test runs.',
    consumed_by: 'FoundryAdapter',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'true',
    required_in_production: false,
  },
  GIT_TERMINAL_PROMPT: {
    name: 'GIT_TERMINAL_PROMPT',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Prevents git clone from hanging on terminal authentication prompts.',
    consumed_by: 'GitSourceProvider',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: '0',
    required_in_production: false,
  },
  SEMGREP_SEND_METRICS: {
    name: 'SEMGREP_SEND_METRICS',
    classification: ConfigurationClassification.DERIVED_CONFIGURATION,
    description: 'Disables telemetry when executing semgrep scans.',
    consumed_by: 'SemgrepService',
    is_secret: false,
    safe_for_frontend: false,
    safe_default: 'off',
    required_in_production: false,
  },
};

/**
 * Validates environment variables according to Intent Security Workbench rules.
 * Never leaks secret values in error messages.
 */
export function validateEnvironment(env: Record<string, string | undefined> = process.env): {
  valid: boolean;
  errors: ConfigValidationError[];
  warnings: string[];
} {
  const errors: ConfigValidationError[] = [];
  const warnings: string[] = [];

  const environment = (env.ENVIRONMENT || env.NODE_ENV || 'development').toLowerCase() as Environment;
  const isProduction = environment === 'production';

  // 1. Port Validation
  const portStr = env.API_PORT || '3000';
  const port = parseInt(portStr, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    errors.push({
      variable: 'API_PORT',
      service: 'Server (HTTP/WebSocket)',
      is_secret: false,
      message: `Invalid API_PORT '${portStr}'. Must be an integer between 1 and 65535.`,
      resolution: 'Set API_PORT to a valid port number, e.g. API_PORT=3000',
    });
  }

  // 2. Sandbox Security Invariants
  const allowArbitraryShell = env.SANDBOX_ALLOW_ARBITRARY_SHELL;
  if (allowArbitraryShell === 'true') {
    errors.push({
      variable: 'SANDBOX_ALLOW_ARBITRARY_SHELL',
      service: 'SandboxBoundaryEnforcer',
      is_secret: false,
      message: 'SANDBOX_ALLOW_ARBITRARY_SHELL=true violates the Phase 0 security boundary policy.',
      resolution: 'Set SANDBOX_ALLOW_ARBITRARY_SHELL=false or unset it to enforce containment.',
    });
  }

  const timeoutMsStr = env.SANDBOX_TIMEOUT_MS;
  if (timeoutMsStr) {
    const timeout = parseInt(timeoutMsStr, 10);
    if (isNaN(timeout) || timeout < 1000) {
      errors.push({
        variable: 'SANDBOX_TIMEOUT_MS',
        service: 'SandboxBoundaryEnforcer',
        is_secret: false,
        message: `SANDBOX_TIMEOUT_MS must be at least 1000ms. Received: '${timeoutMsStr}'`,
        resolution: 'Set SANDBOX_TIMEOUT_MS to a value >= 1000 (e.g. 120000)',
      });
    }
  }

  // 3. Database URL Validation (if configured)
  const dbUrl = env.DATABASE_URL;
  if (dbUrl) {
    if (!dbUrl.startsWith('postgresql://') && !dbUrl.startsWith('postgres://')) {
      errors.push({
        variable: 'DATABASE_URL',
        service: 'DatabaseStore',
        is_secret: true,
        message: 'DATABASE_URL is configured but is not a valid PostgreSQL URI.',
        resolution: 'Configure a valid PostgreSQL URI (e.g. postgresql://user:pass@host:5432/db) or unset to use in-memory store.',
      });
    }
  } else if (isProduction) {
    warnings.push('DATABASE_URL is not set in production. In-memory ephemeral storage will be used.');
  }

  // 4. Redis URL Validation (if configured)
  const redisUrl = env.REDIS_URL;
  if (redisUrl) {
    if (!redisUrl.startsWith('redis://') && !redisUrl.startsWith('rediss://')) {
      errors.push({
        variable: 'REDIS_URL',
        service: 'JobOrchestrator',
        is_secret: true,
        message: 'REDIS_URL is configured but does not start with redis:// or rediss://.',
        resolution: 'Configure a valid Redis URI or unset to use in-process job queue.',
      });
    }
  }

  // 5. AI Provider Validation
  const rawProvider = (env.AI_PROVIDER || 'none').toLowerCase() as AIProviderType;
  const validProviders: AIProviderType[] = ['none', 'gemini', 'grok', 'openai', 'anthropic', 'custom'];
  if (!validProviders.includes(rawProvider)) {
    errors.push({
      variable: 'AI_PROVIDER',
      service: 'AIProviderService',
      is_secret: false,
      message: `Unsupported AI_PROVIDER '${rawProvider}'. Allowed providers: ${validProviders.join(', ')}`,
      resolution: `Set AI_PROVIDER to one of: ${validProviders.join(', ')}`,
    });
  } else if (rawProvider !== 'none') {
    // Check provider-specific API credentials
    if (rawProvider === 'gemini' && !env.GEMINI_API_KEY) {
      errors.push({
        variable: 'GEMINI_API_KEY',
        service: 'AIProviderService (Gemini)',
        is_secret: true,
        message: "AI provider 'gemini' is enabled but GEMINI_API_KEY is not configured.",
        resolution: "Add GEMINI_API_KEY to server-side secret configuration or set AI_PROVIDER='none'.",
      });
    } else if (rawProvider === 'grok' && !env.GROK_API_KEY) {
      errors.push({
        variable: 'GROK_API_KEY',
        service: 'AIProviderService (Grok)',
        is_secret: true,
        message: "AI provider 'grok' is enabled but GROK_API_KEY is not configured.",
        resolution: "Add GROK_API_KEY to server-side secret configuration or set AI_PROVIDER='none'.",
      });
    } else if (rawProvider === 'openai' && !env.OPENAI_API_KEY) {
      errors.push({
        variable: 'OPENAI_API_KEY',
        service: 'AIProviderService (OpenAI)',
        is_secret: true,
        message: "AI provider 'openai' is enabled but OPENAI_API_KEY is not configured.",
        resolution: "Add OPENAI_API_KEY to server-side secret configuration or set AI_PROVIDER='none'.",
      });
    } else if (rawProvider === 'anthropic' && !env.ANTHROPIC_API_KEY) {
      errors.push({
        variable: 'ANTHROPIC_API_KEY',
        service: 'AIProviderService (Anthropic)',
        is_secret: true,
        message: "AI provider 'anthropic' is enabled but ANTHROPIC_API_KEY is not configured.",
        resolution: "Add ANTHROPIC_API_KEY to server-side secret configuration or set AI_PROVIDER='none'.",
      });
    }
  }

  // 6. Check that no server secrets are exposed in VITE_* environment variables
  for (const [key, val] of Object.entries(env)) {
    if (key.startsWith('VITE_') && val) {
      if (isSecretKey(key)) {
        errors.push({
          variable: key,
          service: 'Frontend Build (Vite)',
          is_secret: true,
          message: `Forbidden: Secret variable '${key}' is prefixed with VITE_, which exposes it to browser bundles!`,
          resolution: `Remove VITE_ prefix from '${key}' and keep it server-side only.`,
        });
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Authoritative Configuration Manager
 */
export class ConfigurationManager {
  private env: Record<string, string | undefined>;

  constructor(env: Record<string, string | undefined> = process.env) {
    this.env = { ...env };
  }

  /**
   * Reload configuration from environment
   */
  reload(env: Record<string, string | undefined> = process.env): void {
    this.env = { ...env };
  }

  getEnvironment(): Environment {
    const raw = (this.env.ENVIRONMENT || this.env.NODE_ENV || 'development').toLowerCase();
    if (raw === 'production') return 'production';
    if (raw === 'test') return 'test';
    return 'development';
  }

  getLogLevel(): LogLevel {
    const raw = (this.env.LOG_LEVEL || 'INFO').toUpperCase();
    if (['DEBUG', 'INFO', 'WARN', 'ERROR'].includes(raw)) {
      return raw as LogLevel;
    }
    return 'INFO';
  }

  /**
   * Public configuration safe to serialize and send to browser clients.
   */
  getPublicConfig(): PublicConfiguration {
    const ai = this.getAIConfig();
    return {
      environment: this.getEnvironment(),
      api_url: this.env.VITE_API_URL || '',
      ws_url: this.env.VITE_WS_URL || '',
      app_name: 'Intent Security Workbench',
      api_version: '0.1.0-phase0',
      sandbox_enforced: true,
      ai_provider_configured: ai.is_configured,
      ai_provider_name: ai.provider,
    };
  }

  /**
   * Backend server-only configuration.
   */
  getServerConfig(): ServerConfiguration {
    const port = parseInt(this.env.API_PORT || '3000', 10);
    return {
      host: this.env.API_HOST || '0.0.0.0',
      port: isNaN(port) ? 3000 : port,
      environment: this.getEnvironment(),
      log_level: this.getLogLevel(),
      database_configured: Boolean(this.env.DATABASE_URL),
      redis_configured: Boolean(this.env.REDIS_URL),
      anti_fabrication_mode: 'enforced',
    };
  }

  /**
   * Worker-only configuration.
   */
  getWorkerConfig(): WorkerConfiguration {
    const redisConfigured = Boolean(this.env.REDIS_URL);
    return {
      concurrency: 4,
      redis_configured: redisConfigured,
      execution_mode: redisConfigured ? 'DISTRIBUTED_REDIS' : 'IN_PROCESS',
      job_timeout_ms: parseInt(this.env.SANDBOX_TIMEOUT_MS || '120000', 10),
    };
  }

  /**
   * Internal raw secrets — MUST NEVER leave backend.
   */
  getSecretConfig(): SecretConfiguration {
    return {
      database_url: this.env.DATABASE_URL,
      redis_url: this.env.REDIS_URL,
      gemini_api_key: this.env.GEMINI_API_KEY,
      grok_api_key: this.env.GROK_API_KEY,
      openai_api_key: this.env.OPENAI_API_KEY,
      anthropic_api_key: this.env.ANTHROPIC_API_KEY,
    };
  }

  /**
   * AI Provider configuration.
   */
  getAIConfig(): AIProviderConfiguration {
    const provider = (this.env.AI_PROVIDER || 'none').toLowerCase() as AIProviderType;
    let isConfigured = false;

    if (provider === 'gemini' && Boolean(this.env.GEMINI_API_KEY)) {
      isConfigured = true;
    } else if (provider === 'grok' && Boolean(this.env.GROK_API_KEY)) {
      isConfigured = true;
    } else if (provider === 'openai' && Boolean(this.env.OPENAI_API_KEY)) {
      isConfigured = true;
    } else if (provider === 'anthropic' && Boolean(this.env.ANTHROPIC_API_KEY)) {
      isConfigured = true;
    }

    return {
      provider,
      model: this.env.AI_MODEL || (provider === 'gemini' ? 'gemini-3.6-flash' : 'gemini-3.6-flash'),
      endpoint: this.env.AI_ENDPOINT,
      temperature: parseFloat(this.env.AI_TEMPERATURE || '0.1'),
      max_tokens: parseInt(this.env.AI_MAX_TOKENS || '4096', 10),
      is_configured: isConfigured,
    };
  }

  /**
   * Sandbox configuration.
   */
  getSandboxConfig(): SandboxConfiguration {
    return {
      allow_arbitrary_shell: false, // Invariant enforced
      require_explicit_target_scope: true, // Invariant enforced
      network_egress_restricted: true, // Invariant enforced
      timeout_ms: parseInt(this.env.SANDBOX_TIMEOUT_MS || '120000', 10),
      strict_scope_check: this.env.SANDBOX_STRICT_SCOPE_CHECK !== 'false',
    };
  }
}
