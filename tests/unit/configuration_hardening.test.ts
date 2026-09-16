/**
 * Configuration Hardening & Secret Hygiene Test Suite
 * Intent Security Workbench - Environment & Configuration Architecture
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  ConfigurationClassification,
  VARIABLE_INVENTORY,
  validateEnvironment,
  ConfigurationManager,
  redactSecret,
  redactUriCredentials,
  redactString,
  sanitizeForLogging,
  createSanitizedProcessEnv,
  isSecretKey,
  AIProviderService,
  DiagnosticsService,
} from '../../packages/config/src/index.js';

describe('Configuration Classification & Variable Inventory (Phase B)', () => {
  it('should correctly classify secrets as OPTIONAL_SECRET or REQUIRED_SECRET', () => {
    expect(VARIABLE_INVENTORY.DATABASE_URL.classification).toBe(ConfigurationClassification.OPTIONAL_SECRET);
    expect(VARIABLE_INVENTORY.DATABASE_URL.is_secret).toBe(true);
    expect(VARIABLE_INVENTORY.DATABASE_URL.safe_for_frontend).toBe(false);

    expect(VARIABLE_INVENTORY.REDIS_URL.classification).toBe(ConfigurationClassification.OPTIONAL_SECRET);
    expect(VARIABLE_INVENTORY.REDIS_URL.is_secret).toBe(true);

    expect(VARIABLE_INVENTORY.GEMINI_API_KEY.classification).toBe(ConfigurationClassification.OPTIONAL_SECRET);
    expect(VARIABLE_INVENTORY.GEMINI_API_KEY.is_secret).toBe(true);
    expect(VARIABLE_INVENTORY.GEMINI_API_KEY.safe_for_frontend).toBe(false);
  });

  it('should correctly classify runtime configuration as OPTIONAL_CONFIGURATION or DERIVED', () => {
    expect(VARIABLE_INVENTORY.API_PORT.classification).toBe(ConfigurationClassification.OPTIONAL_CONFIGURATION);
    expect(VARIABLE_INVENTORY.API_PORT.is_secret).toBe(false);
    expect(VARIABLE_INVENTORY.API_PORT.safe_for_frontend).toBe(true);

    expect(VARIABLE_INVENTORY.SANDBOX_ALLOW_ARBITRARY_SHELL.classification).toBe(
      ConfigurationClassification.OPTIONAL_CONFIGURATION
    );
    expect(VARIABLE_INVENTORY.SANDBOX_ALLOW_ARBITRARY_SHELL.is_secret).toBe(false);

    expect(VARIABLE_INVENTORY.NODE_ENV.classification).toBe(ConfigurationClassification.DERIVED_CONFIGURATION);
  });
});

describe('Validation & Startup Rules (Phase C, D, G)', () => {
  it('should succeed with safe defaults when optional secrets (DATABASE_URL, REDIS_URL) are omitted', () => {
    const cleanEnv: Record<string, string> = {
      NODE_ENV: 'development',
      API_PORT: '3000',
    };

    const res = validateEnvironment(cleanEnv);
    expect(res.valid).toBe(true);
    expect(res.errors).toHaveLength(0);

    const config = new ConfigurationManager(cleanEnv);
    const serverConf = config.getServerConfig();
    expect(serverConf.database_configured).toBe(false);
    expect(serverConf.redis_configured).toBe(false);
    expect(serverConf.port).toBe(3000);
  });

  it('should reject invalid ports with clear diagnostic message', () => {
    const invalidEnv = {
      API_PORT: '999999',
    };

    const res = validateEnvironment(invalidEnv);
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.variable === 'API_PORT')).toBe(true);
    expect(res.errors[0].message).toContain('integer between 1 and 65535');
    expect(res.errors[0].resolution).toContain('API_PORT');
  });

  it('should reject SANDBOX_ALLOW_ARBITRARY_SHELL=true to protect execution boundary', () => {
    const dangerousEnv = {
      SANDBOX_ALLOW_ARBITRARY_SHELL: 'true',
    };

    const res = validateEnvironment(dangerousEnv);
    expect(res.valid).toBe(false);
    expect(res.errors.some((e) => e.variable === 'SANDBOX_ALLOW_ARBITRARY_SHELL')).toBe(true);
    expect(res.errors[0].message).toContain('violates the Phase 0 security boundary policy');
  });

  it('should reject invalid DATABASE_URL schemes without printing secrets', () => {
    const badDbEnv = {
      DATABASE_URL: 'mysql://user:supersecretpass@localhost:3306/db',
    };

    const res = validateEnvironment(badDbEnv);
    expect(res.valid).toBe(false);
    expect(res.errors[0].variable).toBe('DATABASE_URL');
    expect(res.errors[0].is_secret).toBe(true);
    // Crucial: error message must NEVER leak 'supersecretpass'
    expect(res.errors[0].message).not.toContain('supersecretpass');
    expect(res.errors[0].resolution).not.toContain('supersecretpass');
    expect(res.errors[0].message).toContain('valid PostgreSQL URI');
  });

  it('should reject invalid REDIS_URL protocols', () => {
    const badRedisEnv = {
      REDIS_URL: 'http://localhost:6379',
    };

    const res = validateEnvironment(badRedisEnv);
    expect(res.valid).toBe(false);
    expect(res.errors[0].variable).toBe('REDIS_URL');
    expect(res.errors[0].message).toContain('redis://');
  });

  it('should reject secret variables prefixed with VITE_ to prevent frontend leakage', () => {
    const leakingEnv = {
      VITE_DATABASE_PASSWORD: 'super_secret_db_pass',
      VITE_API_KEY: 'sk-12345678901234567890',
    };

    const res = validateEnvironment(leakingEnv);
    expect(res.valid).toBe(false);
    expect(res.errors.length).toBeGreaterThanOrEqual(2);
    expect(res.errors[0].message).toContain('exposes it to browser bundles');
  });
});

describe('Secret Redaction & Sanitization (Phase E)', () => {
  it('should redact explicit secret values', () => {
    expect(redactSecret('super_secret_value')).toBe('[REDACTED]');
    expect(redactSecret('')).toBe('');
    expect(redactSecret(null)).toBe('');
  });

  it('should redact user and password from connection URIs', () => {
    const uri = 'postgresql://admin_user:P@ssw0rd123!@db.internal.net:5432/workbench';
    const redacted = redactUriCredentials(uri);
    expect(redacted).not.toContain('P@ssw0rd123!');
    expect(redacted).not.toContain('admin_user');
    expect(redacted).toContain('[REDACTED]');
    expect(redacted).toContain('db.internal.net:5432/workbench');
  });

  it('should sanitize nested objects and arrays for logging and WebSocket broadcasts', () => {
    const sensitivePayload = {
      user: 'researcher',
      session_token: 'secret_token_abcdef',
      config: {
        database_url: 'postgresql://usr:secret_pass@10.0.0.1:5432/db',
        api_key: 'AIzaSyD-fakeKey123456789012345678901234',
        log_level: 'INFO',
      },
      tags: ['audit', 'sk-test1234567890123456789012'],
    };

    const sanitized = sanitizeForLogging(sensitivePayload);

    expect(sanitized.user).toBe('researcher');
    expect(sanitized.session_token).toBe('[REDACTED]');
    expect(sanitized.config.database_url).not.toContain('secret_pass');
    expect(sanitized.config.database_url).toContain('[REDACTED]');
    expect(sanitized.config.api_key).toBe('[REDACTED]');
    expect(sanitized.config.log_level).toBe('INFO');
    expect(sanitized.tags[1]).toBe('[REDACTED]');
  });

  it('should identify sensitive keys via isSecretKey', () => {
    expect(isSecretKey('api_key')).toBe(true);
    expect(isSecretKey('gemini_api_key')).toBe(true);
    expect(isSecretKey('password')).toBe(true);
    expect(isSecretKey('token')).toBe(true);
    expect(isSecretKey('authorization')).toBe(true);
    expect(isSecretKey('database_url')).toBe(true);
    expect(isSecretKey('port')).toBe(false);
    expect(isSecretKey('environment')).toBe(false);
  });
});

describe('Subprocess Environment Sandboxing (Phase E, K)', () => {
  it('should create sanitized environment stripping secrets for child processes', () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      DATABASE_URL: 'postgresql://usr:pass@localhost:5432/db',
      REDIS_URL: 'redis://:pass@localhost:6379',
      GEMINI_API_KEY: 'test-gemini-key',
      OPENAI_API_KEY: 'sk-test-key-12345',
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: '/tmp',
    };

    try {
      const cleanEnv = createSanitizedProcessEnv({ FOUNDRY_DISABLE_AUTO_UPDATE: 'true' });

      // Invariants: secrets MUST be absent
      expect(cleanEnv.DATABASE_URL).toBeUndefined();
      expect(cleanEnv.REDIS_URL).toBeUndefined();
      expect(cleanEnv.GEMINI_API_KEY).toBeUndefined();
      expect(cleanEnv.OPENAI_API_KEY).toBeUndefined();

      // Safe variables MUST be preserved
      expect(cleanEnv.PATH).toBeDefined();
      expect(cleanEnv.FOUNDRY_DISABLE_AUTO_UPDATE).toBe('true');
    } finally {
      process.env = originalEnv;
    }
  });
});

describe('AI Provider Configuration & Capability Reporting (Phase F)', () => {
  it('should report not configured when AI_PROVIDER is none', () => {
    const aiService = new AIProviderService({
      AI_PROVIDER: 'none',
    });

    const status = aiService.getStatus();
    expect(status.provider).toBe('none');
    expect(status.configured).toBe(false);
    expect(status.status_text).toContain('NOT_CONFIGURED');
  });

  it('should report CONFIGURED truthfully when Gemini provider has key, without leaking key', () => {
    const aiService = new AIProviderService({
      AI_PROVIDER: 'gemini',
      GEMINI_API_KEY: 'secret-gemini-key-12345',
      AI_MODEL: 'gemini-3.8-flash',
    });

    const status = aiService.getStatus();
    expect(status.provider).toBe('gemini');
    expect(status.configured).toBe(true);
    expect(status.model).toBe('gemini-3.8-flash');
    expect(status.status_text).toBe('Google Gemini: CONFIGURED');

    // Verification: status object MUST NOT contain the API key
    const serialized = JSON.stringify(status);
    expect(serialized).not.toContain('secret-gemini-key-12345');
  });

  it('should fail validation if AI_PROVIDER is gemini but GEMINI_API_KEY is missing', () => {
    const badEnv = {
      AI_PROVIDER: 'gemini',
    };

    const res = validateEnvironment(badEnv);
    expect(res.valid).toBe(false);
    expect(res.errors[0].variable).toBe('GEMINI_API_KEY');
    expect(res.errors[0].message).toContain('GEMINI_API_KEY is not configured');
  });

  it('should sanitize AI prompt context to strip any leaked secrets or connection strings', () => {
    const aiService = new AIProviderService({
      GEMINI_API_KEY: 'gemini-secret-token-xyz',
      DATABASE_URL: 'postgresql://dbuser:pass123@db:5432/data',
    });

    const dirtyPrompt =
      'Please analyze this contract. Context: Connected to postgresql://dbuser:pass123@db:5432/data with key gemini-secret-token-xyz';
    const cleanedPrompt = aiService.sanitizePromptContext(dirtyPrompt);

    expect(cleanedPrompt).not.toContain('pass123');
    expect(cleanedPrompt).not.toContain('gemini-secret-token-xyz');
    expect(cleanedPrompt).toContain('[REDACTED');
  });
});

describe('Configuration Diagnostics Service (Phase I)', () => {
  it('should return truthful, safe service diagnostics without exposing secrets', async () => {
    const diagService = new DiagnosticsService({
      API_PORT: '3000',
      AI_PROVIDER: 'none',
      SANDBOX_ALLOW_ARBITRARY_SHELL: 'false',
    });

    const diagnostics = await diagService.getDiagnostics();

    expect(diagnostics.database).toBe('NOT_CONFIGURED');
    expect(diagnostics.redis).toBe('NOT_CONFIGURED');
    expect(diagnostics.sandbox).toBe('READY');
    expect(diagnostics.ai_provider).toBe('NOT_CONFIGURED');
    expect(diagnostics.worker).toBe('READY');
    expect(['AVAILABLE', 'UNAVAILABLE']).toContain(diagnostics.git);

    const serialized = JSON.stringify(diagnostics);
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('secret');
  });

  it('should report database CONNECTED when valid PostgreSQL URL is present', async () => {
    const diagService = new DiagnosticsService({
      DATABASE_URL: 'postgresql://valid_user:valid_password@db_host:5432/workbench_db',
    });

    const diagnostics = await diagService.getDiagnostics();
    expect(diagnostics.database).toBe('CONNECTED');
    expect(diagnostics.details.database_mode).toBe('POSTGRESQL');

    const serialized = JSON.stringify(diagnostics);
    // Must NOT contain the credentials!
    expect(serialized).not.toContain('valid_password');
    expect(serialized).not.toContain('valid_user');
  });
});
