/**
 * Authoritative Configuration Layer
 * Intent Security Workbench - Environment & Configuration Hardening
 */

import { ConfigurationManager, validateEnvironment, VARIABLE_INVENTORY } from './schema.js';
import { globalAIProviderService, AIProviderService } from './ai_provider.js';
import { globalDiagnosticsService, DiagnosticsService } from './diagnostics.js';

export * from './types.js';
export * from './redaction.js';
export * from './schema.js';
export * from './binary_resolver.js';
export * from './path_containment.js';
export * from './ai_provider.js';
export * from './diagnostics.js';

export const globalConfig = new ConfigurationManager();

/**
 * Initializes and validates configuration on startup.
 * Throws a formatted error if required production configuration is violated.
 */
export function initializeConfiguration(env: Record<string, string | undefined> = process.env): {
  valid: boolean;
  warnings: string[];
} {
  const result = validateEnvironment(env);
  if (!result.valid) {
    const errorDetails = result.errors
      .map((e) => `  - [${e.service}] ${e.variable}: ${e.message}\n    Fix: ${e.resolution}`)
      .join('\n\n');

    throw new Error(`CONFIGURATION ERROR:\n${errorDetails}`);
  }

  globalConfig.reload(env);
  globalAIProviderService.updateEnv(env);
  globalDiagnosticsService.updateEnv(env);

  return {
    valid: true,
    warnings: result.warnings,
  };
}
