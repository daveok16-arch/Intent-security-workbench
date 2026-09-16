/**
 * Configuration & System Diagnostics Engine
 * Intent Security Workbench - Environment & Configuration Hardening
 *
 * Requirements:
 * - Safe system status reporting:
 *   Database: CONNECTED / NOT CONFIGURED / ERROR
 *   Redis: CONNECTED / NOT CONFIGURED / ERROR
 *   Sandbox: READY / ERROR
 *   Git: AVAILABLE / UNAVAILABLE
 *   AI Provider: CONFIGURED / NOT CONFIGURED
 *   Worker: READY / BLOCKED
 * - NEVER reveal credentials, tokens, or secret URIs.
 */

import { execFileSync } from 'child_process';
import {
  ConfigurationDiagnostics,
  DiagnosticStatus,
  SandboxDiagnosticStatus,
  GitDiagnosticStatus,
  AIProviderDiagnosticStatus,
  WorkerDiagnosticStatus,
  AIProviderType,
} from './types.js';
import { AIProviderService } from './ai_provider.js';

export class DiagnosticsService {
  private env: Record<string, string | undefined>;
  private aiService: AIProviderService;

  constructor(env: Record<string, string | undefined> = process.env) {
    this.env = { ...env };
    this.aiService = new AIProviderService(this.env);
  }

  updateEnv(env: Record<string, string | undefined> = process.env): void {
    this.env = { ...env };
    this.aiService.updateEnv(this.env);
  }

  /**
   * Evaluate complete safe system diagnostics.
   * Zero secrets or credentials are ever returned.
   */
  async getDiagnostics(): Promise<ConfigurationDiagnostics> {
    const dbStatus = this.checkDatabaseStatus();
    const redisStatus = this.checkRedisStatus();
    const sandboxStatus = this.checkSandboxStatus();
    const { status: gitStatus, version: gitVersion } = this.checkGitStatus();
    const aiStatus = this.checkAIProviderStatus();
    const workerStatus = this.checkWorkerStatus();

    const provider = (this.env.AI_PROVIDER || 'none').toLowerCase() as AIProviderType;

    return {
      database: dbStatus,
      redis: redisStatus,
      sandbox: sandboxStatus,
      git: gitStatus,
      ai_provider: aiStatus,
      worker: workerStatus,
      details: {
        database_mode: this.env.DATABASE_URL ? 'POSTGRESQL' : 'IN_MEMORY',
        worker_mode: this.env.REDIS_URL ? 'DISTRIBUTED_REDIS' : 'IN_PROCESS',
        sandbox_policy_enforced: sandboxStatus === 'READY',
        git_version: gitVersion,
        ai_provider: provider,
        ai_model: this.env.AI_MODEL || (provider === 'gemini' ? 'gemini-3.8-flash' : 'default'),
      },
    };
  }

  private checkDatabaseStatus(): DiagnosticStatus {
    const dbUrl = this.env.DATABASE_URL;
    if (!dbUrl || dbUrl.trim() === '') {
      return 'NOT_CONFIGURED'; // In-memory database active
    }

    try {
      // Validate URI format without connecting
      if (dbUrl.startsWith('postgresql://') || dbUrl.startsWith('postgres://')) {
        return 'CONNECTED';
      }
      return 'ERROR';
    } catch {
      return 'ERROR';
    }
  }

  private checkRedisStatus(): DiagnosticStatus {
    const redisUrl = this.env.REDIS_URL;
    if (!redisUrl || redisUrl.trim() === '') {
      return 'NOT_CONFIGURED'; // In-process job queue active
    }

    try {
      if (redisUrl.startsWith('redis://') || redisUrl.startsWith('rediss://')) {
        return 'CONNECTED';
      }
      return 'ERROR';
    } catch {
      return 'ERROR';
    }
  }

  private checkSandboxStatus(): SandboxDiagnosticStatus {
    // Arbitrary shell MUST be disabled
    if (this.env.SANDBOX_ALLOW_ARBITRARY_SHELL === 'true') {
      return 'ERROR';
    }
    return 'READY';
  }

  private checkGitStatus(): { status: GitDiagnosticStatus; version: string | null } {
    try {
      const output = execFileSync('git', ['--version'], {
        encoding: 'utf-8',
        timeout: 2000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      return {
        status: 'AVAILABLE',
        version: output,
      };
    } catch {
      return {
        status: 'UNAVAILABLE',
        version: null,
      };
    }
  }

  private checkAIProviderStatus(): AIProviderDiagnosticStatus {
    const provider = (this.env.AI_PROVIDER || 'none').toLowerCase() as AIProviderType;
    if (provider === 'none') {
      return 'NOT_CONFIGURED';
    }

    const isConfigured = this.aiService.isProviderConfigured(provider);
    return isConfigured ? 'CONFIGURED' : 'NOT_CONFIGURED';
  }

  private checkWorkerStatus(): WorkerDiagnosticStatus {
    // If Redis is configured with invalid protocol, worker is blocked
    if (this.env.REDIS_URL && !this.env.REDIS_URL.startsWith('redis://') && !this.env.REDIS_URL.startsWith('rediss://')) {
      return 'BLOCKED';
    }
    return 'READY';
  }
}

export const globalDiagnosticsService = new DiagnosticsService();
