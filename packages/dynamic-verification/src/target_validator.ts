/**
 * Isolated Target Validation for Dynamic Verification
 * Intent Security Workbench - Phase 5
 *
 * Rules:
 * Dynamic verification must NEVER directly attack a production target.
 * Only permit:
 * - LOCAL_SOURCE
 * - LOCAL_NODE
 * - LOCAL_FORK
 * - CONTROLLED_TESTNET
 *
 * Reject:
 * - UNAUTHORIZED_PRODUCTION_TARGET
 * - ENVIRONMENT_INVALID
 */

import { TargetEnvironment, TargetValidationResult } from './types.js';

export class TargetValidator {
  private static readonly ALLOWED_ENVIRONMENTS: TargetEnvironment[] = [
    'LOCAL_SOURCE',
    'LOCAL_NODE',
    'LOCAL_FORK',
    'CONTROLLED_TESTNET',
    'LOCAL_ANVIL',
    'LOCAL_SIMNET',
    'DOCKER_ISOLATED',
  ];

  private static readonly LOCAL_HOSTS = [
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    'local',
    'testnet',
    'anvil',
    'hardhat',
    'ganache',
  ];

  /**
   * Convenience wrapper for validating environment and optional URL.
   */
  static validateTarget(
    environment: TargetEnvironment | string,
    targetUrlOrPath?: string,
    targetId = 'target-default'
  ): { approved: boolean; valid: boolean; error: string | null } {
    const res = this.validate(environment, targetId, targetUrlOrPath);
    return {
      approved: res.valid,
      valid: res.valid,
      error: res.error || (res.valid ? null : 'UNSAFE_EXECUTION_TARGET'),
    };
  }

  /**
   * Validate that the requested dynamic verification environment and target
   * are strictly isolated and not a production or unauthorized remote target.
   */
  static validate(
    environment: string,
    targetId: string,
    targetUrlOrPath?: string
  ): TargetValidationResult {
    // 1. Validate environment category
    if (!this.ALLOWED_ENVIRONMENTS.includes(environment as TargetEnvironment)) {
      return {
        valid: false,
        environment,
        target_id: targetId,
        target_url: targetUrlOrPath,
        rejection_reason: 'ENVIRONMENT_INVALID',
        error: `ENVIRONMENT_INVALID: '${environment}' is not an authorized isolated execution environment. Allowed: ${this.ALLOWED_ENVIRONMENTS.join(', ')}`,
      };
    }

    // 2. Validate URL/Path if specified
    if (targetUrlOrPath) {
      const trimmed = targetUrlOrPath.trim();

      // Check for remote HTTP/HTTPS production targets
      if (/^https?:\/\//i.test(trimmed)) {
        try {
          const parsed = new URL(trimmed);
          const hostname = parsed.hostname.toLowerCase();

          // Reject non-local hostnames unless testnet or explicitly mock
          const isLocal = this.LOCAL_HOSTS.some(
            (h) => hostname === h || hostname.endsWith(`.${h}`)
          );

          if (!isLocal && !hostname.includes('testnet')) {
            return {
              valid: false,
              environment,
              target_id: targetId,
              target_url: targetUrlOrPath,
              rejection_reason: 'UNAUTHORIZED_PRODUCTION_TARGET',
              error: `UNAUTHORIZED_PRODUCTION_TARGET: Target URL '${trimmed}' refers to an external or production host. Dynamic verification requires an isolated local environment (LOCAL_SOURCE, LOCAL_NODE, LOCAL_FORK, or CONTROLLED_TESTNET).`,
            };
          }
        } catch (e: any) {
          return {
            valid: false,
            environment,
            target_id: targetId,
            target_url: targetUrlOrPath,
            rejection_reason: 'MALFORMED_URL',
            error: `MALFORMED_URL: Target address '${trimmed}' is not a valid URL or path.`,
          };
        }
      }

      // Check for public IP addresses
      const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
      if (ipv4Match) {
        const firstOctet = parseInt(ipv4Match[1], 10);
        const isLoopback = firstOctet === 127;
        const isPrivate =
          firstOctet === 10 ||
          (firstOctet === 172 && parseInt(ipv4Match[2], 10) >= 16 && parseInt(ipv4Match[2], 10) <= 31) ||
          (firstOctet === 192 && parseInt(ipv4Match[2], 10) === 168);

        if (!isLoopback && !isPrivate) {
          return {
            valid: false,
            environment,
            target_id: targetId,
            target_url: targetUrlOrPath,
            rejection_reason: 'UNAUTHORIZED_PRODUCTION_TARGET',
            error: `UNAUTHORIZED_PRODUCTION_TARGET: Public IP '${trimmed}' is prohibited for dynamic execution.`,
          };
        }
      }
    }

    return {
      valid: true,
      environment: environment as TargetEnvironment,
      target_id: targetId,
      target_url: targetUrlOrPath,
      rejection_reason: null,
    };
  }
}
