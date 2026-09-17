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
   * True when the host is loopback, a known local alias, or a private-range IP.
   * Matching is label-aware: `evil-localhost.com` is not local, whereas
   * `anvil.localhost` is.
   */
  private static isLocalHostname(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (this.LOCAL_HOSTS.some((h) => host === h || host.endsWith(`.${h}`))) {
      return true;
    }
    return this.isPrivateOrLoopbackAddress(host);
  }

  /**
   * True for loopback and RFC1918/ULA addresses. Anything else on the network is
   * a third-party host that dynamic verification must not contact.
   */
  private static isPrivateOrLoopbackAddress(host: string): boolean {
    const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const [a, b] = [parseInt(v4[1], 10), parseInt(v4[2], 10)];
      if (v4.slice(1).some((o) => parseInt(o, 10) > 255)) return false;
      return (
        a === 127 ||
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a === 0
      );
    }
    // IPv6 loopback and unique-local prefixes.
    if (host === '::1' || host === '::') return true;
    if (/^f[cd][0-9a-f]{2}:/i.test(host)) return true;
    if (/^fe80:/i.test(host)) return true;
    return false;
  }

  /**
   * Distinguishes a filesystem path (always local) from a network host.
   */
  private static looksLikeLocalPath(value: string): boolean {
    if (/^(\.{0,2}\/)/.test(value)) return true;
    if (/^[a-zA-Z]:[\\/]/.test(value)) return true; // Windows drive
    if (/^\\\\/.test(value)) return true; // UNC
    if (value.includes('://')) return false;
    // A bare token with no dot and no slash is an identifier/path, not a host.
    if (!value.includes('.') && !value.includes(':')) return true;
    return false;
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

      // Reject explicit non-HTTP schemes outright. An unvalidated scheme (ws,
      // file, ftp, ...) previously slipped past the production check entirely.
      const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
      if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
        return {
          valid: false,
          environment,
          target_id: targetId,
          target_url: targetUrlOrPath,
          rejection_reason: 'UNAUTHORIZED_PRODUCTION_TARGET',
          error: `UNAUTHORIZED_PRODUCTION_TARGET: scheme '${schemeMatch[1]}' is not permitted for dynamic execution. Only http/https to an isolated local endpoint is allowed.`,
        };
      }

      if (/^https?:\/\//i.test(trimmed)) {
        let parsed: URL;
        try {
          parsed = new URL(trimmed);
        } catch {
          return {
            valid: false,
            environment,
            target_id: targetId,
            target_url: targetUrlOrPath,
            rejection_reason: 'MALFORMED_URL',
            error: `MALFORMED_URL: Target address '${trimmed}' is not a valid URL or path.`,
          };
        }

        if (!this.isLocalHostname(parsed.hostname)) {
          return {
            valid: false,
            environment,
            target_id: targetId,
            target_url: targetUrlOrPath,
            rejection_reason: 'UNAUTHORIZED_PRODUCTION_TARGET',
            error: `UNAUTHORIZED_PRODUCTION_TARGET: Target URL '${trimmed}' refers to an external or production host. Dynamic verification requires an isolated local environment (LOCAL_SOURCE, LOCAL_NODE, LOCAL_FORK, or CONTROLLED_TESTNET).`,
          };
        }
      } else if (!this.looksLikeLocalPath(trimmed)) {
        // A schemeless hostname such as `api.production.example.com` bypassed
        // the URL check and reached the runner. Treat anything that is not a
        // recognizable local path as a remote host.
        const hostOnly = trimmed.split('/')[0].split(':')[0];
        if (hostOnly && !this.isLocalHostname(hostOnly)) {
          return {
            valid: false,
            environment,
            target_id: targetId,
            target_url: targetUrlOrPath,
            rejection_reason: 'UNAUTHORIZED_PRODUCTION_TARGET',
            error: `UNAUTHORIZED_PRODUCTION_TARGET: Target address '${trimmed}' is not a local endpoint. Dynamic verification requires an isolated local environment.`,
          };
        }
      }

      // Check for public IP addresses
      const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
      if (ipv4Match && !this.isPrivateOrLoopbackAddress(
        `${ipv4Match[1]}.${ipv4Match[2]}.${ipv4Match[3]}.${ipv4Match[4]}`
      )) {
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

    return {
      valid: true,
      environment: environment as TargetEnvironment,
      target_id: targetId,
      target_url: targetUrlOrPath,
      rejection_reason: null,
    };
  }
}
