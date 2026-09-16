/**
 * API Authentication and Origin Control
 *
 * The workbench exposes research data (targets, source snapshots, evidence
 * artifacts, findings) and can execute analysis binaries. It previously had no
 * authentication whatsoever and bound 0.0.0.0, so anyone able to reach the port
 * had full read/write access.
 *
 * Two independent controls, both opt-in so local single-user use is unchanged:
 *
 * 1. Bearer token auth (AUTH_TOKEN). When set, every /api and /ws request must
 *    present the token. Compared in constant time.
 * 2. Origin allowlist (ALLOWED_ORIGINS). When set, cross-origin browser requests
 *    from other origins are rejected, and WebSocket upgrades are checked.
 *
 * Neither is a substitute for running behind a proper identity-aware proxy, but
 * they close the "wide open on the network" gap and are enforced in one place so
 * a new route cannot forget them.
 */

import crypto from 'crypto';

export interface AuthConfig {
  /** When non-empty, requests must present this token. */
  token: string | null;
  /** When non-empty, browser requests must originate from one of these origins. */
  allowedOrigins: string[];
  /** True when any control is active. */
  enforced: boolean;
}

export function resolveAuthConfig(
  env: Record<string, string | undefined> = process.env
): AuthConfig {
  const token = (env.AUTH_TOKEN || '').trim() || null;
  const allowedOrigins = (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);
  return { token, allowedOrigins, enforced: Boolean(token) || allowedOrigins.length > 0 };
}

/** Constant-time string comparison that never short-circuits on length. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf-8');
  const bb = Buffer.from(b, 'utf-8');
  if (ab.length !== bb.length) {
    // Still perform a comparison to keep timing independent of length.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

/** Extracts a bearer token from an Authorization header or a `token` query param. */
export function extractToken(
  authHeader: string | undefined,
  queryToken?: unknown
): string | null {
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice('Bearer '.length).trim() || null;
  }
  if (typeof queryToken === 'string' && queryToken.trim()) {
    // Permitted for WebSocket upgrades, where browsers cannot set headers.
    return queryToken.trim();
  }
  return null;
}

export function isOriginAllowed(origin: string | undefined, cfg: AuthConfig): boolean {
  // Non-browser clients (CLI, curl) send no Origin header.
  if (!origin) return true;
  if (cfg.allowedOrigins.length === 0) return true;
  return cfg.allowedOrigins.some((allowed) => {
    if (allowed === '*') return true;
    if (allowed === origin) return true;
    // Support a leading-dot suffix match, e.g. ".example.com".
    if (allowed.startsWith('.') && origin.endsWith(allowed)) return true;
    return false;
  });
}

export interface AuthDecision {
  ok: boolean;
  status: number;
  error?: string;
}

/** Decides whether a request may proceed. */
export function authorizeRequest(
  headers: Record<string, string | string[] | undefined>,
  cfg: AuthConfig,
  queryToken?: unknown,
  options: { allowQueryToken?: boolean } = {}
): AuthDecision {
  if (!cfg.enforced) return { ok: true, status: 200 };

  const origin = Array.isArray(headers['origin']) ? headers['origin'][0] : headers['origin'];
  if (!isOriginAllowed(origin, cfg)) {
    return { ok: false, status: 403, error: 'Origin not allowed.' };
  }

  if (cfg.token) {
    const authHeader = Array.isArray(headers['authorization'])
      ? headers['authorization'][0]
      : headers['authorization'];
    // Query-string tokens are accepted only where headers are impossible (the
    // WebSocket handshake). Accepting them on REST would leak the token into
    // access logs, browser history and Referer headers.
    const presented = extractToken(authHeader, options.allowQueryToken ? queryToken : undefined);
    if (!presented) {
      return { ok: false, status: 401, error: 'Authentication required: missing bearer token.' };
    }
    if (!safeEqual(presented, cfg.token)) {
      return { ok: false, status: 401, error: 'Authentication failed: invalid bearer token.' };
    }
  }

  return { ok: true, status: 200 };
}

/**
 * Paths that stay reachable without a token so infrastructure can probe health.
 */
export const PUBLIC_PATHS = new Set<string>([
  '/api/health',
  '/api/readiness',
  '/api/version',
]);

export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.has(pathname);
}
