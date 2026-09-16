import { describe, it, expect } from 'vitest';
import {
  resolveAuthConfig,
  authorizeRequest,
  isOriginAllowed,
  safeEqual,
  extractToken,
  isPublicPath,
} from '../../apps/api/auth.js';

describe('API Authentication & Origin Control', () => {
  describe('1. Configuration', () => {
    it('is disabled when no token and no origins are configured', () => {
      const cfg = resolveAuthConfig({});
      expect(cfg.enforced).toBe(false);
      expect(cfg.token).toBeNull();
      expect(cfg.allowedOrigins).toEqual([]);
    });

    it('is enforced when AUTH_TOKEN is set', () => {
      const cfg = resolveAuthConfig({ AUTH_TOKEN: 'secret-token' });
      expect(cfg.enforced).toBe(true);
      expect(cfg.token).toBe('secret-token');
    });

    it('parses a comma-separated origin allowlist', () => {
      const cfg = resolveAuthConfig({ ALLOWED_ORIGINS: 'https://a.test, https://b.test' });
      expect(cfg.allowedOrigins).toEqual(['https://a.test', 'https://b.test']);
      expect(cfg.enforced).toBe(true);
    });
  });

  describe('2. Token comparison', () => {
    it('accepts an exact match and rejects a mismatch', () => {
      expect(safeEqual('abc123', 'abc123')).toBe(true);
      expect(safeEqual('abc123', 'abc124')).toBe(false);
    });

    it('rejects differing lengths without throwing', () => {
      expect(safeEqual('short', 'considerably-longer-value')).toBe(false);
      expect(safeEqual('', 'x')).toBe(false);
    });

    it('extracts bearer tokens and ignores malformed headers', () => {
      expect(extractToken('Bearer abc')).toBe('abc');
      expect(extractToken('Basic abc')).toBeNull();
      expect(extractToken(undefined)).toBeNull();
      expect(extractToken('Bearer ')).toBeNull();
    });
  });

  describe('3. Request authorization', () => {
    const cfg = resolveAuthConfig({ AUTH_TOKEN: 'correct-horse', ALLOWED_ORIGINS: 'https://ok.test' });

    it('allows requests with the correct bearer token', () => {
      const d = authorizeRequest({ authorization: 'Bearer correct-horse' }, cfg);
      expect(d.ok).toBe(true);
    });

    it('rejects requests with no token (401)', () => {
      const d = authorizeRequest({}, cfg);
      expect(d.ok).toBe(false);
      expect(d.status).toBe(401);
    });

    it('rejects requests with a wrong token (401)', () => {
      const d = authorizeRequest({ authorization: 'Bearer wrong' }, cfg);
      expect(d.ok).toBe(false);
      expect(d.status).toBe(401);
    });

    it('rejects a disallowed browser origin (403)', () => {
      const d = authorizeRequest({ authorization: 'Bearer correct-horse', origin: 'https://evil.test' }, cfg);
      expect(d.ok).toBe(false);
      expect(d.status).toBe(403);
    });

    it('allows the configured origin', () => {
      const d = authorizeRequest({ authorization: 'Bearer correct-horse', origin: 'https://ok.test' }, cfg);
      expect(d.ok).toBe(true);
    });

    it('allows non-browser clients that send no Origin (CLI, curl)', () => {
      const d = authorizeRequest({ authorization: 'Bearer correct-horse' }, cfg);
      expect(d.ok).toBe(true);
    });

    it('does NOT accept a query-string token on REST requests', () => {
      // Query tokens would leak via logs, history and Referer headers.
      const d = authorizeRequest({}, cfg, 'correct-horse', { allowQueryToken: false });
      expect(d.ok).toBe(false);
      expect(d.status).toBe(401);
    });

    it('accepts a query-string token only when explicitly permitted (WebSocket)', () => {
      const d = authorizeRequest({}, cfg, 'correct-horse', { allowQueryToken: true });
      expect(d.ok).toBe(true);
    });

    it('is a no-op when auth is not configured', () => {
      const open = resolveAuthConfig({});
      expect(authorizeRequest({}, open).ok).toBe(true);
      expect(authorizeRequest({ origin: 'https://anything.test' }, open).ok).toBe(true);
    });
  });

  describe('4. Origin matching', () => {
    it('supports suffix matching via a leading dot', () => {
      const cfg = resolveAuthConfig({ ALLOWED_ORIGINS: '.example.com' });
      expect(isOriginAllowed('https://app.example.com', cfg)).toBe(true);
      expect(isOriginAllowed('https://evil.test', cfg)).toBe(false);
    });

    it('supports an explicit wildcard', () => {
      const cfg = resolveAuthConfig({ ALLOWED_ORIGINS: '*' });
      expect(isOriginAllowed('https://anything.test', cfg)).toBe(true);
    });

    it('allows headerless requests regardless of allowlist', () => {
      const cfg = resolveAuthConfig({ ALLOWED_ORIGINS: 'https://ok.test' });
      expect(isOriginAllowed(undefined, cfg)).toBe(true);
    });

    it('does not treat a lookalike suffix as a match', () => {
      const cfg = resolveAuthConfig({ ALLOWED_ORIGINS: '.example.com' });
      expect(isOriginAllowed('https://notexample.com', cfg)).toBe(false);
    });
  });

  describe('5. Public paths', () => {
    it('exposes only liveness endpoints without a token', () => {
      expect(isPublicPath('/api/health')).toBe(true);
      expect(isPublicPath('/api/readiness')).toBe(true);
      expect(isPublicPath('/api/version')).toBe(true);
    });

    it('does NOT expose data-bearing endpoints', () => {
      expect(isPublicPath('/api/programs')).toBe(false);
      expect(isPublicPath('/api/findings')).toBe(false);
      expect(isPublicPath('/api/evidence')).toBe(false);
      expect(isPublicPath('/api/investigations')).toBe(false);
    });
  });
});