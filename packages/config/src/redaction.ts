/**
 * Secret Redaction & Sanitization Utilities
 * Intent Security Workbench - Environment & Configuration Hardening
 *
 * Strict Rule: Secrets must NEVER appear in logs, API responses, WebSocket events,
 * evidence artifacts, provenance graphs, or AI prompts.
 */

const SENSITIVE_KEY_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /password/i,
  /passwd/i,
  /token/i,
  /private[_-]?key/i,
  /credential/i,
  /authorization/i,
  /auth_header/i,
  /database_url/i,
  /redis_url/i,
  /bearer/i,
];

const INLINE_SECRET_REGEXES = [
  // Database connection strings with embedded passwords: protocol://user:pass@host...
  /((?:postgres(?:ql)?|mysql|redis|mongodb):\/\/[^:\s\/]+:)([^@\s\/]+)(@[^\s\/]+)/gi,
  // Bearer tokens in strings
  /(Bearer\s+)[A-Za-z0-9_\-\.]{12,}/gi,
  // Token passed as a query parameter, e.g. /ws?token=... or ?access_token=...
  /([?&](?:token|access_token|auth_token|api_key|apikey)=)[^&\s'"]+/gi,
  // Generic API key prefixes (e.g., sk-..., AIza...)
  /\b(sk-[A-Za-z0-9_\-]{20,})\b/g,
  /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
  /\b(ghp_[A-Za-z0-9]{36})\b/g,
  /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/g,
];

/**
 * Check if a key or variable name denotes a secret.
 */
export function isSecretKey(keyName: string): boolean {
  if (!keyName) return false;
  return SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(keyName));
}

/**
 * Redact an explicit secret value.
 */
export function redactSecret(value?: string | null): string {
  if (!value) return '';
  return '[REDACTED]';
}

/**
 * Redact user and password credentials from a URI (e.g. DATABASE_URL, REDIS_URL, git clone URL).
 * Safe values such as host and port can be preserved if non-sensitive, but credentials are masked.
 */
export function redactUriCredentials(uri?: string | null): string {
  if (!uri) return '';
  try {
    // Handle standard URLs
    const parsed = new URL(uri);
    if (parsed.password || parsed.username) {
      return `${parsed.protocol}//[REDACTED]:[REDACTED]@${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
    }
    return uri;
  } catch {
    // Fallback regex masking for non-standard URI formats
    return uri.replace(
      /((?:postgres(?:ql)?|redis|mysql|https?|ssh|git):\/\/)([^:@\s]+):([^@\s]+)@/gi,
      '$1[REDACTED]:[REDACTED]@'
    );
  }
}

/**
 * Redact any inline secrets found in an arbitrary string.
 */
export function redactString(text: string): string {
  if (!text || typeof text !== 'string') return text;
  let sanitized = text;

  // Redact embedded URI credentials
  sanitized = sanitized.replace(
    /((?:postgres(?:ql)?|mysql|redis|mongodb|https?):\/\/)([^:\s\/@]+):([^@\s\/]+)(@[^\s\/]+)/gi,
    '$1[REDACTED]:[REDACTED]$4'
  );

  // Redact known token signatures
  for (const regex of INLINE_SECRET_REGEXES) {
    sanitized = sanitized.replace(regex, (match) => {
      if (match.startsWith('Bearer ')) {
        return 'Bearer [REDACTED]';
      }
      return '[REDACTED]';
    });
  }

  return sanitized;
}

/**
 * Deeply sanitizes an object, map, or array for logging or API responses.
 * Replaces values of sensitive keys with '[REDACTED]' and masks inline secrets in strings.
 */
export function sanitizeForLogging<T>(input: T): T {
  if (input === null || input === undefined) {
    return input;
  }

  if (typeof input === 'string') {
    return redactString(input) as unknown as T;
  }

  if (typeof input === 'number' || typeof input === 'boolean') {
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeForLogging(item)) as unknown as T;
  }

  if (input instanceof Map) {
    const cleanMap = new Map();
    for (const [key, value] of input.entries()) {
      if (typeof key === 'string' && isSecretKey(key)) {
        cleanMap.set(key, '[REDACTED]');
      } else {
        cleanMap.set(key, sanitizeForLogging(value));
      }
    }
    return cleanMap as unknown as T;
  }

  if (input instanceof Set) {
    const cleanSet = new Set();
    for (const item of input.values()) {
      cleanSet.add(sanitizeForLogging(item));
    }
    return cleanSet as unknown as T;
  }

  if (typeof input === 'object') {
    const sanitizedObj: Record<string, any> = {};
    for (const [key, value] of Object.entries(input)) {
      if (isSecretKey(key)) {
        sanitizedObj[key] = '[REDACTED]';
      } else {
        sanitizedObj[key] = sanitizeForLogging(value);
      }
    }
    return sanitizedObj as T;
  }

  return input;
}

/**
 * Whitelisted safe host environment variable names for child process execution.
 */
const SAFE_PROCESS_ENV_WHITELIST = new Set([
  'PATH',
  'HOME',
  'TMPDIR',
  'TEMP',
  'USER',
  'LOGNAME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'TERM',
  'SHELL',
  'HOSTNAME',
  'NODE_ENV',
  'FOUNDRY_DISABLE_AUTO_UPDATE',
  'GIT_TERMINAL_PROMPT',
  'SEMGREP_SEND_METRICS',
]);

/**
 * Creates a sanitized environment object for spawning child processes (git, forge, anvil, etc.).
 * Strips all database URLs, API keys, secrets, and credentials from process.env.
 */
export function createSanitizedProcessEnv(overrides?: Record<string, string>): Record<string, string> {
  const cleanEnv: Record<string, string> = {};

  // Copy only whitelisted non-sensitive environment variables
  for (const [key, val] of Object.entries(process.env)) {
    if (!val) continue;
    if (SAFE_PROCESS_ENV_WHITELIST.has(key) && !isSecretKey(key)) {
      cleanEnv[key] = val;
    }
  }

  // Ensure baseline minimal execution environment
  if (!cleanEnv.PATH) {
    cleanEnv.PATH = '/usr/local/bin:/usr/bin:/bin';
  }

  // Apply explicit overrides (if not secret)
  if (overrides) {
    for (const [k, v] of Object.entries(overrides)) {
      if (!isSecretKey(k)) {
        cleanEnv[k] = v;
      }
    }
  }

  return cleanEnv;
}
