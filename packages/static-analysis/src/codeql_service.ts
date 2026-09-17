/**
 * Real CodeQL Semantic Analysis Service
 * Intent Security Workbench - Phase 2
 *
 * Drives the actual CodeQL CLI: builds a queryable database from the target
 * source, then evaluates a security query suite and reads the SARIF result.
 * CodeQL cannot ship its own findings — the database is derived from the real
 * source tree and the SARIF is the CLI's genuine output.
 *
 * JavaScript/TypeScript, Python and Java extract without a build system. A
 * language whose extractor requires a compiler (C/C++) fails honestly rather
 * than reporting a clean scan.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { resolveExecutable } from '../../config/src/binary_resolver.js';

export type CodeQLStatus = 'COMPLETED' | 'FAILED' | 'NOT_INSTALLED' | 'BROKEN' | 'SKIPPED';

export interface CodeQLFinding {
  rule_id: string;
  rule_name: string;
  message: string;
  severity: string;
  security_severity: number | null;
  file: string;
  line_start?: number;
  line_end?: number;
  cwe: string[];
  help_uri?: string;
  snippet?: string;
}

export interface CodeQLExecutionDetails {
  status: CodeQLStatus;
  executable_path: string | null;
  version: string | null;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  findings: CodeQLFinding[];
  language: string | null;
  database_path: string | null;
  error?: string | null;
}

/** Languages CodeQL can extract here, mapped to the query suite to evaluate. */
const LANGUAGE_SUITES: Record<string, string> = {
  javascript: 'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
  typescript: 'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
  python: 'codeql/python-queries:codeql-suites/python-security-extended.qls',
  java: 'codeql/java-queries:codeql-suites/java-security-extended.qls',
};

/** CWE metadata CodeQL attaches to each security query, keyed by rule id prefix. */
const RULE_CWE_HINTS: Array<{ match: RegExp; cwe: string[] }> = [
  { match: /command-line-injection|command-injection/i, cwe: ['CWE-78'] },
  { match: /sql-injection/i, cwe: ['CWE-89'] },
  { match: /path-injection|path-traversal/i, cwe: ['CWE-22'] },
  { match: /code-injection|eval/i, cwe: ['CWE-94'] },
  { match: /request-forgery|ssrf/i, cwe: ['CWE-918'] },
  { match: /xss|cross-site-scripting/i, cwe: ['CWE-79'] },
  { match: /prototype-pollution/i, cwe: ['CWE-1321'] },
  { match: /ldap-injection/i, cwe: ['CWE-90'] },
  { match: /xpath-injection/i, cwe: ['CWE-643'] },
  { match: /hardcoded|cleartext|credential/i, cwe: ['CWE-798'] },
  { match: /missing-rate-limiting/i, cwe: ['CWE-770'] },
  { match: /deserialization/i, cwe: ['CWE-502'] },
  { match: /unsafe-deserialization/i, cwe: ['CWE-502'] },
  { match: /zip-slip/i, cwe: ['CWE-22'] },
  { match: /weak-crypt|crypto/i, cwe: ['CWE-327'] },
  { match: /regex|redos/i, cwe: ['CWE-1333'] },
];

export class CodeQLAnalysisService {
  private executable: string;

  constructor(executable = 'codeql') {
    this.executable = executable;
  }

  async checkAvailability(): Promise<{
    available: boolean;
    status: CodeQLStatus;
    path: string | null;
    version: string | null;
    error: string | null;
  }> {
    let detectedPath: string | null = null;
    try {
      detectedPath = resolveExecutable(this.executable);
    } catch {
      detectedPath = null;
    }

    if (!detectedPath) {
      return {
        available: false,
        status: 'NOT_INSTALLED',
        path: null,
        version: null,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
      };
    }

    // CodeQL reports its version on stderr; `codeql version` exits 0 either way.
    try {
      let out = '';
      try {
        out = execFileSync(detectedPath, ['version'], {
          encoding: 'utf-8',
          timeout: 60000,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (err: any) {
        out = (err.stdout ? err.stdout.toString() : '') + (err.stderr ? err.stderr.toString() : '');
        if (!out) throw err;
      }
      const firstLine = out.split('\n').map(l => l.trim()).find(l => l.length > 0) || '';
      if (!firstLine) throw new Error('no version output');
      return { available: true, status: 'COMPLETED', path: detectedPath, version: firstLine, error: null };
    } catch (err: any) {
      return {
        available: false,
        status: 'BROKEN',
        path: detectedPath,
        version: null,
        error: `Failed to execute '${this.executable} version': ${err.message}`,
      };
    }
  }

  /** Detects the CodeQL language for a source tree from its file extensions. */
  detectLanguage(sourceDir: string): string | null {
    const counts: Record<string, number> = {};
    const walk = (dir: string, depth = 0) => {
      if (depth > 4) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
          walk(full, depth + 1);
        } else {
          const ext = path.extname(entry.name).toLowerCase();
          const lang =
            ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs'
              ? 'javascript'
              : ext === '.ts' || ext === '.tsx'
                ? 'typescript'
                : ext === '.py'
                  ? 'python'
                  : ext === '.java'
                    ? 'java'
                    : null;
          if (lang) counts[lang] = (counts[lang] || 0) + 1;
        }
      }
    };
    walk(sourceDir);

    const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    return ranked.length > 0 ? ranked[0][0] : null;
  }

  /**
   * Parses a SARIF 2.x document into findings. Returns null when the payload is
   * not SARIF (e.g. an error message on stdout).
   */
  parseSarif(sarifText: string): CodeQLFinding[] | null {
    if (!sarifText || !sarifText.trim()) return null;

    let doc: any;
    try {
      doc = JSON.parse(sarifText);
    } catch {
      return null;
    }
    if (!doc || !Array.isArray(doc.runs)) return null;

    const findings: CodeQLFinding[] = [];

    for (const run of doc.runs) {
      const rules = new Map<string, any>();
      for (const rule of run?.tool?.driver?.rules || []) {
        if (rule?.id) rules.set(rule.id, rule);
      }

      for (const result of run?.results || []) {
        const ruleId = result.ruleId || 'unknown-rule';
        const rule = rules.get(ruleId) || {};
        const location = (result.locations || [])[0]?.physicalLocation || {};
        const uri = location.artifactLocation?.uri || '';
        const region = location.region || {};

        const rawSeverity = rule.properties?.['security-severity'];
        const securitySeverity = rawSeverity !== undefined ? Number(rawSeverity) : null;

        findings.push({
          rule_id: ruleId,
          rule_name: rule.name || ruleId,
          message: result.message?.text || rule.shortDescription?.text || '',
          severity: this.severityFor(securitySeverity, result.level),
          security_severity: Number.isFinite(securitySeverity as number) ? securitySeverity : null,
          file: uri,
          line_start: region.startLine,
          line_end: region.endLine,
          cwe: this.cwesFor(ruleId, rule),
          help_uri: rule.helpUri || rule.help?.text || undefined,
          snippet: region.snippet?.text,
        });
      }
    }

    return findings;
  }

  private severityFor(securitySeverity: number | null, level?: string): string {
    if (securitySeverity !== null && Number.isFinite(securitySeverity)) {
      if (securitySeverity >= 9.0) return 'CRITICAL';
      if (securitySeverity >= 7.0) return 'HIGH';
      if (securitySeverity >= 4.0) return 'MEDIUM';
      if (securitySeverity > 0) return 'LOW';
      return 'INFO';
    }
    switch ((level || '').toLowerCase()) {
      case 'error':
        return 'HIGH';
      case 'warning':
        return 'MEDIUM';
      case 'note':
        return 'LOW';
      default:
        return 'INFO';
    }
  }

  private cwesFor(ruleId: string, rule: any): string[] {
    // Prefer CWE tags CodeQL records on the query itself.
    const tags: string[] = rule?.properties?.tags || [];
    const fromTags = tags
      .filter((t: string) => typeof t === 'string' && t.startsWith('external/cwe/cwe-'))
      .map((t: string) => `CWE-${t.replace('external/cwe/cwe-', '')}`);
    if (fromTags.length > 0) return fromTags;

    for (const hint of RULE_CWE_HINTS) {
      if (hint.match.test(ruleId)) return hint.cwe;
    }
    return [];
  }

  /**
   * Builds a database from the source tree, then evaluates a security suite.
   */
  async analyze(
    sourceDir: string,
    options: {
      timeoutMs?: number;
      language?: string;
      suite?: string;
      keepDatabase?: boolean;
    } = {}
  ): Promise<CodeQLExecutionDetails> {
    const avail = await this.checkAvailability();
    const base = (over: Partial<CodeQLExecutionDetails>): CodeQLExecutionDetails => ({
      status: 'FAILED',
      executable_path: avail.path,
      version: avail.version,
      command: `${avail.path || this.executable} database create/analyze [src=${sourceDir}]`,
      exit_code: 127,
      stdout: '',
      stderr: avail.error || `Executable '${this.executable}' is not installed.`,
      duration_ms: 0,
      findings: [],
      language: null,
      database_path: null,
      error: avail.error || 'ENGINE_NOT_INSTALLED',
      ...over,
    });

    if (!avail.available || !avail.path) return base({});

    if (!fs.existsSync(sourceDir)) {
      return base({
        exit_code: 1,
        stderr: `Source directory not found: ${sourceDir}`,
        error: `Source directory does not exist at ${sourceDir}`,
      });
    }

    const language = options.language || this.detectLanguage(sourceDir);
    if (!language) {
      return base({
        status: 'SKIPPED',
        exit_code: 1,
        stderr: 'No CodeQL-supported source files found.',
        error: `NO_SUPPORTED_SOURCE: no CodeQL-supported files under ${sourceDir}`,
      });
    }

    const suite = options.suite || LANGUAGE_SUITES[language];
    if (!suite) {
      return base({
        status: 'SKIPPED',
        language,
        exit_code: 1,
        stderr: `No CodeQL security suite configured for language '${language}'.`,
        error: `UNSUPPORTED_LANGUAGE: '${language}' has no configured query suite.`,
      });
    }

    const workRoot = path.join(os.tmpdir(), 'intent-codeql-work');
    fs.mkdirSync(workRoot, { recursive: true });
    const dbPath = fs.mkdtempSync(path.join(workRoot, 'db-'));
    const sarifPath = path.join(workRoot, `codeql-${Date.now()}.sarif`);

    const startMs = Date.now();
    let createOut = '';
    let analyzeOut = '';
    let stderr = '';

    try {
      createOut = execFileSync(
        avail.path,
        ['database', 'create', dbPath, `--language=${language}`, '--overwrite'],
        {
          encoding: 'utf-8',
          timeout: options.timeoutMs ?? 600000,
          maxBuffer: 32 * 1024 * 1024,
          cwd: sourceDir,
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
    } catch (err: any) {
      const errOut = (err.stdout ? err.stdout.toString() : '') + (err.stderr ? err.stderr.toString() : '');
      try {
        fs.rmSync(dbPath, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
      return base({
        command: `${avail.path} database create ${dbPath} --language=${language} [cwd=${sourceDir}]`,
        exit_code: typeof err.status === 'number' ? err.status : 1,
        stdout: errOut,
        stderr: errOut || err.message,
        duration_ms: Date.now() - startMs,
        language,
        error: `CODEQL_DATABASE_CREATE_FAILED: could not extract a database for '${language}'. ${errOut.split('\n').filter(l => l.includes('ERROR') || l.includes('error')).slice(0, 2).join(' ')}`,
      });
    }

    try {
      analyzeOut = execFileSync(
        avail.path,
        ['database', 'analyze', dbPath, suite, '--format=sarif-latest', `--output=${sarifPath}`],
        {
          encoding: 'utf-8',
          timeout: options.timeoutMs ?? 900000,
          maxBuffer: 32 * 1024 * 1024,
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
    } catch (err: any) {
      analyzeOut = (err.stdout ? err.stdout.toString() : '') + (err.stderr ? err.stderr.toString() : '');
      stderr = analyzeOut;
    }

    const duration_ms = Date.now() - startMs;

    let sarifText = '';
    try {
      if (fs.existsSync(sarifPath)) sarifText = fs.readFileSync(sarifPath, 'utf-8');
    } catch {
      sarifText = '';
    }

    if (!options.keepDatabase) {
      try {
        fs.rmSync(dbPath, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
    try {
      if (fs.existsSync(sarifPath)) fs.rmSync(sarifPath, { force: true });
    } catch {
      /* best-effort */
    }

    const findings = this.parseSarif(sarifText);
    if (findings === null) {
      return base({
        command: `${avail.path} database analyze ${dbPath} ${suite}`,
        exit_code: 1,
        stdout: analyzeOut || createOut,
        stderr: stderr || 'CodeQL did not emit a parsable SARIF document.',
        duration_ms,
        language,
        database_path: options.keepDatabase ? dbPath : null,
        error: 'CODEQL_OUTPUT_UNPARSEABLE: no SARIF result document was produced.',
      });
    }

    return {
      status: 'COMPLETED',
      executable_path: avail.path,
      version: avail.version,
      command: `${avail.path} database analyze <db> ${suite}`,
      exit_code: 0,
      stdout: analyzeOut || createOut,
      stderr,
      duration_ms,
      findings,
      language,
      database_path: options.keepDatabase ? dbPath : null,
      error: null,
    };
  }
}

export const globalCodeQLService = new CodeQLAnalysisService();