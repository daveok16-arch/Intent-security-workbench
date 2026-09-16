/**
 * Versioned Security Rule Registry
 * Intent Security Workbench - Phase 2
 *
 * All rules are data-driven, versioned, and deterministically scored.
 * Candidate classifications are strictly initial hypotheses (CANDIDATE).
 */

import { Severity, Confidence } from '../../core/src/index.js';
import { StaticRule, StaticRuleCategory } from './types.js';

function formatRuleYaml(yamlStr: string): string {
  const lines = yamlStr.split('\n');
  while (lines.length > 0 && lines[0].trim() === '') lines.shift();
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();
  if (lines.length === 0) return '';

  let minIndent = Infinity;
  for (const line of lines) {
    if (line.trim() !== '') {
      const indent = line.search(/\S/);
      if (indent < minIndent) minIndent = indent;
    }
  }

  return lines.map(line => {
    if (line.trim() === '') return '';
    const stripped = line.slice(minIndent);
    return `  ${stripped}`;
  }).join('\n');
}

export class SecurityRuleRegistry {
  private rules: Map<string, StaticRule> = new Map();

  constructor() {
    this.registerDefaults();
  }

  private registerDefaults(): void {
    const defaultRules: StaticRule[] = [
      // 1. INTENT-BOLA-001 (BOLA / IDOR)
      {
        id: 'INTENT-BOLA-001',
        name: 'Broken Object Level Authorization (BOLA / IDOR)',
        description: 'Identifies functions where an object is resolved from a store using an external identifier and subsequently subjected to state mutation or transfer without verified caller authorization.',
        category: StaticRuleCategory.BOLA,
        languages: ['javascript', 'typescript', 'solidity', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-639', 'CWE-285', 'CWE-862'],
        owasp_categories: ['API1:2023', 'API1:2023-Broken Object Level Authorization', 'A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Matched external identifier flowing into resource lookup and subsequent transfer/mutation without preceding caller equality assert or authorization check.',
        remediation: 'Ensure an explicit authorization boundary (e.g. assert(caller == owner), require(msg.sender == owner), or tenant permission check) precedes resource resolution and mutation.',
        semgrep_yaml: `
- id: INTENT-BOLA-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Potential BOLA in route handler"
  metadata:
    cwe: "CWE-639"
    owasp: "API1:2023-Broken Object Level Authorization"
    category: "BOLA"
  patterns:
    - pattern-either:
        - pattern: |
            router.$METHOD($ROUTE, async ($REQ, $RES) => {
              ...
              const $PARAM = $REQ.params.$FIELD;
              ...
              const $DOC = await $DB.$COLL.findOne({ ... });
              ...
              return $RES.json($DOC);
            })
        - pattern: |
            router.$METHOD($ROUTE, async ($REQ, $RES) => {
              ...
              const $PARAM = $REQ.params.$FIELD;
              ...
              await $DB.$COLL.deleteOne({ id: $PARAM });
              ...
            })
    - pattern-not: |
        router.$METHOD($ROUTE, async ($REQ, $RES) => {
          ...
          if ($DOC.ownerId !== $REQ.user.id && $OTHER) {
            ...
          }
          ...
        })
    - pattern-not: |
        router.$METHOD($ROUTE, async ($REQ, $RES) => {
          ...
          await $DB.$COLL.deleteOne({
            id: $PARAM,
            userId: $USERID,
          });
          ...
        })
`,
        structural_query: {
          type: 'bola_pattern',
          target_nodes: ['function_declaration', 'arrow_function', 'method_definition'],
          sensitive_sinks: ['transfer', 'call', 'send', 'update', 'delete', 'deleteOne', 'findOne', 'mutate', 'withdraw'],
          authorization_boundaries: ['assert', 'require', 'checkAuth', 'hasPermission', 'verifyOwner', 'isAuthorized', 'doc.ownerId !== req.user.id'],
          requires_auth_check: true,
          requires_state_mutation: true,
        },
      },

      // 2. RULE-BOLA-001 (Alias / BOLA_IDOR Category)
      {
        id: 'RULE-BOLA-001',
        name: 'Missing Authorization Boundary in Object Lookup and State Mutation',
        description: 'Identifies functions where an object is resolved from a store using an external identifier and subsequently accessed without authorization.',
        category: StaticRuleCategory.BOLA_IDOR,
        languages: ['javascript', 'typescript', 'solidity', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-639', 'CWE-285'],
        owasp_categories: ['A01:2021-Broken Access Control', 'API1:2023-Broken Object Level Authorization'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Matched external identifier flowing into resource lookup without caller equality assert or authorization check.',
        remediation: 'Ensure an explicit authorization boundary precedes resource resolution.',
        semgrep_yaml: `
- id: RULE-BOLA-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Missing authorization check before accessing object"
  metadata:
    cwe: "CWE-639"
  patterns:
    - pattern: |
        router.$METHOD($ROUTE, async ($REQ, $RES) => {
          ...
          const $DOC = await $DB.$COLL.findOne({ ... });
          ...
        })
    - pattern-not: |
        router.$METHOD($ROUTE, async ($REQ, $RES) => {
          ...
          if ($DOC.ownerId !== $REQ.user.id && $OTHER) {
            ...
          }
          ...
        })
    - pattern-not: |
        router.$METHOD($ROUTE, async ($REQ, $RES) => {
          ...
          await $DB.$COLL.deleteOne({
            id: $PARAM,
            userId: $USERID,
          });
          ...
        })
`,
      },

      // 3. ACCESS CONTROL
      {
        id: 'RULE-ACCESS-001',
        name: 'Missing Access Control on Sensitive Administrative Function',
        description: 'Detects administrative or privileged functions lacking access-control modifiers or caller authentication checks.',
        category: StaticRuleCategory.ACCESS_CONTROL,
        languages: ['solidity', 'javascript', 'typescript', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-285', 'CWE-862'],
        owasp_categories: ['A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Function signature matches privileged action (admin, withdraw, emergency, pause) with no role verification pattern.',
        remediation: 'Attach access control modifiers (e.g., onlyOwner, requiresRole, authMiddleware) to privileged operations.',
        semgrep_yaml: `
- id: RULE-ACCESS-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Sensitive administrative function lacking access control boundary"
  metadata:
    cwe: "CWE-285"
  pattern: |
    app.post("/admin/$ROUTE", ($REQ, $RES) => {
      ...
    })
`,
        structural_query: {
          type: 'privileged_function_check',
          sensitive_sinks: ['emergencyStop', 'withdrawAll', 'setAdmin', 'setFee'],
          authorization_boundaries: ['onlyOwner', 'onlyAdmin', 'hasRole'],
          requires_auth_check: true,
        },
      },

      // 4. AUTHENTICATION
      {
        id: 'RULE-AUTH-002',
        name: 'Hardcoded Credentials or Default Authentication Bypass',
        description: 'Detects hardcoded passwords, tokens, or default credentials used in authentication verification.',
        category: StaticRuleCategory.AUTHENTICATION,
        languages: ['javascript', 'typescript', 'python', 'go'],
        severity: Severity.CRITICAL,
        cwe_ids: ['CWE-798', 'CWE-259'],
        owasp_categories: ['A07:2021-Identification and Authentication Failures'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'String literal comparison against auth/password/token parameter in verification path.',
        remediation: 'Use secure secret management and constant-time comparison with cryptographically derived password hashes.',
        semgrep_yaml: `
- id: RULE-AUTH-002
  languages: [javascript, typescript]
  severity: ERROR
  message: "Hardcoded credential in authentication path"
  metadata:
    cwe: "CWE-798"
  patterns:
    - pattern-either:
        - pattern: $PASS === "..."
        - pattern: '... === $PASS'
        - pattern: $PASS == "..."
    - metavariable-regex:
        metavariable: $PASS
        regex: "(?i).*(pass|passwd|password|secret|token|apikey|api_key|credential|authkey).*"
    - pattern-not: $PASS === ""
    - pattern-not: $PASS === "undefined"
`,
      },

      // 5. TENANT ISOLATION
      {
        id: 'RULE-TENANT-001',
        name: 'Missing Tenant Boundary in Multi-Tenant Query',
        description: 'Detects database resource lookups where tenant ID is omitted from query constraints, risking cross-tenant data access.',
        category: StaticRuleCategory.TENANT_ISOLATION,
        languages: ['javascript', 'typescript', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-639', 'CWE-284'],
        owasp_categories: ['A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Repository or entity query accepts primary key without filtering on tenant context.',
        remediation: 'Always include tenant_id in WHERE clauses or enforce Row Level Security (RLS) at the database layer.',
        semgrep_yaml: `
- id: RULE-TENANT-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Potential tenant isolation violation: query lacks tenant_id constraint"
  metadata:
    cwe: "CWE-639"
  pattern: |
    $DB.findOne({ id: $REQ.params.id })
`,
      },

      // 6. INPUT VALIDATION
      {
        id: 'RULE-INP-001',
        name: 'Unvalidated Dynamic Property or Object Lookup',
        description: 'Detects dynamic bracket notation object access using arbitrary user input, potentially leading to prototype pollution or unintended state access.',
        category: StaticRuleCategory.INPUT_VALIDATION,
        languages: ['javascript', 'typescript'],
        severity: Severity.MEDIUM,
        cwe_ids: ['CWE-20', 'CWE-1321'],
        owasp_categories: ['A03:2021-Injection'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Target object accessed via raw parameter without property whitelist check.',
        remediation: 'Validate input against an explicit allowlist or use Map instead of dynamic object index lookup.',
        semgrep_yaml: `
- id: RULE-INP-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Dynamic property access using unvalidated request input"
  metadata:
    cwe: "CWE-20"
  pattern: |
    $OBJ[$REQ.body.$PROP] = $VAL
`,
      },

      // 7. INJECTION (Generic Injection Category)
      {
        id: 'RULE-INJ-001',
        name: 'Generic Code or Expression Injection',
        description: 'Detects unsanitized user inputs evaluated as dynamic code or template expressions.',
        category: StaticRuleCategory.INJECTION,
        languages: ['javascript', 'typescript', 'python'],
        severity: Severity.CRITICAL,
        cwe_ids: ['CWE-94', 'CWE-74'],
        owasp_categories: ['A03:2021-Injection'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'Dynamic evaluation of unvalidated expression string.',
        remediation: 'Avoid eval or dynamic code compilers with user-provided parameters.',
        semgrep_yaml: `
- id: RULE-INJ-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "Unsafe dynamic evaluation of untrusted expression"
  metadata:
    cwe: "CWE-94"
  pattern: |
    eval($REQ.body.code)
`,
      },

      // 8. COMMAND EXECUTION
      {
        id: 'RULE-CMD-001',
        name: 'Command Injection via Unsanitized Process Execution',
        description: 'Detects execution of external shell commands where command arguments incorporate untrusted inputs without validation or escaping.',
        category: StaticRuleCategory.COMMAND_EXECUTION,
        languages: ['javascript', 'typescript', 'python', 'go'],
        severity: Severity.CRITICAL,
        cwe_ids: ['CWE-78'],
        owasp_categories: ['A03:2021-Injection'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'String interpolation or concatenation passed into exec or child_process command runner.',
        remediation: 'Avoid shell execution. Use execFile or spawn with structured arguments and strict parameter allowlists.',
        semgrep_yaml: `
- id: RULE-CMD-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "Potential command injection via child_process.exec"
  metadata:
    cwe: "CWE-78"
  patterns:
    - pattern-either:
        - pattern: child_process.exec($CMD + ...)
        - pattern: exec($CMD + ...)
`,
      },

      // 9. PATH TRAVERSAL
      {
        id: 'RULE-PATH-001',
        name: 'Path Traversal via Unvalidated File Path Joining',
        description: 'Detects file system operations that join paths with untrusted user input without path sanitization or canonicalization.',
        category: StaticRuleCategory.PATH_TRAVERSAL,
        languages: ['javascript', 'typescript', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-22', 'CWE-23'],
        owasp_categories: ['A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'Path concatenation used in fs.readFile/writeFile without root boundary verification.',
        remediation: 'Resolve paths and verify they reside within the intended base directory using path.resolve and startsWith boundary check.',
        semgrep_yaml: `
- id: RULE-PATH-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "Potential path traversal in file read/write operation"
  metadata:
    cwe: "CWE-22"
  patterns:
    - pattern-either:
        - pattern: fs.readFile(path.join($DIR, $REQ.query.$FILE), ...)
        - pattern: fs.readFileSync(path.join($DIR, $REQ.params.$FILE), ...)
`,
      },

      // 10. SECRET EXPOSURE
      {
        id: 'RULE-SEC-001',
        name: 'Hardcoded Private Key or Sensitive API Secret',
        description: 'Detects hardcoded cryptographic private keys, mnemonic phrases, or third-party secret tokens in source code.',
        category: StaticRuleCategory.SECRET_EXPOSURE,
        languages: ['javascript', 'typescript', 'solidity', 'python', 'go'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-798', 'CWE-312'],
        owasp_categories: ['A02:2021-Cryptographic Failures'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'High-entropy private key literal or secret assignment matching known key patterns.',
        remediation: 'Store credentials in environment variables or secure secret vaults; never commit secrets to version control.',
        semgrep_yaml: `
- id: RULE-SEC-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "Hardcoded private key or secret token detected"
  metadata:
    cwe: "CWE-798"
  pattern: |
    const $KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
`,
      },

      // 11. INSECURE DESERIALIZATION
      {
        id: 'RULE-DESER-001',
        name: 'Insecure Deserialization of Untrusted Data',
        description: 'Detects deserialization of untrusted payloads using unsafe parsers (e.g. serialize-javascript, eval, pickle).',
        category: StaticRuleCategory.INSECURE_DESERIALIZATION,
        languages: ['javascript', 'typescript', 'python'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-502'],
        owasp_categories: ['A08:2021-Software and Data Integrity Failures'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'Invocation of dangerous deserializer on request body or parameters.',
        remediation: 'Use safe serialization formats like standard JSON.parse and validate schemas with strict type validators.',
        semgrep_yaml: `
- id: RULE-DESER-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "Unsafe deserialization of untrusted payload"
  metadata:
    cwe: "CWE-502"
  pattern: |
    eval($REQ.body)
`,
      },

      // 12. SSRF (Server-Side Request Forgery)
      {
        id: 'RULE-SSRF-001',
        name: 'Server-Side Request Forgery via Attacker-Controlled URL',
        description: 'Detects outbound HTTP/fetch requests using URLs supplied directly from user input without hostname or IP validation.',
        category: StaticRuleCategory.SSRF,
        languages: ['javascript', 'typescript', 'python', 'go'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-918'],
        owasp_categories: ['A10:2021-Server-Side Request Forgery (SSRF)'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'User input from request query or body directly supplies target URL in fetch or axios call.',
        remediation: 'Enforce strict domain allowlists and block requests to internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).',
        semgrep_yaml: `
- id: RULE-SSRF-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Outbound request made using unvalidated user-supplied URL"
  metadata:
    cwe: "CWE-918"
  patterns:
    - pattern-either:
        - pattern: fetch($REQ.query.url)
        - pattern: axios.get($REQ.body.target)
`,
      },

      // 13. SQL INJECTION
      {
        id: 'RULE-SQLI-001',
        name: 'SQL Injection via Unsanitized Query Concatenation',
        description: 'Detects database query execution where SQL strings are constructed via string concatenation or template literals incorporating user input.',
        category: StaticRuleCategory.SQL_INJECTION,
        languages: ['javascript', 'typescript', 'python', 'go'],
        severity: Severity.CRITICAL,
        cwe_ids: ['CWE-89'],
        owasp_categories: ['A03:2021-Injection'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'String concatenation or template literal passed to db.query or execute without parameterized placeholders.',
        remediation: 'Use parameterized queries, prepared statements, or ORM query builders that sanitize parameters automatically.',
        semgrep_yaml: `
- id: RULE-SQLI-001
  languages: [javascript, typescript]
  severity: ERROR
  message: "SQL query constructed via string concatenation"
  metadata:
    cwe: "CWE-89"
  pattern: |
    db.query("SELECT * FROM " + $TABLE + " WHERE id = " + $ID)
`,
      },

      // 14. XSS (Cross-Site Scripting)
      {
        id: 'RULE-XSS-001',
        name: 'Reflected or DOM Cross-Site Scripting',
        description: 'Detects unencoded user input reflected directly into HTML output or assigned to dangerous DOM properties.',
        category: StaticRuleCategory.XSS,
        languages: ['javascript', 'typescript'],
        severity: Severity.MEDIUM,
        cwe_ids: ['CWE-79'],
        owasp_categories: ['A03:2021-Injection'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'User input rendered into dangerouslySetInnerHTML or innerHTML without sanitization.',
        remediation: 'Use context-aware HTML encoding libraries or DOMPurify before injecting dynamic content.',
        semgrep_yaml: `
- id: RULE-XSS-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "Direct injection of unsanitized input into HTML property"
  metadata:
    cwe: "CWE-79"
  pattern: |
    $ELEM.innerHTML = $REQ.query.msg
`,
      },

      // 15. CSRF (Cross-Site Request Forgery)
      {
        id: 'RULE-CSRF-001',
        name: 'State-Changing Operation Without CSRF Protection',
        description: 'Detects mutation HTTP routes (POST, PUT, DELETE) lacking CSRF token verification middleware or SameSite cookie protection.',
        category: StaticRuleCategory.CSRF,
        languages: ['javascript', 'typescript'],
        severity: Severity.MEDIUM,
        cwe_ids: ['CWE-352'],
        owasp_categories: ['A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.LOW,
        confidence_basis: 'State-changing route registered without anti-CSRF token check in middleware pipeline.',
        remediation: 'Implement anti-CSRF tokens for session-authenticated mutation requests and configure SameSite=Strict cookies.',
        semgrep_yaml: `
- id: RULE-CSRF-001
  languages: [javascript, typescript]
  severity: INFO
  message: "State-changing endpoint registered without explicit CSRF middleware"
  metadata:
    cwe: "CWE-352"
  pattern: |
    app.post("/api/$PATH", ($REQ, $RES) => { ... })
`,
      },

      // 16. OPEN REDIRECT
      {
        id: 'RULE-REDIR-001',
        name: 'Open Redirect via Unvalidated User Parameter',
        description: 'Detects HTTP redirect operations where the destination URL is accepted directly from untrusted input without destination validation.',
        category: StaticRuleCategory.OPEN_REDIRECT,
        languages: ['javascript', 'typescript', 'python'],
        severity: Severity.LOW,
        cwe_ids: ['CWE-601'],
        owasp_categories: ['A01:2021-Broken Access Control'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.MEDIUM,
        confidence_basis: 'Response redirect accepts user input parameter without relative path check or domain whitelist.',
        remediation: 'Validate redirect target against an allowlist of permitted hosts or enforce relative paths starting with /.',
        semgrep_yaml: `
- id: RULE-REDIR-001
  languages: [javascript, typescript]
  severity: WARNING
  message: "HTTP redirect to unvalidated user-supplied destination"
  metadata:
    cwe: "CWE-601"
  pattern: |
    res.redirect($REQ.query.next)
`,
      },

      // 17. SMART CONTRACT
      {
        id: 'RULE-CONTRACT-001',
        name: 'Unchecked Low-Level External Call in Smart Contract',
        description: 'Detects low-level external calls in Solidity contracts without checking the return success boolean.',
        category: StaticRuleCategory.SMART_CONTRACT,
        languages: ['solidity'],
        severity: Severity.HIGH,
        cwe_ids: ['CWE-252'],
        owasp_categories: ['SC04:2023-Unchecked Call Return Value'],
        source: 'built-in',
        version: '1.0.0',
        confidence: Confidence.HIGH,
        confidence_basis: 'Low-level call invoked without require/assert checking returned boolean.',
        remediation: 'Always check the boolean return value of low-level calls or use OpenZeppelin Address library.',
        semgrep_yaml: `
- id: RULE-CONTRACT-001
  languages: [solidity]
  severity: ERROR
  message: "Unchecked low-level call return value"
  metadata:
    cwe: "CWE-252"
  pattern: |
    $TARGET.call{value: $VAL}("")
`,
      },
    ];

    for (const rule of defaultRules) {
      this.register(rule);
    }
  }

  register(rule: StaticRule): void {
    rule.title = rule.title || rule.name;
    rule.engine_support = rule.engine_support || ['treesitter', 'semgrep'];
    rule.patterns = rule.patterns || (rule.semgrep_yaml ? { semgrep: rule.semgrep_yaml } : {});
    this.rules.set(rule.id, rule);
  }

  get(rule_id: string): StaticRule | undefined {
    return this.rules.get(rule_id);
  }

  list(filters?: { category?: string; severity?: string; language?: string }): StaticRule[] {
    let result = Array.from(this.rules.values());
    if (filters?.category) {
      result = result.filter(r => r.category.toLowerCase() === filters.category!.toLowerCase());
    }
    if (filters?.severity) {
      result = result.filter(r => r.severity.toLowerCase() === filters.severity!.toLowerCase());
    }
    if (filters?.language) {
      const lang = filters.language.toLowerCase();
      result = result.filter(r => r.languages.some(l => l.toLowerCase() === lang || l === 'all'));
    }
    return result;
  }

  filterByLanguage(language: string): StaticRule[] {
    const lang = language.toLowerCase();
    return this.list().filter(r => 
      r.languages.some(l => l.toLowerCase() === lang || l === 'all')
    );
  }

  filterByCategory(category: StaticRuleCategory): StaticRule[] {
    return this.list().filter(r => r.category === category);
  }

  /**
   * Generates a combined Semgrep YAML configuration file content from all registered rules.
   */
  generateSemgrepConfig(languages?: string[]): string {
    const rulesToInclude = languages && languages.length > 0
      ? this.list().filter(r => r.languages.some(l => languages.includes(l.toLowerCase())))
      : this.list();

    const semgrepRuleBlocks = rulesToInclude
      .filter(r => !!r.semgrep_yaml)
      .map(r => formatRuleYaml(r.semgrep_yaml!))
      .join('\n\n');

    return `rules:\n${semgrepRuleBlocks}\n`;
  }
}

export const globalSecurityRuleRegistry = new SecurityRuleRegistry();
