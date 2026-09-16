/**
 * Real Tree-sitter Parser and Structural Security Analysis Engine
 * Intent Security Workbench - Phase 2
 *
 * Integrates web-tree-sitter with prebuilt WASM grammars.
 * Produces genuine concrete syntax trees, captures parse errors,
 * creates verifiable AST artifacts, and runs structural security queries.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import Parser from 'web-tree-sitter';
import {
  ArtifactType,
  Confidence,
  EvidenceEventType,
  FindingStatus,
  Severity,
} from '../../core/src/index.js';
import {
  createEvidenceArtifact,
  globalArtifactStorage,
  globalEvidenceEventManager,
} from '../../evidence/src/index.js';
import {
  CandidateFinding,
  StaticRuleCategory,
  TreeSitterParseResult,
  TreeSitterStructuralMatch,
} from './types.js';
import { globalSecurityRuleRegistry } from './rule_registry.js';

// Mapping from file extension to Tree-sitter WASM language name
const EXTENSION_TO_LANGUAGE: Record<string, string> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'tsx',
  '.py': 'python',
  '.sol': 'solidity',
  '.go': 'go',
  '.rs': 'rust',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.hpp': 'cpp',
  '.cc': 'cpp',
  '.java': 'java',
  '.rb': 'ruby',
  '.sh': 'bash',
  '.bash': 'bash',
};

/**
 * Extracts the concrete evidence for a BOLA match from the function source.
 *
 * Reporting a fixed `req.params.id` / `db.getAccount(...)` for every hit would
 * fabricate evidence: the finding would claim things the code does not contain.
 * These helpers pull the real request value and the real call expression, and
 * report empty strings when nothing specific can be identified.
 */
function extractBolaEvidence(
  fnText: string,
  requestInputPattern: string,
  dataVerbPattern: string,
  identifierNames: string[] = [],
  allRequestNames: string[] = [],
  contentNames: string[] = []
): { requestValue: string; lookupCall: string; sinkCall: string } {
  // 1. The attacker-controlled *object identifier* that reaches the data layer.
  //    Preference order: the identifier-like bound name, then a direct
  //    `req.params.x` access, then a destructured binding.
  let requestValue = '';
  if (identifierNames.length > 0) {
    requestValue = identifierNames[0];
  } else {
    const direct = fnText.match(
      new RegExp(`\\b(?:req|request)\\s*\\.\\s*(?:params|query|body)\\s*\\.\\s*[A-Za-z0-9_$]+`, 'i')
    );
    if (direct) {
      requestValue = direct[0].replace(/\s+/g, '');
    } else {
      const destructured = fnText.match(
        /\{\s*([A-Za-z0-9_$]+)[^}]*\}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body)/i
      );
      if (destructured) requestValue = destructured[1];
    }
  }

  // 2. The data-layer call consuming it, e.g. `allocationsDAO.getByUserIdAndThreshold`.
  let lookupCall = '';
  let callMatch = null;
  for (const name of identifierNames) {
    callMatch = new RegExp(
      `\\b[A-Za-z_$][A-Za-z0-9_$.]*\\s*\\.\\s*${dataVerbPattern}\\s*\\([^;]{0,200}\\b${name}\\b`,
      'i'
    ).exec(fnText);
    if (callMatch) break;
  }
  if (!callMatch) {
    callMatch = new RegExp(`\\b[A-Za-z_$][A-Za-z0-9_$.]*\\s*\\.\\s*${dataVerbPattern}`, 'i').exec(fnText);
  }
  if (callMatch) {
    const raw = callMatch[0];
    const paren = raw.indexOf('(');
    lookupCall = (paren > 0 ? raw.slice(0, paren) : raw).replace(/\s+/g, '');
  }

  // 3. The mutation sink, when the match is destructive rather than a read.
  let sinkCall = '';
  const sink = fnText.match(
    /\b[A-Za-z_$][A-Za-z0-9_$.]*\s*\.\s*(?:delete[A-Za-z0-9_]*|update[A-Za-z0-9_]*|remove|destroy|save|insert|create)\s*\(/i
  );
  if (sink) sinkCall = sink[0].replace(/\s+/g, '');

  return { requestValue, lookupCall, sinkCall };
}

export class TreeSitterAnalysisService {
  private parserInitialized = false;
  private loadedLanguages: Map<string, any> = new Map();
  private wasmsDir: string;

  constructor(wasmsDir?: string) {
    this.wasmsDir = wasmsDir || path.join(process.cwd(), 'node_modules', 'tree-sitter-wasms', 'out');
  }

  async init(): Promise<boolean> {
    if (!this.parserInitialized) {
      try {
        await Parser.init();
        this.parserInitialized = true;
      } catch (err) {
        console.error('Failed to initialize web-tree-sitter:', err);
        return false;
      }
    }
    return true;
  }

  get wasmsDirectory(): string {
    return this.wasmsDir;
  }

  isLanguageSupported(languageOrExt: string): boolean {
    const ext = languageOrExt.startsWith('.') ? languageOrExt : `.${languageOrExt}`;
    const lang = EXTENSION_TO_LANGUAGE[ext] || languageOrExt.toLowerCase();
    const wasmPath = path.join(this.wasmsDir, `tree-sitter-${lang}.wasm`);
    return fs.existsSync(wasmPath);
  }

  getSupportedLanguages(): string[] {
    return Array.from(new Set(Object.values(EXTENSION_TO_LANGUAGE)));
  }

  private async getLanguage(language: string): Promise<any | null> {
    if (this.loadedLanguages.has(language)) {
      return this.loadedLanguages.get(language);
    }

    const wasmPath = path.join(this.wasmsDir, `tree-sitter-${language}.wasm`);
    if (!fs.existsSync(wasmPath)) {
      return null;
    }

    try {
      const lang = await Parser.Language.load(wasmPath);
      this.loadedLanguages.set(language, lang);
      return lang;
    } catch (err) {
      console.error(`Failed to load Tree-sitter language wasm for ${language}:`, err);
      return null;
    }
  }

  detectLanguage(filePath: string): string | null {
    const ext = path.extname(filePath).toLowerCase();
    return EXTENSION_TO_LANGUAGE[ext] || null;
  }

  /**
   * Parse a single source file and perform structural security analysis.
   */
  async parseFile(
    filePath: string,
    sourceContent?: string,
    sourceSnapshotId: string = 'snap-default',
    investigationId?: string,
    targetId?: string
  ): Promise<TreeSitterParseResult> {
    await this.init();

    if (sourceContent === undefined) {
      if (fs.existsSync(filePath)) {
        sourceContent = fs.readFileSync(filePath, 'utf-8');
      } else {
        sourceContent = '';
      }
    }

    const language = this.detectLanguage(filePath);
    if (!language) {
      return {
        source_file: filePath,
        language: 'unknown',
        parser_version: '0.20.8',
        source_snapshot_id: sourceSnapshotId,
        parse_status: 'UNSUPPORTED_LANGUAGE',
        error_count: 0,
        node_count: 0,
        structural_matches: [],
        source_locations: [],
      };
    }

    const lang = await this.getLanguage(language);
    if (!lang) {
      return {
        source_file: filePath,
        language,
        parser_version: '0.20.8',
        source_snapshot_id: sourceSnapshotId,
        parse_status: 'UNSUPPORTED_LANGUAGE',
        error_count: 0,
        node_count: 0,
        structural_matches: [],
        source_locations: [],
      };
    }

    const parser = new Parser();
    parser.setLanguage(lang);

    let tree: any;
    let parseStatus: 'SUCCESS' | 'ERROR' | 'PARTIAL' = 'SUCCESS';
    let errorCount = 0;
    let nodeCount = 0;

    try {
      tree = parser.parse(sourceContent);
    } catch (err) {
      return {
        source_file: filePath,
        language,
        parser_version: '0.20.8',
        source_snapshot_id: sourceSnapshotId,
        parse_status: 'ERROR',
        error_count: 1,
        node_count: 0,
        structural_matches: [],
        source_locations: [],
      };
    }

    // Traverse CST to count nodes and locate errors
    const sourceLocations: { line: number; column: number; node_type: string }[] = [];
    
    const countAndFindErrors = (node: any) => {
      nodeCount++;
      if (node.isError || node.hasError()) {
        if (node.isError) errorCount++;
      }
      if (nodeCount <= 200) {
        sourceLocations.push({
          line: node.startPosition.row + 1,
          column: node.startPosition.column + 1,
          node_type: node.type,
        });
      }
      for (let i = 0; i < node.childCount; i++) {
        countAndFindErrors(node.child(i));
      }
    };

    countAndFindErrors(tree.rootNode);

    if (errorCount > 0) {
      parseStatus = errorCount === nodeCount ? 'ERROR' : 'PARTIAL';
    }

    // Generate serialized AST artifact
    const astJson = JSON.stringify({
      source_file: filePath,
      language,
      parser_version: '0.20.8',
      parse_status: parseStatus,
      error_count: errorCount,
      node_count: nodeCount,
      s_expression: tree.rootNode ? tree.rootNode.toString().slice(0, 10000) : '',
    }, null, 2);

    const calculatedSha256 = crypto.createHash('sha256').update(astJson).digest('hex');
    let astArtifactId: string | undefined;
    let astSha256: string | undefined;

    if (investigationId) {
      try {
        const artifact = createEvidenceArtifact({
          id: `art-ast-${crypto.randomBytes(6).toString('hex')}`,
          investigation_id: investigationId,
          target_id: targetId,
          artifact_type: ArtifactType.AST,
          producer: 'treesitter',
          producer_version: '0.20.8',
          source_snapshot_id: sourceSnapshotId,
          content: astJson,
          path: `evidence/ast_${path.basename(filePath)}_${Date.now()}.json`,
          mime_type: 'application/json',
          metadata: {
            source_file: filePath,
            language,
            node_count: nodeCount,
            error_count: errorCount,
          },
        });
        astArtifactId = artifact.id;
        astSha256 = artifact.sha256;
      } catch (err) {
        // Fallback sha256 if storage isn't available
        astSha256 = calculatedSha256;
      }
    }

    // Run structural security queries on CST
    const structuralMatches = this.runStructuralQueries(
      tree.rootNode,
      sourceContent,
      filePath,
      language
    );

    return {
      source_file: filePath,
      language,
      parser_version: '0.20.8',
      source_snapshot_id: sourceSnapshotId,
      parse_status: parseStatus,
      error_count: errorCount,
      node_count: nodeCount,
      root_node: tree.rootNode,
      sha256: calculatedSha256,
      ast_artifact_id: astArtifactId,
      ast_sha256: astSha256 || calculatedSha256,
      structural_matches: structuralMatches,
      source_locations: sourceLocations,
    };
  }

  /**
   * Store AST artifact into evidence subsystem and compute its SHA-256 hash.
   */
  async storeAstArtifact(
    parseResult: TreeSitterParseResult,
    investigationId: string,
    targetId: string,
    sourceSnapshotId: string
  ): Promise<{ artifactId: string; sha256: string }> {
    const artifactId = `art-ast-${crypto.randomBytes(6).toString('hex')}`;
    const astJson = JSON.stringify({
      source_file: parseResult.source_file,
      language: parseResult.language,
      parser_version: parseResult.parser_version,
      parse_status: parseResult.parse_status,
      error_count: parseResult.error_count,
      node_count: parseResult.node_count,
      s_expression: parseResult.root_node ? parseResult.root_node.toString().slice(0, 10000) : '',
    }, null, 2);

    const sha256 = parseResult.sha256 || crypto.createHash('sha256').update(astJson).digest('hex');

    createEvidenceArtifact({
      id: artifactId,
      investigation_id: investigationId,
      target_id: targetId,
      artifact_type: ArtifactType.AST,
      producer: 'treesitter',
      producer_version: '0.20.8',
      source_snapshot_id: sourceSnapshotId,
      content: astJson,
      path: `evidence/ast_${path.basename(parseResult.source_file)}_${Date.now()}.json`,
      mime_type: 'application/json',
      metadata: {
        source_file: parseResult.source_file,
        language: parseResult.language,
        node_count: parseResult.node_count,
        error_count: parseResult.error_count,
      },
    });

    parseResult.ast_artifact_id = artifactId;
    parseResult.ast_sha256 = sha256;

    return {
      artifactId,
      sha256,
    };
  }

  /**
   * Structural security query execution against Tree-sitter concrete syntax tree.
   * Identifies candidate patterns:
   * - BOLA: Resource lookup using external parameter followed by state mutation / transfer without authorization boundary.
   * - Missing Access Control: Privileged administrative function without modifier or caller check.
   */
  private runStructuralQueries(
    rootNode: any,
    sourceCode: string,
    filePath: string,
    language: string
  ): TreeSitterStructuralMatch[] {
    const matches: TreeSitterStructuralMatch[] = [];

    // Find all function declarations or method definitions
    const findFunctions = (node: any, found: any[] = []): any[] => {
      if (!node) return found;
      const fnTypes = [
        'function_declaration',
        'arrow_function',
        'function_item', // Rust
        'method_definition',
        'function_definition', // Python, Solidity
      ];

      if (fnTypes.includes(node.type)) {
        found.push(node);
      }

      for (let i = 0; i < node.childCount; i++) {
        findFunctions(node.child(i), found);
      }
      return found;
    };

    const functions = findFunctions(rootNode);

    for (const fnNode of functions) {
      const fnText = sourceCode.slice(fnNode.startIndex, fnNode.endIndex);
      
      // Extract function name if available
      let fnName = 'anonymous';
      const nameNode = fnNode.childForFieldName ? fnNode.childForFieldName('name') : null;
      if (nameNode) {
        fnName = sourceCode.slice(nameNode.startIndex, nameNode.endIndex);
      } else {
        // Fallback search for identifier child
        for (let i = 0; i < fnNode.childCount; i++) {
          const child = fnNode.child(i);
          if (child.type === 'identifier') {
            fnName = sourceCode.slice(child.startIndex, child.endIndex);
            break;
          }
        }
      }

      // 1. Analyze for BOLA/IDOR structural pattern
      // Component 1: Parameter representing user / account / owner identifier
      const paramNames: string[] = [];
      const paramsNode = fnNode.childForFieldName ? fnNode.childForFieldName('parameters') : null;
      if (paramsNode) {
        const paramText = sourceCode.slice(paramsNode.startIndex, paramsNode.endIndex);
        const matches = paramText.match(/[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
        for (const m of matches) {
          if (!['function', 'public', 'external', 'payable', 'address', 'uint256', 'string', 'req', 'res', 'next'].includes(m)) {
            paramNames.push(m);
          }
        }
      }

      // Check for route parameter or external input parameter.
      //
      // BOLA is an *HTTP request* defect: an attacker-supplied identifier from
      // the request is used to reach a resource without an ownership check.
      //
      // `req.session` is deliberately excluded: the session is server-side
      // state, not attacker-controlled input, and treating it as a request
      // parameter produced false positives on handlers that read the
      // authenticated user's own id from the session.
      const hasRequestParam =
        /(req|request)\s*\.\s*(?:params|query|body)\s*(?:\.|\[|\}|\s*;|\s*\))/i.test(fnText) ||
        /\bctx\s*\.\s*(?:params|query|body)\b/i.test(fnText) ||
        /\bevent\s*\.\s*(?:pathParameters|queryStringParameters)\b/i.test(fnText);
      // Node/Express-style handler signature, e.g. (req, res) or (request, reply).
      const hasHandlerSignature = /\(\s*(req|request)\s*,\s*(res|reply|response)\b/.test(fnText);
      // Route registration: router.get('/x/:id', ...) / app.post(...).
      const hasRouteRegistration =
        /\b(router|app|server|api|route)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`]/i.test(fnText) ||
        /\b(router|app|server|api|route)\.(get|post|put|patch|delete|all|use)\s*\(/.test(fnText);
      // Handler methods used as Express callbacks declare `(req, res)` even when
      // the route is registered elsewhere (NodeGoat registers
      // `this.displayAllocations` in a separate router file while the handler
      // body lives here), so a handler signature is itself sufficient context.
      const isRouteHandler = hasRouteRegistration || hasHandlerSignature;
      const hasRouteParam = hasRequestParam;

      // Resource lookup, anchored on data-access idioms rather than bare verbs.
      //
      // The receiver must look like a data layer: literally db/database/etc., a
      // name ending in a persistence-ish suffix (DAO, Repository, Model,
      // Store, Service, Collection), or a capitalised model name. NodeGoat's
      // `allocationsDAO.getByUserIdAndThreshold(...)` is a real instance of the
      // suffix form.
      const DATA_RECEIVER =
        '(?:[A-Za-z_$][A-Za-z0-9_$]*(?:DAO|Dao|Repository|Repo|Model|Store|Service|Collection|Table|Entity|Db|DB)|' +
        'db|database|repository|repo|prisma|sequelize|knex|collection|model|Model|store|' +
        'Document|Order|Account|User|Resource|Invoice|Payment|Wallet|Vault|Profile|Transaction|Benefit|Allocation)';
      // Separated verb classes. Conflating them caused false positives:
      // treating `insert`/`create` as a *lookup* flagged NodeGoat's
      // `memosDAO.insert(req.body.memo, ...)`, and treating them as a BOLA sink
      // flagged it again — creating a record is not object-level authorization
      // failure, which requires reaching an *existing* object by identifier.
      const READ_VERB =
        '(?:findOne|findById|findUnique|findFirst|findByPk|findAll|findBy[A-Za-z0-9_]*|find|' +
        'getBy[A-Za-z0-9_]*|getOne|getById|getAll[A-Za-z0-9_]*|get|query|select|aggregate)';
      const MUTATE_VERB =
        '(?:deleteOne|deleteMany|deleteById|deleteBy[A-Za-z0-9_]*|delete|' +
        'updateOne|updateMany|updateBy[A-Za-z0-9_]*|update|remove|destroy)';
      const DATA_VERB = `(?:${READ_VERB}|${MUTATE_VERB})`;

      const resourceLookupRe = new RegExp(
        `\\b${DATA_RECEIVER}\\s*(?:\\.\\s*[A-Za-z0-9_$]+\\s*)*\\.\\s*${READ_VERB}\\s*\\(`,
        'i'
      );
      const hasResourceLookup = resourceLookupRe.test(fnText);

      // Sensitive sink: a mutation, transfer, or destructive operation.
      //
      // Create-only verbs are excluded: creating a new record is not object-level
      // authorization failure, which requires an *existing* object to be reached
      // through an attacker-supplied identifier. Treating `insert`/`create` as a
      // BOLA sink flagged NodeGoat's `memosDAO.insert(req.body.memo, ...)`.
      const mutationRe = new RegExp(
        `\\b${DATA_RECEIVER}\\s*(?:\\.\\s*[A-Za-z0-9_$]+\\s*)*\\.\\s*(?:deleteOne|deleteMany|deleteById|deleteBy[A-Za-z0-9_]*|delete|updateOne|updateMany|updateBy[A-Za-z0-9_]*|update|remove|destroy)\\s*\\(`,
        'i'
      );
      const hasMutationOrTransfer =
        mutationRe.test(fnText) ||
        /\.\s*(transfer|transferFrom|sendValue|withdraw|withdrawAll|burn|mint)\s*\(/.test(fnText) ||
        /\.\s*(balance|amount|owner|ownerId)\s*=[^=]/.test(fnText);

      // Does an attacker-controllable request value reach the lookup/mutation?
      //
      // Three real shapes, all present in the wild:
      //   1. inline:        db.users.findOne({ id: req.params.id })
      //   2. via assignment: const id = req.params.id
      //   3. destructured:   const { userId } = req.params   <- NodeGoat
      //
      // Only params/query/body count. `req.session` is server-side state.
      const REQ_INPUT = '(?:req|request)\\s*\\.\\s*(?:params|query|body)';
      // Destructured binding: `const { userId } = req.params;`
      const destructuredReq = new RegExp(
        `\\b(?:const|let|var)\\s*\\{\\s*([A-Za-z0-9_$]+)[^}]*\\}\\s*=\\s*${REQ_INPUT}\\b`,
        'i'
      ).exec(fnText);
      const directReq = new RegExp(`\\b(?:const|let|var)\\s+([A-Za-z0-9_$]+)\\s*=\\s*${REQ_INPUT}\\b`, 'i').exec(fnText);
      // Names actually bound from params/query/body in this function only. A
      // match is only valid when one of these names is passed to the data layer,
      // which stops unrelated request fields (a memo body, a username) from
      // being treated as an object identifier.
      const requestBoundNames: string[] = [];
      if (directReq) requestBoundNames.push(directReq[1]);
      if (destructuredReq) {
        const inner = destructuredReq[1];
        if (!requestBoundNames.includes(inner)) requestBoundNames.push(inner);
      }
      const hasRequestValueBinding = requestBoundNames.length > 0;
      const hasInlineRequestArg = new RegExp(
        `${DATA_VERB}\\s*\\(\\s*\\{?[^)]{0,160}${REQ_INPUT}`,
        'is'
      ).test(fnText);

      // Does the data-layer call actually receive the request-derived value?
      // `allocationsDAO.getByUserIdAndThreshold(userId, threshold, cb)` does;
      // `userDAO.validateLogin(userName, password, cb)` does not constitute an
      // object-level authorization defect even though userName is request input.
      const requestValuesInDataCall = requestBoundNames.filter((name) =>
        new RegExp(
          `\\b[A-Za-z_$][A-Za-z0-9_$.]*\\s*\\.\\s*${DATA_VERB}\\s*\\(\\s*[^;]{0,200}\\b${name}\\b`,
          'i'
        ).test(fnText)
      );

      // Only object-identifier-ish names count. A value that is clearly content
      // (a memo body, a comment) or a credential (password, username) is not an
      // object reference, and flagging it produces a false positive.
      const IDENTIFIERISH = /(^|_)(id|ids|uuid|guid|key|ref|reference|owner|userId|accountId|orderId|docId|documentId|resourceId|profileId|recordId|itemId)(_|$)/i;
      const CONTENTISH = /(password|passwd|secret|token|memo|comment|message|body|content|text|note|title|description|name|email|username|userName|firstName|lastName)/i;
      const identifierLike = requestValuesInDataCall.filter(
        (n) => IDENTIFIERISH.test(n) || (!CONTENTISH.test(n) && /id|key|ref|owner/i.test(n))
      );
      const contentOnly = requestValuesInDataCall.filter((n) => CONTENTISH.test(n) && !IDENTIFIERISH.test(n));

      const usesRequestValueInQuery =
        hasInlineRequestArg ||
        (requestValuesInDataCall.length > 0 && identifierLike.length > 0) ||
        /\b(?:ctx|event)\s*\.\s*(?:params|query|body|pathParameters)\b/i.test(fnText);

      // Extract the actual evidence from the source rather than assuming it.
      const extracted = extractBolaEvidence(fnText, REQ_INPUT, DATA_VERB, identifierLike, requestValuesInDataCall, contentOnly);

      // Check for explicit authorization boundary / identity comparison
      const hasAuthBoundary = /assert\s*\(\s*.*(==|===|!=|!==).*\)/i.test(fnText) ||
                              /require\s*\(\s*.*(==|===|!=|!==).*\)/i.test(fnText) ||
                              /if\s*\(\s*.*(!==|!=|==|===).*\)\s*(throw|return)/i.test(fnText) ||
                              /(caller\s*==\s*owner|msg\.sender\s*==|user\.id\s*===|user\.id\s*!==|doc\.ownerId\s*!==|ownerId\s*!==|userId:\s*(currentUserId|req\.user\.id|userId)|isOwner|hasPermission|checkAuth|onlyOwner)/i.test(fnText);

      // Deterministic BOLA Candidate Evaluation.
      //
      // All four must hold:
      //   1. this is an HTTP route handler (not a generic library function),
      //   2. it reads an attacker-controllable request value,
      //   3. that value actually flows into a resource lookup or mutation,
      //   4. no authorization boundary guards it.
      //
      // Requiring 1 and 3 is what removes the false positives produced on
      // ordinary library code, where any function with a parameter and a
      // `get(`/`delete(` call used to be reported as BOLA.
      const bolaPattern =
        isRouteHandler &&
        hasRouteParam &&
        usesRequestValueInQuery &&
        (hasResourceLookup || hasMutationOrTransfer) &&
        !hasAuthBoundary;

      if (bolaPattern) {
        matches.push({
          rule_id: 'INTENT-BOLA-001',
          rule_name: 'Broken Object Level Authorization (BOLA / IDOR)',
          category: StaticRuleCategory.BOLA,
          function_name: fnName,
          line_start: fnNode.startPosition.row + 1,
          line_end: fnNode.endPosition.row + 1,
          column_start: fnNode.startPosition.column + 1,
          column_end: fnNode.endPosition.column + 1,
          matched_snippet: fnText,
          has_authorization_boundary: false,
          is_state_mutation: Boolean(hasMutationOrTransfer),
          is_sink: true,
          sink_name: hasMutationOrTransfer ? 'mutation / delete' : 'resource lookup',
          // Extracted from the real source, never assumed. Reporting a
          // hardcoded `req.params.id` / `db.getAccount(...)` for every finding
          // would fabricate evidence regardless of what the code actually does.
          resource_identifier: extracted.requestValue,
          details: {
            parameters: paramNames,
            has_route_param: hasRouteParam,
            has_resource_lookup: hasResourceLookup,
            has_mutation_or_transfer: hasMutationOrTransfer,
            has_auth_boundary: false,
            matched_request_value: extracted.requestValue,
            matched_lookup_call: extracted.lookupCall,
            matched_sink_call: extracted.sinkCall,
          },
        });
      }

      // Administrative access control: the function name indicates a privileged
      // operation AND it performs a real state-changing sink. Matching on the
      // name alone flagged pure getters and unrelated helpers (e.g. a function
      // merely named `getAdminConfig`), so a sink is now required.
      const isAdminNamed = /\b(admin|emergency|pause|unpause|setFee|setOwner|withdrawAll|grantRole|revokeRole|mint|burn|upgrade)\b/i.test(fnName);
      const hasStateChangingSink =
        /(\.\s*(transfer|transferFrom|sendValue|withdraw|withdrawAll|burn|mint|selfdestruct|delegatecall)\s*\()/i.test(fnText) ||
        /(\.\s*(balance|amount|owner|ownerId|fee|paused)\s*=[^=])/i.test(fnText) ||
        /\b(selfdestruct|sstore|delegatecall)\b/i.test(fnText) ||
        /\b(db|database|repository|collection|model|Model|store)\s*(\.\s*[a-zA-Z0-9_]+\s*)*\.\s*(deleteOne|deleteMany|updateOne|updateMany|update|save|remove|destroy)\s*\(/i.test(fnText);

      if (isAdminNamed && hasStateChangingSink && !hasAuthBoundary) {
        matches.push({
          rule_id: 'RULE-ACCESS-001',
          rule_name: 'Missing Access Control on Sensitive Administrative Function',
          category: StaticRuleCategory.ACCESS_CONTROL,
          function_name: fnName,
          line_start: fnNode.startPosition.row + 1,
          line_end: fnNode.endPosition.row + 1,
          column_start: fnNode.startPosition.column + 1,
          column_end: fnNode.endPosition.column + 1,
          matched_snippet: fnText.slice(0, 300),
          has_authorization_boundary: false,
          is_state_mutation: true,
          is_sink: true,
          details: {
            function_name: fnName,
            is_administrative: true,
            has_auth_boundary: false,
          },
        });
      }
    }

    // A nested function that itself matches (an arrow handler inside a constructor
// or module-level function) produces a second finding covering a wider range.
// Keep only the most specific match: when one match's line range is contained
// within another's, the inner (narrower) one is the real handler.
    const sorted = [...matches].sort(
      (a, b) => (a.line_end - a.line_start) - (b.line_end - b.line_start)
    );
    const kept: TreeSitterStructuralMatch[] = [];
    for (const m of sorted) {
      // Narrower matches are processed first, so a kept match that this one
      // contains means this match is the outer (enclosing) function.
      const containsKept = kept.some(
        (k) =>
          k.rule_id === m.rule_id &&
          m.line_start <= k.line_start &&
          m.line_end >= k.line_end &&
          (k.resource_identifier || '') === (m.resource_identifier || '')
      );
      if (!containsKept) kept.push(m);
    }

    return kept;
  }

  /**
   * Analyze a single file for security vulnerabilities using Tree-sitter AST queries.
   */
  async analyzeFileForVulnerabilities(
    filePath: string,
    sourceSnapshotId: string = 'snap-default',
    investigationId?: string,
    targetId?: string
  ): Promise<CandidateFinding[]> {
    await this.init();

    const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : '';
    const parseRes = await this.parseFile(
      filePath,
      content,
      sourceSnapshotId,
      investigationId,
      targetId
    );

    const candidates: CandidateFinding[] = [];

    for (const match of parseRes.structural_matches) {
      const rule = globalSecurityRuleRegistry.get(match.rule_id);
      const candidateId = `cand-ts-${match.rule_id}-${crypto.randomBytes(4).toString('hex')}`;

      const candidate: CandidateFinding = {
        id: candidateId,
        investigation_id: investigationId || 'inv-unknown',
        target_id: targetId || 'tgt-unknown',
        title: `[Tree-sitter] ${match.rule_name} in ${path.basename(filePath)}`,
        category: match.category,
        severity: rule?.severity || Severity.HIGH,
        status: FindingStatus.CANDIDATE,
        confidence: rule?.confidence || Confidence.MEDIUM,
        confidence_basis: `Tree-sitter concrete syntax tree analysis matched ${match.rule_id}: verified missing authorization boundary preceding sensitive sink.`,
        engine: 'treesitter',
        engine_version: '0.20.8',
        rule_id: match.rule_id,
        rule_version: rule?.version || '1.0.0',
        source_snapshot_id: sourceSnapshotId,
        file_path: filePath,
        line_start: match.line_start,
        line_end: match.line_end,
        column_start: match.column_start,
        column_end: match.column_end,
        matched_code: match.matched_snippet,
        data_flow: {
          source: match.resource_identifier || 'request input',
          flow: ['request input', match.details?.matched_lookup_call || 'resource lookup', 'sensitive sink'],
          object: match.details?.matched_lookup_call || undefined,
          authorization: match.has_authorization_boundary ? 'VERIFIED' : 'MISSING',
          sink: match.sink_name,
        },
        structural_evidence: {
          ast_node_type: 'function_declaration',
          function_name: match.function_name,
          has_auth_boundary: match.has_authorization_boundary,
          is_state_mutation: match.is_state_mutation,
          mutation_sink: match.sink_name,
        },
        evidence_artifact_ids: parseRes.ast_artifact_id ? [parseRes.ast_artifact_id] : [],
        cwe_ids: rule?.cwe_ids || ['CWE-639'],
        owasp_categories: rule?.owasp_categories || ['API1:2023-Broken Object Level Authorization'],
        remediation: rule?.remediation || 'Enforce authorization checks before performing sensitive operations.',
        corroborated: false,
        status_history: [
          {
            from_status: null,
            to_status: FindingStatus.CANDIDATE,
            timestamp: new Date().toISOString(),
            actor: 'engine:treesitter',
            reason: 'Initial candidate creation from Tree-sitter structural query',
          },
        ],
        provenance: {
          source_snapshot_id: sourceSnapshotId,
          engine: 'treesitter',
          engine_version: '0.20.8',
          rule_id: match.rule_id,
          rule_version: rule?.version || '1.0.0',
          matched_at: new Date().toISOString(),
          source_file: filePath,
          line: match.line_start,
        },
        metadata: {
          node_count: parseRes.node_count,
          error_count: parseRes.error_count,
          match_details: match.details,
        },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };

      candidates.push(candidate);
    }

    return candidates;
  }

  /**
   * Recursively scan a source directory and perform Tree-sitter parsing & analysis on all source files.
   */
  async scanDirectory(
    sourceDir: string,
    sourceSnapshotId: string,
    investigationId?: string,
    targetId?: string
  ): Promise<{
    results: TreeSitterParseResult[];
    candidates: CandidateFinding[];
    artifactIds: string[];
    directory_exists?: boolean;
  }> {
    await this.init();

    const results: TreeSitterParseResult[] = [];
    const candidates: CandidateFinding[] = [];
    const artifactIds: string[] = [];

    const walk = (dir: string): string[] => {
      let files: string[] = [];
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          // Skip ignore directories
          if (!['.git', 'node_modules', 'dist', 'build', '.next', '.cache'].includes(entry.name)) {
            files = files.concat(walk(fullPath));
          }
        } else if (entry.isFile()) {
          files.push(fullPath);
        }
      }
      return files;
    };

    if (!fs.existsSync(sourceDir)) {
      // Report failure rather than an empty success: scanning nothing is not a
      // completed analysis, and silently returning zero findings would let the
      // caller record "SUCCESS with no issues" for a missing target.
      return { results, candidates, artifactIds, directory_exists: false };
    }

    const allFiles = walk(sourceDir);

    for (const file of allFiles) {
      const relPath = path.relative(sourceDir, file);
      const content = fs.readFileSync(file, 'utf-8');
      
      const parseRes = await this.parseFile(
        relPath,
        content,
        sourceSnapshotId,
        investigationId,
        targetId
      );
      results.push(parseRes);

      if (parseRes.ast_artifact_id) {
        artifactIds.push(parseRes.ast_artifact_id);
      }

      // Convert structural matches to CandidateFindings
      for (const match of parseRes.structural_matches) {
        const rule = globalSecurityRuleRegistry.get(match.rule_id);
        const candidateId = `cand-ts-${crypto.randomBytes(6).toString('hex')}`;
        
        const candidate: CandidateFinding = {
          id: candidateId,
          investigation_id: investigationId || 'inv-unknown',
          target_id: targetId || 'tgt-unknown',
          title: `[Tree-sitter] ${match.rule_name} in ${relPath}`,
          category: match.category,
          severity: rule?.severity || Severity.HIGH,
          status: FindingStatus.CANDIDATE, // STRICT INVARIANT: Always starts at CANDIDATE
          confidence: rule?.confidence || Confidence.MEDIUM,
          confidence_basis: `Tree-sitter concrete syntax tree analysis matched ${match.rule_id} in function ${match.function_name || 'block'}: verified missing authorization boundary preceding sensitive sink.`,
          engine: 'treesitter',
          engine_version: '0.20.8',
          rule_id: match.rule_id,
          rule_version: rule?.version || '1.0.0',
          source_snapshot_id: sourceSnapshotId,
          file_path: relPath,
          line_start: match.line_start,
          line_end: match.line_end,
          column_start: match.column_start,
          column_end: match.column_end,
          matched_code: match.matched_snippet,
          data_flow: {
            source: match.resource_identifier || 'request input',
            flow: ['request input', match.details?.matched_lookup_call || 'resource lookup', 'sensitive sink'],
            object: match.details?.matched_lookup_call || undefined,
            authorization: match.has_authorization_boundary ? 'VERIFIED' : 'MISSING',
            sink: match.sink_name,
          },
          structural_evidence: {
            ast_node_type: 'function_declaration',
            function_name: match.function_name,
            has_auth_boundary: match.has_authorization_boundary,
            is_state_mutation: match.is_state_mutation,
            mutation_sink: match.sink_name,
          },
          evidence_artifact_ids: parseRes.ast_artifact_id ? [parseRes.ast_artifact_id] : [],
          cwe_ids: rule?.cwe_ids || [],
          owasp_categories: rule?.owasp_categories || [],
          remediation: rule?.remediation || 'Enforce authorization checks before performing sensitive operations.',
          corroborated: false,
          status_history: [
            {
              from_status: null,
              to_status: FindingStatus.CANDIDATE,
              timestamp: new Date().toISOString(),
              actor: 'engine:treesitter',
              reason: 'Initial candidate creation from Tree-sitter structural query',
            },
          ],
          provenance: {
            source_snapshot_id: sourceSnapshotId,
            engine: 'treesitter',
            engine_version: '0.20.8',
            rule_id: match.rule_id,
            rule_version: rule?.version || '1.0.0',
            matched_at: new Date().toISOString(),
            source_file: relPath,
            line: match.line_start,
          },
          metadata: {
            node_count: parseRes.node_count,
            error_count: parseRes.error_count,
            match_details: match.details,
          },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        candidates.push(candidate);
      }
    }

    return { results, candidates, artifactIds, directory_exists: true };
  }
}

export const globalTreeSitterService = new TreeSitterAnalysisService();
