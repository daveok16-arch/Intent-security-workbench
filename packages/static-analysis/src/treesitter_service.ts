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
      // Requiring genuine request context is what keeps this rule from firing on
      // ordinary library code, where `get(`/`delete(`/`add(` are ubiquitous.
      const hasRequestParam =
        /(req|request)\.(params|query|body)\s*(\.|\[)/i.test(fnText) ||
        /\bctx\.(params|query|body)\b/i.test(fnText) ||
        /\bevent\.(pathParameters|queryStringParameters)\b/i.test(fnText);
      // Node/Express-style handler signature, e.g. (req, res) or (request, reply).
      const hasHandlerSignature = /\(\s*(req|request)\s*,\s*(res|reply|response)\b/.test(fnText);
      // Route registration: router.get('/x/:id', ...) / app.post(...).
      const hasRouteRegistration =
        /\b(router|app|server|api|route)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`]/i.test(fnText) ||
        /\b(router|app|server|api|route)\.(get|post|put|patch|delete|all|use)\s*\(/.test(fnText);
      // Handler declared as a route callback: router.get('/x/:id', async (req,res) => ...)
      const isRouteHandler = hasRouteRegistration || hasHandlerSignature;
      const hasRouteParam = hasRequestParam;

      // Resource lookup, anchored on data-access idioms rather than bare verbs.
      const hasResourceLookup =
        /\b(db|database|repository|repo|prisma|sequelize|knex|collection|model|Model|store)\s*(\.\s*[a-zA-Z0-9_]+\s*)*\.\s*(findOne|findById|findUnique|findFirst|findByPk|find|get|getById|getAccount|getUser|query|select)\s*\(/i.test(fnText) ||
        /\b(Document|Order|Account|User|Resource|Invoice|Payment|Wallet|Vault|Profile)\s*\.\s*(findOne|findById|findUnique|findFirst|find|get|query)\s*\(/.test(fnText);

      // Sensitive sink: a mutation, transfer, or destructive operation on data.
      const hasMutationOrTransfer =
        /\b(db|database|repository|repo|prisma|sequelize|knex|collection|model|Model|store)\s*(\.\s*[a-zA-Z0-9_]+\s*)*\.\s*(deleteOne|deleteMany|deleteById|updateOne|updateMany|update|save|insert|insertOne|remove|destroy)\s*\(/i.test(fnText) ||
        /\.\s*(transfer|transferFrom|sendValue|withdraw|withdrawAll|burn|mint)\s*\(/.test(fnText) ||
        /\.\s*(balance|amount|owner|ownerId)\s*=[^=]/.test(fnText);

      // The request-supplied identifier must actually flow into the lookup or
      // mutation, otherwise this is an unrelated function that merely happens to
      // reference request data.
      const usesRequestValueInQuery =
        /(findOne|findById|findUnique|findFirst|find|get|getById|query|select|deleteOne|deleteMany|updateOne|updateMany|update|save|remove|destroy)\s*\(\s*\{?[^)]{0,120}(req|request)\.(params|query|body)/is.test(fnText) ||
        /\b(const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(req|request)\.(params|query|body)\b/i.test(fnText) ||
        /\b(ctx|event)\.(params|query|body|pathParameters)\b/i.test(fnText);

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
          resource_identifier: hasRouteParam ? 'req.params.id' : (paramNames[0] || 'id'),
          details: {
            parameters: paramNames,
            has_route_param: hasRouteParam,
            has_resource_lookup: hasResourceLookup,
            has_mutation_or_transfer: hasMutationOrTransfer,
            has_auth_boundary: false,
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

    return matches;
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
          source: match.resource_identifier || 'external parameter',
          flow: ['function input', 'resource lookup', 'sensitive sink'],
          object: match.resource_identifier ? `db.getAccount(${match.resource_identifier})` : undefined,
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
            source: match.resource_identifier || 'external parameter',
            flow: ['function input', 'resource lookup', 'sensitive sink'],
            object: match.resource_identifier ? `db.getAccount(${match.resource_identifier})` : undefined,
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
