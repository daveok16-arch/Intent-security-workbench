/**
 * API Contract & Authorization Analysis Pipeline Orchestrator
 * Intent Security Workbench - Phase 3
 *
 * Coordinates OpenAPI parsing, Spectral execution, Tree-sitter source discovery,
 * contract differential analysis, and authorization candidate synthesis.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { globalOpenAPIParser } from './openapi_parser.js';
import { globalSpectralService } from './spectral_service.js';
import { globalAuthorizationAnalyzer, SourceAnalysisContext } from './authorization_analyzer.js';
import { globalContractDifferential } from './contract_differential.js';
import {
  APIContract,
  APIEndpoint,
  AuthorizationCandidate,
  ContractDiffResult,
} from './types.js';
import { createEvidenceArtifact } from '../../evidence/src/index.js';
import { ArtifactType } from '../../core/src/index.js';

export interface APIAnalysisRunOptions {
  investigationId: string;
  targetId: string;
  sourceDir: string;
  sourceSnapshotId?: string;
  specificationFilePath?: string;
  rulesetPath?: string;
}

export interface APIAnalysisPipelineResult {
  status: 'SUCCESS' | 'API_SPEC_NOT_FOUND' | 'FAILED';
  message: string;
  contract?: APIContract;
  spectralResult?: any;
  diff?: ContractDiffResult;
  authorizationCandidates: AuthorizationCandidate[];
  sourceDiscoveredEndpoints: APIEndpoint[];
  evidenceArtifactIds: string[];
}

export class APIAnalysisPipelineOrchestrator {
  /**
   * Search a target repository for candidate OpenAPI / Swagger specification files.
   */
  findSpecificationFile(sourceDir: string): string | null {
    const candidateNames = [
      'openapi.yaml',
      'openapi.yml',
      'openapi.json',
      'swagger.yaml',
      'swagger.yml',
      'swagger.json',
      'api.yaml',
      'api.yml',
      'api.json',
      'api-spec.yaml',
      'api-spec.json',
      'specs/openapi.yaml',
      'specs/openapi.json',
      'docs/openapi.yaml',
      'docs/openapi.json',
    ];

    for (const name of candidateNames) {
      const fullPath = path.join(sourceDir, name);
      if (fs.existsSync(fullPath)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8').slice(0, 500);
          if (content.includes('openapi') || content.includes('swagger')) {
            return fullPath;
          }
        } catch {
          // continue
        }
      }
    }

    // Fallback: search directory recursively up to 3 levels deep
    return this.searchRecursiveForSpec(sourceDir, 0, 3);
  }

  private searchRecursiveForSpec(dir: string, depth: number, maxDepth: number): string | null {
    if (depth > maxDepth || !fs.existsSync(dir)) return null;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isFile() && /\.(ya?ml|json)$/i.test(entry.name)) {
          try {
            const head = fs.readFileSync(fullPath, 'utf-8').slice(0, 300);
            if (/openapi\s*:\s*['"]?3/i.test(head) || /swagger\s*:\s*['"]?2/i.test(head)) {
              return fullPath;
            }
          } catch {
            // continue
          }
        } else if (entry.isDirectory()) {
          const res = this.searchRecursiveForSpec(fullPath, depth + 1, maxDepth);
          if (res) return res;
        }
      }
    } catch {
      // directory reading failure
    }
    return null;
  }

  /**
   * Run full API Security & Authorization Analysis.
   */
  async runAnalysis(options: APIAnalysisRunOptions): Promise<APIAnalysisPipelineResult> {
    const { investigationId, targetId, sourceDir, sourceSnapshotId, rulesetPath } = options;
    const evidenceArtifactIds: string[] = [];

    // 1. Locate specification
    let specPath = options.specificationFilePath;
    if (!specPath || !fs.existsSync(specPath)) {
      specPath = this.findSpecificationFile(sourceDir) || undefined;
    }

    if (!specPath || !fs.existsSync(specPath)) {
      return {
        status: 'API_SPEC_NOT_FOUND',
        message: 'No OpenAPI or Swagger API specification was discovered inside the target workspace. Non-existent contract was not fabricated.',
        authorizationCandidates: [],
        sourceDiscoveredEndpoints: [],
        evidenceArtifactIds: [],
      };
    }

    // 2. Read raw specification and calculate real SHA-256
    const rawContent = fs.readFileSync(specPath, 'utf-8');
    const specHash = crypto.createHash('sha256').update(rawContent).digest('hex');

    // Create evidence artifact for the raw specification
    try {
      const specArtifact = createEvidenceArtifact({
        investigation_id: investigationId,
        target_id: targetId,
        artifact_type: ArtifactType.SOURCE,
        content: rawContent,
        mime_type: specPath.endsWith('.json') ? 'application/json' : 'application/yaml',
        producer: 'openapi-specification-acquisition',
        producer_version: '1.0.0',
        command: `read ${specPath}`,
      });
      evidenceArtifactIds.push(specArtifact.id);
    } catch (e) {
      // Non-blocking evidence storage
    }

    // 3. Parse OpenAPI model & validate contract
    const { contract, validationIssues } = globalOpenAPIParser.parseSpecification(
      rawContent,
      specPath,
      targetId,
      investigationId,
      sourceSnapshotId
    );

    // 4. Run real Spectral CLI if installed
    const spectralResult = await globalSpectralService.lintSpecification(specPath, rulesetPath);

    if (spectralResult.available && spectralResult.stdout) {
      try {
        const spectralArtifact = createEvidenceArtifact({
          investigation_id: investigationId,
          target_id: targetId,
          artifact_type: ArtifactType.ENGINE_STDOUT,
          content: spectralResult.stdout,
          mime_type: 'application/json',
          producer: 'spectral-cli',
          producer_version: spectralResult.version || '6.x',
          command: spectralResult.command,
        });
        evidenceArtifactIds.push(spectralArtifact.id);
      } catch (e) {
        // continue
      }
    }

    // 5. Gather source code contexts from repository
    const sourceContexts: SourceAnalysisContext[] = [];
    const sourceDiscoveredEndpoints: APIEndpoint[] = [];

    this.collectSourceFiles(sourceDir, sourceContexts);

    // Extract endpoints and boundaries from all gathered source files
    for (const ctx of sourceContexts) {
      const endpoints = globalContractDifferential.extractSourceEndpoints(ctx.sourceCode, ctx.file);
      sourceDiscoveredEndpoints.push(...endpoints);
    }

    // 6. Perform Contract vs Source Differential Analysis
    const diff = globalContractDifferential.compareContractAndSource(
      contract,
      sourceDiscoveredEndpoints,
      investigationId,
      targetId
    );

    // 7. Perform Authorization Analysis for each documented endpoint
    const authorizationCandidates: AuthorizationCandidate[] = [];

    for (const ep of contract.endpoints) {
      const candidate = globalAuthorizationAnalyzer.analyzeEndpointAuthorization(
        ep,
        contract,
        sourceContexts,
        investigationId,
        targetId
      );

      if (candidate) {
        candidate.evidence_artifact_ids = [...evidenceArtifactIds];
        authorizationCandidates.push(candidate);
      }
    }

    return {
      status: 'SUCCESS',
      message: `Analyzed API specification (${contract.endpoints.length} documented endpoints, ${sourceDiscoveredEndpoints.length} source routes). Identified ${authorizationCandidates.length} authorization candidates.`,
      contract,
      spectralResult,
      diff,
      authorizationCandidates,
      sourceDiscoveredEndpoints,
      evidenceArtifactIds,
    };
  }

  private collectSourceFiles(dir: string, contexts: SourceAnalysisContext[], depth = 0, maxDepth = 4) {
    if (depth > maxDepth || !fs.existsSync(dir)) return;

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') continue;
        const fullPath = path.join(dir, entry.name);

        if (entry.isFile() && /\.(js|ts|jsx|tsx|sol|py|go|java)$/i.test(entry.name)) {
          try {
            const sourceCode = fs.readFileSync(fullPath, 'utf-8');
            contexts.push({
              file: path.relative(process.cwd(), fullPath),
              sourceCode,
            });
          } catch {
            // continue
          }
        } else if (entry.isDirectory()) {
          this.collectSourceFiles(fullPath, contexts, depth + 1, maxDepth);
        }
      }
    } catch {
      // continue
    }
  }
}

export const globalAPIAnalysisOrchestrator = new APIAnalysisPipelineOrchestrator();
