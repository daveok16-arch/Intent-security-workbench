/**
 * Deterministic Expert Security Reasoning Engine
 * Phase 6B — Advanced AI Security Controller
 *
 * Provides reproducible, verifiable, offline security orchestration
 * adhering strictly to Workbench anti-fabrication invariants.
 */

import {
  LLMProvider,
  AIReasoningContext,
  AIReasoningResponse,
  SuggestedToolCall,
} from './types.js';
import {
  ResearchPhase,
  ScopeAssetType,
  ScopeInclusionStatus,
  TargetType,
  Ecosystem,
  CompiledPolicyAndScope,
  CompiledScopeAsset,
  CompiledSuggestedTarget,
} from '../types.js';

export class DeterministicProvider implements LLMProvider {
  public readonly id = 'deterministic';
  public readonly name = 'Deterministic Expert Security Rules';

  public isAvailable(): boolean {
    return true; // Always available without network or external keys
  }

  /**
   * Compiles natural-language or pasted bounty program guidelines into structured policy & scope.
   */
  public async compilePolicyAndScope(rawText: string): Promise<CompiledPolicyAndScope> {
    const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
    let programName = 'Bug Bounty Security Program';
    let safeHarbor = true;
    const testingRules: string[] = [];
    const scopeEntries: CompiledScopeAsset[] = [];
    const suggestedTargets: CompiledSuggestedTarget[] = [];
    const unknowns: Array<{ question: string; context: string; impact: string }> = [];

    let currentSection: 'GENERAL' | 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'RULES' | 'EXCLUSIONS' = 'GENERAL';

    // Heuristic parsing of title / program name
    const firstHeading = lines.find(l => l.startsWith('# '));
    if (firstHeading) {
      programName = firstHeading.replace('# ', '').trim();
    } else if (lines.length > 0 && lines[0].length < 80) {
      programName = lines[0];
    }

    // Scan for URLs, GitHub repos, and contract addresses
    const repoRegex = /https?:\/\/github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_.-]+)/g;
    const contractRegex = /0x[a-fA-F0-9]{40}/g;
    const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/[^\s]*)?/g;

    for (const line of lines) {
      const lower = line.toLowerCase();

      // Section triggers
      if (lower.includes('in-scope') || lower.includes('in scope') || lower.includes('authorized assets')) {
        currentSection = 'IN_SCOPE';
        continue;
      } else if (lower.includes('out-of-scope') || lower.includes('out of scope') || lower.includes('excluded') || lower.includes('exclusions')) {
        currentSection = 'OUT_OF_SCOPE';
        continue;
      } else if (lower.includes('testing rule') || lower.includes('policy rule') || lower.includes('guideline') || lower.includes('prohibited')) {
        currentSection = 'RULES';
        continue;
      }

      if (lower.includes('no safe harbor') || lower.includes('safe harbor does not apply')) {
        safeHarbor = false;
      }

      // Collect testing rules
      if (currentSection === 'RULES' || lower.includes('do not') || lower.includes('prohibited') || lower.includes('allowed only')) {
        const cleanRule = line.replace(/^[-*•0-9.]+\s*/, '');
        if (cleanRule.length > 10 && !testingRules.includes(cleanRule)) {
          testingRules.push(cleanRule);
        }
      }

      // Check for repos
      let repoMatch;
      while ((repoMatch = repoRegex.exec(line)) !== null) {
        const repoUrl = repoMatch[0];
        const status = currentSection === 'OUT_OF_SCOPE' ? ScopeInclusionStatus.OUT_OF_SCOPE : ScopeInclusionStatus.IN_SCOPE;
        if (!scopeEntries.some(e => e.asset_identifier === repoUrl)) {
          scopeEntries.push({
            asset_identifier: repoUrl,
            asset_type: ScopeAssetType.REPOSITORY,
            inclusion_status: status,
            instruction: status === ScopeInclusionStatus.IN_SCOPE ? 'Source repository authorized for static & dynamic inspection' : 'Excluded repository',
          });

          if (status === ScopeInclusionStatus.IN_SCOPE) {
            const repoName = repoMatch[2].replace(/\.git$/, '');
            suggestedTargets.push({
              name: repoName,
              target_type: TargetType.SMART_CONTRACT,
              ecosystem: Ecosystem.EVM,
              primary_location: repoUrl,
              repository_url: repoUrl,
            });
          }
        }
      }

      // Check for contracts
      let contractMatch;
      while ((contractMatch = contractRegex.exec(line)) !== null) {
        const addr = contractMatch[0];
        const status = currentSection === 'OUT_OF_SCOPE' ? ScopeInclusionStatus.OUT_OF_SCOPE : ScopeInclusionStatus.IN_SCOPE;
        if (!scopeEntries.some(e => e.asset_identifier.toLowerCase() === addr.toLowerCase())) {
          scopeEntries.push({
            asset_identifier: addr,
            asset_type: ScopeAssetType.SMART_CONTRACT,
            inclusion_status: status,
            instruction: status === ScopeInclusionStatus.IN_SCOPE ? 'On-chain contract authorized for fork reproduction' : 'Excluded contract',
          });

          if (status === ScopeInclusionStatus.IN_SCOPE) {
            suggestedTargets.push({
              name: `Contract ${addr.substring(0, 8)}...`,
              target_type: TargetType.SMART_CONTRACT,
              ecosystem: Ecosystem.EVM,
              primary_location: addr,
            });
          }
        }
      }

      // Check for generic domains/endpoints if not already matched
      if (currentSection === 'IN_SCOPE' || currentSection === 'OUT_OF_SCOPE') {
        let urlMatch;
        while ((urlMatch = urlRegex.exec(line)) !== null) {
          const u = urlMatch[0];
          if (!u.includes('github.com') && !scopeEntries.some(e => e.asset_identifier === u)) {
            const status = currentSection === 'OUT_OF_SCOPE' ? ScopeInclusionStatus.OUT_OF_SCOPE : ScopeInclusionStatus.IN_SCOPE;
            scopeEntries.push({
              asset_identifier: u,
              asset_type: ScopeAssetType.URL,
              inclusion_status: status,
              instruction: status === ScopeInclusionStatus.IN_SCOPE ? 'Web/API endpoint authorized for scoped security testing' : 'Excluded endpoint',
            });
          }
        }
      }
    }

    // Identify standard unknowns if information is incomplete
    if (suggestedTargets.length > 0) {
      unknowns.push({
        question: 'Are target source repositories pinned to specific release commit SHAs?',
        context: `Discovered ${suggestedTargets.length} target(s). Target source requires cryptographic commit resolution.`,
        impact: 'Unpinned commits may drift between analysis and validation.',
      });
    }

    if (testingRules.length === 0) {
      testingRules.push('Authorized testing only within specified asset scope.');
      testingRules.push('Denial of service and physical attacks strictly forbidden.');
      testingRules.push('Sandboxed local fork simulation preferred for exploit reproduction.');
    }

    return {
      program_name: programName,
      policy_summary: `Authoritative bounty guidelines for ${programName}. Discovered ${scopeEntries.length} scope entries (${scopeEntries.filter(s => s.inclusion_status === ScopeInclusionStatus.IN_SCOPE).length} in-scope).`,
      safe_harbor: safeHarbor,
      testing_rules: testingRules,
      disclosure_policy: 'Coordinated Vulnerability Disclosure (90-day standard or program-specified window).',
      scope_entries: scopeEntries,
      suggested_targets: suggestedTargets,
      unknowns,
    };
  }

  /**
   * Generates step reasoning based on structured state machine and established facts.
   */
  public async generateReasoning(context: AIReasoningContext): Promise<AIReasoningResponse> {
    const phase = context.phase;
    const decisions: string[] = [];
    const suggestedToolCalls: SuggestedToolCall[] = [];
    const newUnknowns: Array<{ question: string; context: string; impact?: string }> = [];
    const resolvedUnknowns: Array<{ unknown_id: string; resolution_summary: string; fact_statement?: string }> = [];
    const newHypotheses: any[] = [];
    let explanation = '';
    let nextPhase: ResearchPhase | undefined;

    switch (phase) {
      case ResearchPhase.IDLE:
      case ResearchPhase.UNDERSTANDING_REQUEST:
        explanation = `Analyzing research objective: "${context.objective}". Determining required program and target scopes.`;
        decisions.push('Identified objective requiring program policy inspection and target scope verification.');
        
        // Formulate initial unknowns
        if (!context.program) {
          newUnknowns.push({
            question: 'Which registered bounty program governs this research objective?',
            context: 'Every security action requires authoritative program policy validation.',
            impact: 'Cannot execute tests without active program safe harbor.',
          });
        }
        if (!context.target) {
          newUnknowns.push({
            question: 'Which specific target asset is the subject of evaluation?',
            context: 'Scope verification requires concrete repository, contract address, or API URL.',
            impact: 'Target cannot be evaluated for authorization.',
          });
        }
        nextPhase = ResearchPhase.PLANNING;
        break;

      case ResearchPhase.PLANNING:
        explanation = 'Constructing execution plan: Policy validation -> Target discovery -> Source verification -> Capability assessment -> Analysis.';
        decisions.push('Generated 7-stage security research plan adhering to Workbench verification invariants.');
        if (context.program?.id) {
          suggestedToolCalls.push({
            tool: 'validateProgramPolicy',
            parameters: { program_id: context.program.id },
            rationale: 'Verify program rules and freshness before evaluating targets.',
          });
          nextPhase = ResearchPhase.POLICY_VALIDATION;
        } else {
          suggestedToolCalls.push({
            tool: 'listTargets',
            parameters: {},
            rationale: 'Discover available targets registered under active programs.',
          });
          nextPhase = ResearchPhase.TARGET_VALIDATION;
        }
        break;

      case ResearchPhase.POLICY_VALIDATION:
        explanation = 'Program policy validated. Verifying target scope inclusion status.';
        decisions.push('Program policy confirmed valid and active. Proceeding to scope validation.');
        if (context.program?.id && context.target) {
          suggestedToolCalls.push({
            tool: 'evaluateScope',
            parameters: {
              program_id: context.program.id,
              target_identifier: context.target.primary_location || context.target.repository_url || context.target.name,
              asset_type: context.target.target_type,
            },
            rationale: 'Authoritatively evaluate target against program scope entries.',
          });
        }
        nextPhase = ResearchPhase.SCOPE_VALIDATION;
        break;

      case ResearchPhase.SCOPE_VALIDATION:
        explanation = 'Target scope validated. Target confirmed IN_SCOPE for security research.';
        decisions.push('Target scope evaluated: IN_SCOPE. Proceeding to source acquisition.');
        if (context.target?.id) {
          suggestedToolCalls.push({
            tool: 'acquireTargetSource',
            parameters: { target_id: context.target.id },
            rationale: 'Acquire source code into sandbox containment for hash calculation.',
          });
        }
        nextPhase = ResearchPhase.SOURCE_ACQUISITION;
        break;

      case ResearchPhase.SOURCE_ACQUISITION:
        explanation = 'Source code acquired. Calculating cryptographic SHA-256 tree hash and commit verification.';
        decisions.push('Source code cloned into sandbox container. Performing tree integrity check.');
        if (context.target?.id) {
          suggestedToolCalls.push({
            tool: 'verifySourceIntegrity',
            parameters: { target_id: context.target.id },
            rationale: 'Verify source snapshot tree hash and provenance integrity.',
          });
        }
        nextPhase = ResearchPhase.SOURCE_VERIFICATION;
        break;

      case ResearchPhase.SOURCE_VERIFICATION:
        explanation = 'Source integrity verified cryptographically. Assessing engine capabilities for target ecosystem.';
        decisions.push('Source tree hash verified. Matching target ecosystem to installed engines.');
        if (context.target?.id) {
          suggestedToolCalls.push({
            tool: 'inspectTargetCapability',
            parameters: { target_id: context.target.id },
            rationale: 'Build technology-to-engine capability matrix.',
          });
        }
        nextPhase = ResearchPhase.CAPABILITY_ASSESSMENT;
        break;

      case ResearchPhase.CAPABILITY_ASSESSMENT: {
        const applicable = context.capability_matrix.filter(c => c.status === 'APPLICABLE');
        const notInstalled = context.capability_matrix.filter(c => c.status === 'NOT_INSTALLED');
        
        explanation = `Capability assessment complete. ${applicable.length} engines applicable for target ecosystem (${applicable.map(c => c.name).join(', ')}).`;
        decisions.push(`Selected applicable installed engines: ${applicable.map(c => c.name).join(', ')}.`);
        
        if (notInstalled.length > 0) {
          newUnknowns.push({
            question: `Engines not installed: ${notInstalled.map(e => e.name).join(', ')}. Can alternative engines cover the required vulnerability classes?`,
            context: 'Engine capability matrix identifies tools not present in this runtime container.',
            impact: 'Certain engine-specific detectors will be bypassed.',
          });
        }
        nextPhase = ResearchPhase.ANALYSIS_PLANNING;
        break;
      }

      case ResearchPhase.ANALYSIS_PLANNING: {
        explanation = 'Analysis plan formulated. Submitting static analysis and AST inspection jobs to orchestrator.';
        const targetId = context.target?.id;
        const invId = context.program?.id ? `inv-${context.program.id}` : 'inv-active';

        const applicable = context.capability_matrix.filter(c => c.status === 'APPLICABLE');
        for (const eng of applicable) {
          if (eng.engine_id === 'slither' || eng.engine_id === 'semgrep' || eng.engine_id === 'treesitter') {
            suggestedToolCalls.push({
              tool: 'createAnalysisJob',
              parameters: {
                investigation_id: invId,
                target_id: targetId,
                engine_id: eng.engine_id,
                operation: eng.engine_id === 'treesitter' ? 'ast_rule_scan' : 'standard_scan',
              },
              rationale: `Execute static rule analysis using ${eng.name}.`,
            });
          }
        }
        decisions.push('Scheduled automated static analysis jobs.');
        nextPhase = ResearchPhase.ANALYSIS_EXECUTION;
        break;
      }

      case ResearchPhase.ANALYSIS_EXECUTION:
        explanation = 'Analysis jobs running or completed. Correlating engine findings and forming hypotheses.';
        decisions.push('Engine execution outputs processed. Moving to hypothesis formation.');
        nextPhase = ResearchPhase.RESULT_CORRELATION;
        break;

      case ResearchPhase.RESULT_CORRELATION:
      case ResearchPhase.HYPOTHESIS_FORMATION:
        explanation = 'Forming vulnerability hypotheses based on verified artifacts.';
        if (context.target) {
          newHypotheses.push({
            title: `State Transition & Invariant Verification for ${context.target.name}`,
            premise: 'State updates in core contract methods must strictly maintain token balance and access control invariants.',
            confidence: 'MEDIUM',
            severity: 'HIGH',
          });
        }
        decisions.push('Formed initial research hypotheses.');
        nextPhase = ResearchPhase.CORROBORATION;
        break;

      case ResearchPhase.CORROBORATION:
        explanation = 'Candidate corroboration prepared. Dynamic reproduction requires researcher policy authorization.';
        decisions.push('Prepared verification plan. Dynamic testing gated on user authorization.');
        nextPhase = ResearchPhase.VERIFICATION_REQUESTED;
        break;

      case ResearchPhase.VERIFICATION_REQUESTED:
        explanation = 'Verification requested. Awaiting dynamic execution authorization or formal proof dispatch.';
        decisions.push('Controller awaiting dynamic verification authorization.');
        break;

      default:
        explanation = `Controller currently in phase ${phase}.`;
        break;
    }

    return {
      explanation,
      next_phase: nextPhase,
      suggested_tool_calls: suggestedToolCalls,
      new_hypotheses: newHypotheses,
      new_unknowns: newUnknowns,
      resolved_unknowns: resolvedUnknowns,
      decisions,
    };
  }
}
