/**
 * Gemini LLM Provider
 * Phase 6B — Advanced AI Security Controller
 *
 * Grounded in Google GenAI TypeScript SDK (@google/genai)
 * Enforces server-side execution and strict context sanitization.
 */

import { GoogleGenAI } from '@google/genai';
import {
  LLMProvider,
  AIReasoningContext,
  AIReasoningResponse,
} from './types.js';
import { CompiledPolicyAndScope } from '../types.js';
import {
  globalConfig,
  globalAIProviderService,
} from '../../../config/src/index.js';
import { DeterministicProvider } from './deterministic_provider.js';

export class GeminiProvider implements LLMProvider {
  public readonly id = 'gemini';
  public readonly name = 'Google Gemini AI Security Reasoning Engine';
  private fallbackProvider: DeterministicProvider;

  constructor() {
    this.fallbackProvider = new DeterministicProvider();
  }

  public isAvailable(): boolean {
    const key = process.env.GEMINI_API_KEY || globalConfig.getSecretConfig().gemini_api_key;
    return Boolean(key && key.trim().length > 0);
  }

  private getClient(): GoogleGenAI | null {
    const key = process.env.GEMINI_API_KEY || globalConfig.getSecretConfig().gemini_api_key;
    if (!key) return null;
    return new GoogleGenAI({ apiKey: key });
  }

  /**
   * Compiles natural language or pasted bounty program guidelines into structured policy & scope.
   */
  public async compilePolicyAndScope(rawText: string): Promise<CompiledPolicyAndScope> {
    const client = this.getClient();
    if (!client) {
      return this.fallbackProvider.compilePolicyAndScope(rawText);
    }

    try {
      const sanitizedText = globalAIProviderService.sanitizeContext(rawText);
      const prompt = `You are an expert security policy compiler for the Intent Security Workbench.
Your task is to analyze the following bug bounty or security program guidelines and extract authoritative policy rules and asset scopes.

CRITICAL SECURITY RULES:
- Never fabricate targets, contracts, or in-scope assets.
- If an asset is listed under Out of Scope or Excluded, mark it as OUT_OF_SCOPE.
- Identify safe harbor terms and testing rules.
- Identify UNKNOWNS: list questions about missing repository URLs, commit hashes, or deployment parameters.

OUTPUT FORMAT (JSON ONLY, no markdown, no preamble):
{
  "program_name": "string",
  "policy_summary": "string",
  "safe_harbor": boolean,
  "testing_rules": ["string"],
  "disclosure_policy": "string",
  "scope_entries": [
    {
      "asset_identifier": "string (URL, domain, contract 0x..., or repo)",
      "asset_type": "REPOSITORY | SMART_CONTRACT | URL | DOMAIN | API | OTHER",
      "inclusion_status": "IN_SCOPE | OUT_OF_SCOPE",
      "instruction": "string"
    }
  ],
  "suggested_targets": [
    {
      "name": "string",
      "target_type": "SMART_CONTRACT | WEB_APPLICATION | REST_API | REPOSITORY",
      "ecosystem": "EVM | SOLANA | RUST | TYPESCRIPT | PYTHON | GENERIC",
      "primary_location": "string",
      "repository_url": "string (optional)"
    }
  ],
  "unknowns": [
    {
      "question": "string",
      "context": "string",
      "impact": "string"
    }
  ]
}

Program Guidelines Content:
${sanitizedText}`;

      const aiConfig = globalConfig.getAIConfig();
      const modelName = (aiConfig.model && aiConfig.model !== 'default') ? aiConfig.model : 'gemini-3.6-flash';

      const response = await client.models.generateContent({
        model: modelName,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const text = response.text || '';
      const parsed = JSON.parse(text);
      return {
        program_name: parsed.program_name || 'Bounty Security Program',
        policy_summary: parsed.policy_summary || 'Compiled bounty guidelines',
        safe_harbor: Boolean(parsed.safe_harbor),
        testing_rules: Array.isArray(parsed.testing_rules) ? parsed.testing_rules : [],
        disclosure_policy: parsed.disclosure_policy || 'Coordinated Disclosure',
        scope_entries: Array.isArray(parsed.scope_entries) ? parsed.scope_entries : [],
        suggested_targets: Array.isArray(parsed.suggested_targets) ? parsed.suggested_targets : [],
        unknowns: Array.isArray(parsed.unknowns) ? parsed.unknowns : [],
      };
    } catch (err: any) {
      console.warn(`[GeminiProvider] Fallback to deterministic policy compiler: ${err.message}`);
      return this.fallbackProvider.compilePolicyAndScope(rawText);
    }
  }

  /**
   * Generates step reasoning with Gemini model, falling back cleanly to deterministic provider.
   */
  public async generateReasoning(context: AIReasoningContext): Promise<AIReasoningResponse> {
    const client = this.getClient();
    if (!client) {
      return this.fallbackProvider.generateReasoning(context);
    }

    try {
      const sanitizedContextStr = globalAIProviderService.sanitizeContext(JSON.stringify(context));
      const sanitizedContext: AIReasoningContext = JSON.parse(sanitizedContextStr);
      const prompt = `You are the AI Security Control Plane Orchestrator for Intent Security Workbench.
You operate as an autonomous intelligence surface over verified security workbench services.

INVARIANTS:
1. Never fabricate tool outputs, findings, or proof states.
2. Ground all decisions in established ground-truth FACTS (confidence 1.0).
3. Distinguish clearly between:
   - FACTS: Proven ground truth from sandbox tools and SHA-256 hashes.
   - HYPOTHESES: Candidate vulnerabilities needing verification.
   - UNKNOWNS: Missing or unverified critical information that must be resolved.
   - DECISIONS: Logical progression choices.
   - BLOCKERS: Policy or capability halts.
4. If an action is sensitive (dynamic exploit execution, state differential tests), suggest it but note approval requirement.
5. Never bypass program scope or policy.

Available Tools:
${JSON.stringify(sanitizedContext.available_tools, null, 2)}

Current State:
- Objective: ${sanitizedContext.objective}
- Phase: ${sanitizedContext.phase}
- Target: ${JSON.stringify(sanitizedContext.target)}
- Established Facts: ${JSON.stringify(sanitizedContext.facts)}
- Hypotheses: ${JSON.stringify(sanitizedContext.hypotheses)}
- Unknowns: ${JSON.stringify(sanitizedContext.unknowns)}
- Capability Matrix: ${JSON.stringify(sanitizedContext.capability_matrix)}
- Blockers: ${JSON.stringify(sanitizedContext.blockers)}

OUTPUT FORMAT (JSON ONLY):
{
  "explanation": "High-level plain English explanation of current action and security status",
  "next_phase": "Optional next phase string if state transition is warranted",
  "suggested_tool_calls": [
    {
      "tool": "name_of_tool_from_available_tools",
      "parameters": {},
      "rationale": "Why this tool is called based on facts and policy"
    }
  ],
  "new_hypotheses": [
    {
      "title": "string",
      "premise": "string",
      "confidence": "LOW | MEDIUM | HIGH",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ],
  "new_unknowns": [
    {
      "question": "string",
      "context": "string",
      "impact": "string"
    }
  ],
  "resolved_unknowns": [
    {
      "unknown_id": "string",
      "resolution_summary": "string",
      "fact_statement": "string"
    }
  ],
  "decisions": ["string"]
}`;

      const aiConfig = globalConfig.getAIConfig();
      const modelName = (aiConfig.model && aiConfig.model !== 'default') ? aiConfig.model : 'gemini-3.6-flash';

      const response = await client.models.generateContent({
        model: modelName,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1,
        },
      });

      const text = response.text || '';
      const parsed = JSON.parse(text);

      return {
        explanation: parsed.explanation || `Analyzing investigation phase ${context.phase}.`,
        next_phase: parsed.next_phase,
        suggested_tool_calls: Array.isArray(parsed.suggested_tool_calls) ? parsed.suggested_tool_calls : [],
        new_hypotheses: Array.isArray(parsed.new_hypotheses) ? parsed.new_hypotheses : [],
        new_unknowns: Array.isArray(parsed.new_unknowns) ? parsed.new_unknowns : [],
        resolved_unknowns: Array.isArray(parsed.resolved_unknowns) ? parsed.resolved_unknowns : [],
        decisions: Array.isArray(parsed.decisions) ? parsed.decisions : [],
      };
    } catch (err: any) {
      console.warn(`[GeminiProvider] Reasoning fallback to deterministic provider: ${err.message}`);
      return this.fallbackProvider.generateReasoning(context);
    }
  }
}
