/**
 * AI Provider Client & Reasoning Engine
 * Phase 6B — Advanced AI Security Controller
 * 
 * Invariants:
 * - Pluggable provider architecture (Gemini + Deterministic Expert Rules).
 * - Never leaks API keys to UI, logs, prompts, or tests.
 * - Always sanitizes context via AIProviderService.
 * - Provides deterministic fallback when no LLM API keys are configured.
 * - Validates all model outputs before tool invocation.
 * - Maintains 6 core states: FACT / HYPOTHESIS / PLAN / DECISION / BLOCKER / UNKNOWN.
 */

import {
  LLMProvider,
  AIReasoningContext,
  AIReasoningResponse,
  SuggestedToolCall,
} from './providers/types.js';
import { globalLLMProviderRegistry } from './providers/provider_registry.js';
import { CompiledPolicyAndScope } from './types.js';

export type { AIReasoningContext, SuggestedToolCall, AIReasoningResponse };

export class AIProviderClient {
  /**
   * Generates next research steps and reasoning using configured LLM or deterministic expert engine.
   */
  public async reason(context: AIReasoningContext): Promise<AIReasoningResponse> {
    const provider: LLMProvider = globalLLMProviderRegistry.getProvider();
    return provider.generateReasoning(context);
  }

  /**
   * Deterministic Rule-Based Expert Reasoning Engine.
   * Ensures 100% reproducible, high-precision security orchestration even when offline.
   */
  public async reasonDeterministic(context: AIReasoningContext): Promise<AIReasoningResponse> {
    const provider = globalLLMProviderRegistry.getProvider('deterministic');
    return provider.generateReasoning(context);
  }

  /**
   * Compiles natural language or pasted bounty guidelines into structured policy & scope.
   */
  public async compilePolicyAndScope(rawGuidelines: string): Promise<CompiledPolicyAndScope> {
    const provider = globalLLMProviderRegistry.getProvider();
    if (provider.compilePolicyAndScope) {
      return provider.compilePolicyAndScope(rawGuidelines);
    }
    const fallback = globalLLMProviderRegistry.getProvider('deterministic');
    return fallback.compilePolicyAndScope!(rawGuidelines);
  }
}

export const globalAIProviderClient = new AIProviderClient();
