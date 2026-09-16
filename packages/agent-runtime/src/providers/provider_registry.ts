/**
 * LLM Provider Registry
 * Phase 6B — Advanced AI Security Controller
 *
 * Supports pluggable LLM backends (Gemini, Claude/Anthropic, OpenAI, Local, Deterministic)
 * with deterministic fallback guarantee.
 */

import { LLMProvider } from './types.js';
import { GeminiProvider } from './gemini_provider.js';
import { DeterministicProvider } from './deterministic_provider.js';
import { globalConfig } from '../../../config/src/index.js';

export class LLMProviderRegistry {
  private providers: Map<string, LLMProvider> = new Map();
  private defaultProviderId: string = 'gemini';

  constructor() {
    this.registerProvider(new GeminiProvider());
    this.registerProvider(new DeterministicProvider());
  }

  public registerProvider(provider: LLMProvider): void {
    this.providers.set(provider.id, provider);
  }

  public getProvider(id?: string): LLMProvider {
    const targetId = id || globalConfig.getAIConfig().provider || this.defaultProviderId;
    const provider = this.providers.get(targetId);
    if (provider && provider.isAvailable()) {
      return provider;
    }
    // Fall back to Gemini if configured, or deterministic provider
    const gemini = this.providers.get('gemini');
    if (gemini && gemini.isAvailable()) {
      return gemini;
    }
    return this.providers.get('deterministic')!;
  }

  public listProviders(): Array<{ id: string; name: string; available: boolean }> {
    return Array.from(this.providers.values()).map(p => ({
      id: p.id,
      name: p.name,
      available: p.isAvailable(),
    }));
  }

  public setDefaultProvider(id: string): void {
    if (this.providers.has(id)) {
      this.defaultProviderId = id;
    }
  }
}

export const globalLLMProviderRegistry = new LLMProviderRegistry();
