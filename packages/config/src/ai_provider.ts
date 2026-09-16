/**
 * AI Provider Configuration & Controller Preparation
 * Intent Security Workbench - Environment & Configuration Hardening
 *
 * Requirements:
 * - Conceptual separation of AI_PROVIDER, AI_MODEL, AI_ENDPOINT, AI_API_KEY
 * - API keys remain strictly backend/server-side
 * - AI model/prompt NEVER receives API keys or secrets in prompt context
 * - Safe capability status without credential leakage (e.g. "Gemini provider configured: YES")
 */

import { AIProviderType, AIProviderConfiguration } from './types.js';
import { redactString } from './redaction.js';

export interface AIProviderStatus {
  provider: AIProviderType;
  configured: boolean;
  model: string;
  capabilities: string[];
  endpoint_configured: boolean;
  status_text: string;
}

export interface SupportedProviderInfo {
  provider: AIProviderType;
  displayName: string;
  defaultModel: string;
  description: string;
  capabilities: string[];
}

export const SUPPORTED_AI_PROVIDERS: SupportedProviderInfo[] = [
  {
    provider: 'gemini',
    displayName: 'Google Gemini',
    defaultModel: 'gemini-3.8-flash',
    description: 'High-speed reasoning, formal verification proof synthesis, and AST pattern matching.',
    capabilities: ['text_reasoning', 'ast_analysis', 'proof_synthesis', 'structured_outputs'],
  },
  {
    provider: 'grok',
    displayName: 'xAI Grok',
    defaultModel: 'grok-beta',
    description: 'Deep codebase exploration and exploit path reasoning.',
    capabilities: ['text_reasoning', 'code_analysis', 'structured_outputs'],
  },
  {
    provider: 'openai',
    displayName: 'OpenAI',
    defaultModel: 'gpt-4o',
    description: 'Contract analysis and authorization invariant specification.',
    capabilities: ['text_reasoning', 'ast_analysis', 'structured_outputs'],
  },
  {
    provider: 'anthropic',
    displayName: 'Anthropic Claude',
    defaultModel: 'claude-3-5-sonnet-latest',
    description: 'Deep semantic security audit and multi-step investigation synthesis.',
    capabilities: ['text_reasoning', 'code_analysis', 'structured_outputs'],
  },
];

export class AIProviderService {
  private env: Record<string, string | undefined>;

  constructor(env: Record<string, string | undefined> = process.env) {
    this.env = { ...env };
  }

  updateEnv(env: Record<string, string | undefined> = process.env): void {
    this.env = { ...env };
  }

  /**
   * Return safe capability status for the currently selected AI provider.
   * NEVER returns the API key or any credential.
   */
  getStatus(): AIProviderStatus {
    const provider = (this.env.AI_PROVIDER || 'none').toLowerCase() as AIProviderType;
    return this.getProviderStatus(provider);
  }

  /**
   * Return safe capability status for a specific provider.
   */
  getProviderStatus(provider: AIProviderType): AIProviderStatus {
    const info = SUPPORTED_AI_PROVIDERS.find((p) => p.provider === provider);
    const configured = this.isProviderConfigured(provider);

    const model =
      provider === (this.env.AI_PROVIDER || 'none').toLowerCase()
        ? this.env.AI_MODEL || (info ? info.defaultModel : 'default')
        : info ? info.defaultModel : 'none';

    return {
      provider,
      configured,
      model,
      capabilities: info ? info.capabilities : [],
      endpoint_configured: Boolean(this.env.AI_ENDPOINT),
      status_text: configured ? `${info?.displayName || provider}: CONFIGURED` : `${info?.displayName || provider}: NOT_CONFIGURED`,
    };
  }

  /**
   * Truthfully check if an AI provider has its credential configured.
   */
  isProviderConfigured(provider: AIProviderType): boolean {
    switch (provider) {
      case 'gemini':
        return Boolean(this.env.GEMINI_API_KEY && this.env.GEMINI_API_KEY.trim().length > 0);
      case 'grok':
        return Boolean(this.env.GROK_API_KEY && this.env.GROK_API_KEY.trim().length > 0);
      case 'openai':
        return Boolean(this.env.OPENAI_API_KEY && this.env.OPENAI_API_KEY.trim().length > 0);
      case 'anthropic':
        return Boolean(this.env.ANTHROPIC_API_KEY && this.env.ANTHROPIC_API_KEY.trim().length > 0);
      case 'custom':
        return Boolean(this.env.AI_ENDPOINT);
      case 'none':
      default:
        return false;
    }
  }

  /**
   * Sanitizes prompt context before sending to any LLM.
   * Ensures API keys, database credentials, or internal secret strings are stripped from the prompt.
   */
  sanitizePromptContext(contextText: any): string {
    if (!contextText) return '';
    const str = typeof contextText === 'string' ? contextText : JSON.stringify(contextText);
    let clean = redactString(str);
    if (typeof clean !== 'string') {
      clean = String(clean);
    }

    // Explicitly redact any current server keys if they happen to appear in context
    const currentKeys = [
      this.env.GEMINI_API_KEY,
      this.env.GROK_API_KEY,
      this.env.OPENAI_API_KEY,
      this.env.ANTHROPIC_API_KEY,
      this.env.DATABASE_URL,
      this.env.REDIS_URL,
    ].filter(Boolean) as string[];

    for (const key of currentKeys) {
      if (key && key.length > 5) {
        clean = clean.split(key).join('[REDACTED_SECRET]');
      }
    }

    return clean;
  }

  /**
   * Alias for sanitizePromptContext.
   */
  sanitizeContext(contextText: string): string {
    return this.sanitizePromptContext(contextText);
  }

  /**
   * Returns list of all supported providers and their safe metadata.
   */
  listSupportedProviders(): SupportedProviderInfo[] {
    return SUPPORTED_AI_PROVIDERS;
  }
}

export const globalAIProviderService = new AIProviderService();
