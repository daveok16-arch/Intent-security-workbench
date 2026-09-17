/**
 * LLM Provider Abstraction Types
 * Phase 6B — Advanced AI Security Controller
 */

import {
  ResearchPhase,
  ResearchFact,
  ResearchHypothesis,
  ResearchUnknown,
  CapabilityMatrixEntry,
  ResearchBlocker,
  CompiledPolicyAndScope,
} from '../types.js';

export interface AIReasoningContext {
  objective: string;
  phase: ResearchPhase;
  program?: any;
  target?: any;
  /**
   * The investigation this reasoning belongs to. Tools that write records
   * (notably createAnalysisJob) must target this id; deriving one from the
   * program would orphan the result from the real investigation.
   */
  investigation_id?: string;
  /**
   * Extra parameters merged into every scheduled analysis job, so engines are
   * pointed at the real source tree (source_directory/target_directory/etc.).
   */
  analysis_parameters?: Record<string, any>;
  facts: ResearchFact[];
  hypotheses: ResearchHypothesis[];
  unknowns: ResearchUnknown[];
  capability_matrix: CapabilityMatrixEntry[];
  blockers: ResearchBlocker[];
  available_tools: Array<{ name: string; category: string; description: string; parameters: any }>;
  recent_tool_results?: any[];
}

export interface SuggestedToolCall {
  tool: string;
  parameters: Record<string, any>;
  rationale: string;
}

export interface AIReasoningResponse {
  explanation: string;
  next_phase?: ResearchPhase;
  suggested_tool_calls: SuggestedToolCall[];
  new_hypotheses?: Array<{ title: string; premise: string; confidence: 'LOW' | 'MEDIUM' | 'HIGH'; severity?: any }>;
  new_unknowns?: Array<{ question: string; context: string; impact?: string }>;
  resolved_unknowns?: Array<{ unknown_id: string; resolution_summary: string; fact_statement?: string }>;
  decisions: string[];
}

export interface LLMProvider {
  id: string;
  name: string;
  isAvailable(): boolean;
  generateReasoning(context: AIReasoningContext): Promise<AIReasoningResponse>;
  compilePolicyAndScope?(rawText: string): Promise<CompiledPolicyAndScope>;
}
