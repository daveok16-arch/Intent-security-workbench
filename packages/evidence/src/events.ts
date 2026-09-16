/**
 * Evidence Event Manager (Append-Only Event Store)
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Enforces immutability: historical evidence events cannot be deleted or modified.
 * Corrections must be logged as new METADATA_CORRECTED events.
 */

import { EvidenceEvent, EvidenceEventType } from '../../core/src/index.js';

export class EvidenceEventManager {
  private events: Map<string, EvidenceEvent> = new Map();

  /**
   * Records an immutable evidence event.
   */
  public recordEvent(params: {
    id?: string;
    investigation_id: string;
    event_type: EvidenceEventType | string;
    actor?: string;
    producer: string;
    producer_version?: string;
    input_artifacts?: string[];
    output_artifacts?: string[];
    metadata?: Record<string, any>;
  }): EvidenceEvent {
    const id = params.id || `ev-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const event: EvidenceEvent = {
      id,
      investigation_id: params.investigation_id,
      event_type: params.event_type,
      timestamp: new Date().toISOString(),
      actor: params.actor || 'system',
      producer: params.producer,
      producer_version: params.producer_version || '1.0.0',
      input_artifacts: params.input_artifacts || [],
      output_artifacts: params.output_artifacts || [],
      metadata: Object.freeze({ ...(params.metadata || {}) }),
    };

    // Store immutable copy
    this.events.set(id, Object.freeze(event));
    return event;
  }

  /**
   * Records a metadata correction as an audit trail event rather than silently mutating history.
   */
  public recordMetadataCorrection(params: {
    investigation_id: string;
    target_entity_type: 'ARTIFACT' | 'FINDING' | 'SNAPSHOT' | 'JOB';
    target_entity_id: string;
    actor: string;
    reason: string;
    correction_details: Record<string, any>;
  }): EvidenceEvent {
    return this.recordEvent({
      investigation_id: params.investigation_id,
      event_type: EvidenceEventType.METADATA_CORRECTED,
      actor: params.actor,
      producer: 'provenance-audit-controller',
      producer_version: '1.0.0',
      input_artifacts: params.target_entity_type === 'ARTIFACT' ? [params.target_entity_id] : [],
      output_artifacts: [],
      metadata: {
        target_entity_type: params.target_entity_type,
        target_entity_id: params.target_entity_id,
        reason: params.reason,
        corrections: params.correction_details,
      },
    });
  }

  /**
   * Lists events for an investigation in chronological order.
   */
  public listEvents(investigation_id?: string): EvidenceEvent[] {
    let list = Array.from(this.events.values());
    if (investigation_id) {
      list = list.filter(e => e.investigation_id === investigation_id);
    }
    return list.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }

  /**
   * Gets an event by ID.
   */
  public getEvent(id: string): EvidenceEvent | undefined {
    return this.events.get(id);
  }
}

export const globalEvidenceEventManager = new EvidenceEventManager();
