import { describe, it, expect } from 'vitest';
import { EvidenceEventManager } from '../../packages/evidence/src/events.js';
import { EvidenceEventType } from '../../packages/core/src/index.js';

describe('Phase 0.2 — EvidenceEventManager (Append-Only Event System)', () => {
  it('should record immutable events and freeze them', () => {
    const manager = new EvidenceEventManager();

    const ev = manager.recordEvent({
      investigation_id: 'inv-event-test',
      event_type: EvidenceEventType.ENGINE_STARTED,
      actor: 'orchestrator',
      producer: 'slither',
      producer_version: '0.10.0',
      metadata: { job_id: 'job-1' },
    });

    expect(ev.id).toBeDefined();
    expect(ev.event_type).toBe(EvidenceEventType.ENGINE_STARTED);
    expect(Object.isFrozen(ev)).toBe(true);

    // Verifying immutability
    expect(() => {
      (ev as any).actor = 'tampered';
    }).toThrow();
  });

  it('should list events filtered by investigation in chronological order', () => {
    const manager = new EvidenceEventManager();

    manager.recordEvent({
      investigation_id: 'inv-A',
      event_type: EvidenceEventType.SOURCE_ACQUIRED,
      actor: 'user',
      producer: 'git',
      producer_version: '2.40.0',
    });

    manager.recordEvent({
      investigation_id: 'inv-B',
      event_type: EvidenceEventType.SOURCE_ACQUIRED,
      actor: 'user',
      producer: 'git',
      producer_version: '2.40.0',
    });

    manager.recordEvent({
      investigation_id: 'inv-A',
      event_type: EvidenceEventType.ENGINE_COMPLETED,
      actor: 'orchestrator',
      producer: 'slither',
      producer_version: '0.10.0',
    });

    const eventsA = manager.listEvents('inv-A');
    expect(eventsA.length).toBe(2);
    expect(eventsA[0].event_type).toBe(EvidenceEventType.SOURCE_ACQUIRED);
    expect(eventsA[1].event_type).toBe(EvidenceEventType.ENGINE_COMPLETED);

    const eventsB = manager.listEvents('inv-B');
    expect(eventsB.length).toBe(1);
  });
});
