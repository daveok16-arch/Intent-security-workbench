/**
 * Anti-fabrication regression tests for the finding provenance gate.
 *
 * Background: evidence previously satisfied the VALIDATED/CONFIRMED gate on
 * artifact count alone. `POST /api/evidence` accepts arbitrary caller bytes and
 * hashes them, so a caller could mint "evidence" and walk a finding to
 * CONFIRMED with no engine execution involved. Provenance now distinguishes
 * engine-produced artifacts from caller-supplied payloads.
 */

import { describe, it, expect } from 'vitest';
import { DatabaseStore } from '../../apps/api/db_store.js';
import {
  ArtifactType,
  ArtifactProvenance,
  FindingStatus,
} from '../../packages/core/src/index.js';

const STEPS = [
  FindingStatus.ANALYZING,
  FindingStatus.VERIFICATION_REQUIRED,
  FindingStatus.TESTING,
  FindingStatus.REPRODUCED,
  FindingStatus.VALIDATED,
  FindingStatus.CONFIRMED,
];

function setup() {
  const db = new DatabaseStore();
  const inv = db.createInvestigation({ program_id: 'p1', target_id: 't1', title: 'gate' });
  return { db, inv };
}

function findingWithTrack(db: DatabaseStore, findingId: string) {
  const track: string[] = [];
  for (const s of STEPS) {
    try {
      const updated = db.transitionFinding(findingId, s, 'test');
      track.push(updated.status);
    } catch {
      track.push('BLOCKED');
      break;
    }
  }
  return { finding: db.getFinding(findingId)!, track };
}

describe('Finding provenance gate (anti-fabrication)', () => {
  it('defaults internally-produced evidence to MACHINE_VERIFIABLE and lets it reach CONFIRMED', () => {
    const { db, inv } = setup();
    const art = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      target_id: 't1',
      artifact_type: ArtifactType.EXECUTION_TRACE,
      producer: 'forge',
      producer_version: '1.0.0',
      content: JSON.stringify({ runtime: 'anvil', exit_code: 0 }),
    });
    expect(art.provenance).toBe(ArtifactProvenance.MACHINE_VERIFIABLE);

    const f = db.createFinding({
      investigation_id: inv.id, target_id: 't1', title: 'engine-backed',
      category: 'BOLA', severity: 'HIGH', confidence: 'HIGH',
    });
    db.linkEvidenceToFinding(f.id, art.id);

    const { finding, track } = findingWithTrack(db, f.id);
    expect(track).toEqual(STEPS);
    expect(finding.status).toBe(FindingStatus.CONFIRMED);
  });

  it('blocks CLIENT_SUPPLIED evidence from reaching VALIDATED or CONFIRMED', () => {
    const { db, inv } = setup();
    const art = db.storeEvidenceArtifact({
      investigation_id: inv.id,
      target_id: 't1',
      artifact_type: ArtifactType.EXECUTION_TRACE,
      producer: 'caller',
      content: 'made up proof',
      provenance: ArtifactProvenance.CLIENT_SUPPLIED,
    });
    expect(art.provenance).toBe(ArtifactProvenance.CLIENT_SUPPLIED);

    const f = db.createFinding({
      investigation_id: inv.id, target_id: 't1', title: 'caller-backed',
      category: 'BOLA', severity: 'CRITICAL', confidence: 'HIGH',
    });
    db.linkEvidenceToFinding(f.id, art.id);

    const { finding, track } = findingWithTrack(db, f.id);
    expect(track).not.toContain(FindingStatus.CONFIRMED);
    expect(track).not.toContain(FindingStatus.VALIDATED);
    expect(finding.status).toBe(FindingStatus.REPRODUCED);
  });

  it('blocks the terminal transition when a finding mixes only caller-supplied artifacts', () => {
    const { db, inv } = setup();
    const a1 = db.storeEvidenceArtifact({
      investigation_id: inv.id, artifact_type: ArtifactType.EXECUTION_TRACE,
      producer: 'caller', content: 'x', provenance: ArtifactProvenance.CLIENT_SUPPLIED,
    });
    const a2 = db.storeEvidenceArtifact({
      investigation_id: inv.id, artifact_type: ArtifactType.ENGINE_STDOUT,
      producer: 'caller', content: 'y', provenance: ArtifactProvenance.CLIENT_SUPPLIED,
    });

    const f = db.createFinding({
      investigation_id: inv.id, target_id: 't1', title: 'two caller artifacts',
      category: 'BOLA', severity: 'HIGH', confidence: 'HIGH',
    });
    db.linkEvidenceToFinding(f.id, a1.id);
    db.linkEvidenceToFinding(f.id, a2.id);

    for (const s of [FindingStatus.ANALYZING, FindingStatus.VERIFICATION_REQUIRED, FindingStatus.TESTING, FindingStatus.REPRODUCED]) {
      db.transitionFinding(f.id, s, 'test');
    }
    expect(() => db.transitionFinding(f.id, FindingStatus.VALIDATED, 'test')).toThrow(/CLIENT_SUPPLIED/);
  });

  it('still requires evidence at all for the terminal states', () => {
    const { db, inv } = setup();
    const f = db.createFinding({
      investigation_id: inv.id, target_id: 't1', title: 'no evidence',
      category: 'BOLA', severity: 'HIGH', confidence: 'HIGH',
    });
    for (const s of [FindingStatus.ANALYZING, FindingStatus.VERIFICATION_REQUIRED, FindingStatus.TESTING, FindingStatus.REPRODUCED]) {
      db.transitionFinding(f.id, s, 'test');
    }
    expect(() => db.transitionFinding(f.id, FindingStatus.VALIDATED, 'test'))
      .toThrow(/without linked machine-verifiable evidence artifacts/);
  });
});