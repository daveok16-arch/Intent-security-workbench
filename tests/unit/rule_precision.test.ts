import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { globalTreeSitterService } from '../../packages/static-analysis/src/treesitter_service.js';

/**
 * Precision regression tests for the structural BOLA / access-control rules.
 *
 * The engine previously flagged any function with a parameter and a
 * `get(`/`delete(` call, which produced 45 HIGH findings across the project's
 * own library code with zero true positives. These tests pin both directions:
 * genuine route-handler BOLA must still be found, and ordinary library code must
 * stay clean.
 */
describe('Structural Rule Precision (BOLA / Access Control)', () => {
  const scan = async (file: string, source: string) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prec-'));
    const p = path.join(dir, file);
    fs.writeFileSync(p, source);
    return globalTreeSitterService.analyzeFileForVulnerabilities(p, 'snap-p', 'inv-p', 'tgt-p');
  };

  describe('1. Must detect genuine BOLA in route handlers', () => {
    it('flags a route reading req.params into a db lookup with no auth check', async () => {
      const c = await scan('a.js', `
const router = require('express').Router();
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  return res.json(doc);
});
`);
      expect(c.length).toBeGreaterThan(0);
      expect(c[0].rule_id).toBe('INTENT-BOLA-001');
      expect(c[0].category).toBe('BOLA');
    });

    it('flags a delete route reading req.params into a destructive query', async () => {
      const c = await scan('b.js', `
const router = require('express').Router();
router.delete('/orders/:id', async (req, res) => {
  await db.orders.deleteOne({ id: req.params.id });
  return res.json({ ok: true });
});
`);
      expect(c.some((x) => x.rule_id === 'INTENT-BOLA-001')).toBe(true);
    });
  });

  describe('2. Must NOT flag ordinary library code', () => {
    it('ignores an in-memory collection with .get()/.add()/.delete()', async () => {
      const c = await scan('lib.ts', `
export class EventBus {
  private listeners = new Set<() => void>();
  public addEventListener(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
`);
      expect(c).toEqual([]);
    });

    it('ignores a pure helper taking a parameter and calling Map.get()', async () => {
      const c = await scan('util.ts', `
export function loadFixture(name: string, registry: Map<string, string>): string {
  const value = registry.get(name);
  if (!value) throw new Error('missing ' + name);
  return value;
}
`);
      expect(c).toEqual([]);
    });

    it('ignores a function whose name merely contains "admin" but only reads', async () => {
      const c = await scan('cfg.ts', `
export function getAdminConfig(admin: { id: string }, config: Map<string, string>): string | undefined {
  return config.get(admin.id);
}
`);
      expect(c).toEqual([]);
    });
  });

  describe('3. Must NOT flag secured route handlers', () => {
    it('ignores a route with an ownership comparison', async () => {
      const c = await scan('secure.js', `
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json(doc);
});
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });

    it('ignores a route that never reads an attacker-controlled id', async () => {
      const c = await scan('static.js', `
router.get('/health', async (req, res) => {
  const status = await db.status.findOne({ name: 'health' });
  return res.json(status);
});
`);
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });
  });

  describe('4. Repository fixtures behave as labelled', () => {
    it('finds BOLA in the vulnerable fixture', async () => {
      const c = await globalTreeSitterService.analyzeFileForVulnerabilities(
        path.resolve('fixtures/static_analysis/bola_vulnerable/api.js'),
        'snap-v', 'inv-v', 'tgt-v'
      );
      expect(c.some((x) => x.rule_id === 'INTENT-BOLA-001')).toBe(true);
    });

    it('finds nothing in the secure fixture', async () => {
      const c = await globalTreeSitterService.analyzeFileForVulnerabilities(
        path.resolve('fixtures/static_analysis/bola_secure/api.js'),
        'snap-s', 'inv-s', 'tgt-s'
      );
      expect(c.filter((x) => x.rule_id === 'INTENT-BOLA-001')).toEqual([]);
    });
  });
});