/**
 * Precision Benchmark for the Tree-sitter structural engine.
 *
 * Measures false positives on explicitly SAFE code and true positives on
 * explicitly VULNERABLE code. Run with: npx tsx tools/benchmark_precision.ts
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { globalTreeSitterService } from '../packages/static-analysis/src/treesitter_service.js';

interface Case {
  name: string;
  file: string;
  source: string;
  expect: 'VULNERABLE' | 'SAFE';
}

const CASES: Case[] = [
  {
    name: 'express route param -> db lookup, no auth (true BOLA)',
    file: 'v1.js',
    expect: 'VULNERABLE',
    source: `
const express = require('express');
const router = express.Router();
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  return res.json(doc);
});
`,
  },
  {
    name: 'express delete route param -> deleteOne, no auth (true BOLA)',
    file: 'v2.js',
    expect: 'VULNERABLE',
    source: `
const router = require('express').Router();
router.delete('/orders/:id', async (req, res) => {
  await db.orders.deleteOne({ id: req.params.id });
  return res.json({ ok: true });
});
`,
  },
  {
    name: 'route param -> inline db lookup via req.params (true BOLA)',
    file: 'v3.js',
    expect: 'VULNERABLE',
    source: `
app.get('/invoices/:id', async (req, res) => {
  const inv = await db.invoices.findUnique({ where: { id: req.params.id } });
  res.json(inv);
});
`,
  },
  {
    name: 'EventBus addEventListener (was a false positive)',
    file: 's1.ts',
    expect: 'SAFE',
    source: `
export class EventBus {
  private listeners = new Set<() => void>();
  public addEventListener(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
`,
  },
  {
    name: 'policy gate static method (was a false positive)',
    file: 's2.ts',
    expect: 'SAFE',
    source: `
export class PolicyGate {
  public static evaluateAction(request: { target: string }): { allowed: boolean } {
    const checks = { target_registered: true, scope_permitted: true };
    return { allowed: checks.target_registered && checks.scope_permitted };
  }
}
`,
  },
  {
    name: 'test helper with arbitrary params and .get() (was a false positive)',
    file: 's3.ts',
    expect: 'SAFE',
    source: `
export function loadFixture(name: string, registry: Map<string, string>): string {
  const value = registry.get(name);
  if (!value) throw new Error('missing fixture ' + name);
  return value;
}
`,
  },
  {
    name: 'secure route with ownership check (must stay clean)',
    file: 's4.js',
    expect: 'SAFE',
    source: `
router.get('/documents/:id', async (req, res) => {
  const doc = await db.documents.findOne({ _id: req.params.id });
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'forbidden' });
  }
  return res.json(doc);
});
`,
  },
  {
    name: 'route handler with no attacker-controlled id (safe)',
    file: 's5.js',
    expect: 'SAFE',
    source: `
router.get('/health', async (req, res) => {
  const status = await db.status.findOne({ name: 'health' });
  return res.json(status);
});
`,
  },
  {
    name: 'admin helper that only reads (was a false positive)',
    file: 's6.ts',
    expect: 'SAFE',
    source: `
export function getAdminConfig(admin: { id: string }, config: Map<string, string>): string | undefined {
  return config.get(admin.id);
}
`,
  },
];

async function scanSource(c: Case) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-'));
  const p = path.join(dir, c.file);
  fs.writeFileSync(p, c.source);
  return globalTreeSitterService.analyzeFileForVulnerabilities(p, 'snap-bench', 'inv-bench', 'tgt-bench');
}

async function main() {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const rows: string[] = [];

  for (const c of CASES) {
    const candidates = await scanSource(c);
    const flagged = candidates.length > 0;
    const isVuln = c.expect === 'VULNERABLE';

    let verdict: string;
    if (isVuln && flagged) { tp++; verdict = 'TP'; }
    else if (isVuln && !flagged) { fn++; verdict = 'FN  <-- missed'; }
    else if (!isVuln && flagged) { fp++; verdict = `FP  <-- noise (${candidates.map((x) => x.rule_id).join(',')})`; }
    else { tn++; verdict = 'TN'; }

    rows.push(`  ${verdict.padEnd(34)} ${c.expect.padEnd(10)} ${c.name}`);
  }

  console.log(rows.join('\n'));
  console.log();
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  console.log(`  TP=${tp}  FP=${fp}  TN=${tn}  FN=${fn}`);
  console.log(`  precision = ${(precision * 100).toFixed(1)}%`);
  console.log(`  recall    = ${(recall * 100).toFixed(1)}%`);

  const ok = fp === 0 && fn === 0;
  console.log(ok ? '\n  PASS: no false positives and no misses.' : '\n  FAIL: benchmark thresholds not met.');
  process.exit(ok ? 0 : 1);
}

main();