/**
 * Real-World Corpus Benchmark
 *
 * Runs the static-analysis engines against cloned third-party applications with
 * documented vulnerabilities, to measure whether detection generalises beyond
 * the repository's own fixtures.
 *
 * Usage: npx tsx tools/benchmark_corpus.ts <corpus-dir> [--semgrep]
 */

import fs from 'fs';
import path from 'path';
import { StaticAnalysisEngine } from '../engines/placeholders/static_analysis.js';

async function main() {
  const corpusDir = process.argv[2];
  if (!corpusDir || !fs.existsSync(corpusDir)) {
    console.error('Usage: npx tsx tools/benchmark_corpus.ts <corpus-dir> [--semgrep]');
    process.exit(1);
  }

  const engine = new StaticAnalysisEngine();
  const t0 = Date.now();
  const result = await engine.execute('tgt-corpus', 'scan', {
    investigation_id: 'inv-corpus',
    source_snapshot_id: 'snap-corpus',
    source_directory: corpusDir,
  });
  const secs = ((Date.now() - t0) / 1000).toFixed(1);

  console.log(`dir=${corpusDir}`);
  console.log(`status=${result.status} exit=${result.exit_code} elapsed=${secs}s`);
  console.log(`findings=${result.findings.length}`);
  console.log();

  const byRule = new Map<string, number>();
  const bySeverity = new Map<string, number>();
  const byEngine = new Map<string, number>();
  for (const f of result.findings) {
    const meta = (f.metadata || {}) as Record<string, any>;
    const rid = meta.rule_id || (f as any).rule_id || f.title;
    const eng = meta.engine || (f as any).engine || 'unknown';
    byRule.set(rid, (byRule.get(rid) || 0) + 1);
    bySeverity.set(f.severity, (bySeverity.get(f.severity) || 0) + 1);
    byEngine.set(eng, (byEngine.get(eng) || 0) + 1);
  }

  console.log('by severity:', Object.fromEntries(bySeverity));
  console.log('by engine  :', Object.fromEntries(byEngine));
  console.log('by rule    :', Object.fromEntries(byRule));
  console.log();

  console.log('findings by file (top 25):');
  const byFile = new Map<string, number>();
  for (const f of result.findings) {
    const rel = f.file.replace(corpusDir + '/', '');
    byFile.set(rel, (byFile.get(rel) || 0) + 1);
  }
  [...byFile.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 25)
    .forEach(([f, n]) => console.log(`  ${String(n).padStart(3)}  ${f}`));
}

main();