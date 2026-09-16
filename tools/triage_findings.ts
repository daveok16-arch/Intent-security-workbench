/**
 * Finding Triage
 *
 * Prints each static-analysis finding with the surrounding code and the
 * structural signals that triggered it, so findings can be judged true or false
 * positive without guessing.
 *
 * Usage: npx tsx tools/triage_findings.ts <corpus-dir>
 */

import fs from 'fs';
import path from 'path';
import { StaticAnalysisEngine } from '../engines/placeholders/static_analysis.js';

async function main() {
  const corpusDir = process.argv[2];
  if (!corpusDir || !fs.existsSync(corpusDir)) {
    console.error('Usage: npx tsx tools/triage_findings.ts <corpus-dir>');
    process.exit(1);
  }

  const engine = new StaticAnalysisEngine();
  const result = await engine.execute('tgt-triage', 'scan', {
    investigation_id: 'inv-triage',
    source_snapshot_id: 'snap-triage',
    source_directory: corpusDir,
  });

  console.log(`findings=${result.findings.length} in ${corpusDir}\n`);
  console.log('='.repeat(100));

  const sorted = [...result.findings].sort((a, b) =>
    (a.file + (a.line_start || 0)).localeCompare(b.file + (b.line_start || 0))
  );

  for (const f of sorted) {
    const meta = (f.metadata || {}) as Record<string, any>;
    const rel = f.file.replace(corpusDir + '/', '');
    console.log(`\n${rel}:${f.line_start ?? '?'}  [${f.severity}]`);
    console.log(`  rule: ${meta.rule_id || (f as any).rule_id || f.title}`);
    console.log(`  meta: ${JSON.stringify(meta).slice(0, 300)}`);

    if (fs.existsSync(f.file) && f.line_start) {
      const lines = fs.readFileSync(f.file, 'utf-8').split('\n');
      const start = Math.max(0, f.line_start - 1);
      const end = Math.min(lines.length, (f.line_end || f.line_start) + 1);
      const excerpt = lines.slice(start, end).slice(0, 22);
      console.log('  --- code ---');
      excerpt.forEach((l, i) => console.log(`  ${String(start + i + 1).padStart(4)} | ${l}`));
    }
    console.log('-'.repeat(100));
  }
}

main();