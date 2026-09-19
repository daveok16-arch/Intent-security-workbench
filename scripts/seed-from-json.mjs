#!/usr/bin/env node
/**
 * Register a bounty program, its validated scope, and its targets through the
 * running workbench REST API.
 *
 * This is the supported way to get a program's scope into the scope gate: it
 * goes through the same handlers the UI uses, so scope evaluation, the
 * authorization/scope-status transition, and the SCOPE_EVALUATED evidence
 * events all fire exactly as they do interactively. Registering records by
 * writing the snapshot file directly would bypass that provenance.
 *
 * The program definition is supplied as a JSON file so that target-specific
 * data stays out of this repository (see README: never commit scope data for a
 * program whose policy forbids disclosure).
 *
 * Usage:
 *   node scripts/seed-from-json.mjs <definition.json> [--base-url URL] [--dry-run]
 *
 * Definition shape:
 * {
 *   "program": { "name", "platform", "program_url", "organization",
 *                "description", "status", "freshness_status",
 *                "bounty_policy", "testing_rules": [], "exclusions": [] },
 *   "scope":   [ { "asset_identifier", "asset_type", "inclusion_status",
 *                  "notes" } ],
 *   "targets": [ { "name", "target_type", "ecosystem", "identifier" } ],
 *   "investigation": { "title", "description" }
 * }
 *
 * Exit codes: 0 success, 1 definition/HTTP error, 2 usage error.
 */

const args = process.argv.slice(2);
const definitionPath = args.find((a) => !a.startsWith('--'));
const baseUrlFlag = args.indexOf('--base-url');
const baseUrl = baseUrlFlag !== -1 ? args[baseUrlFlag + 1] : 'http://127.0.0.1:12000';
const dryRun = args.includes('--dry-run');

if (!definitionPath) {
  console.error('Usage: node scripts/seed-from-json.mjs <definition.json> [--base-url URL] [--dry-run]');
  process.exit(2);
}

const fs = await import('fs');
if (!fs.existsSync(definitionPath)) {
  console.error(`Definition file not found: ${definitionPath}`);
  process.exit(2);
}

let def;
try {
  def = JSON.parse(fs.readFileSync(definitionPath, 'utf-8'));
} catch (err) {
  console.error(`Definition is not valid JSON: ${err.message}`);
  process.exit(2);
}
if (!def.program?.name) {
  console.error('Definition must include program.name');
  process.exit(2);
}

async function api(method, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status} ${typeof parsed === 'string' ? parsed : JSON.stringify(parsed)}`);
  }
  return parsed;
}

const created = { program: null, scope: [], targets: [], investigation: null };

// --- Program -----------------------------------------------------------------
created.program = await api('POST', '/api/programs', def.program);
console.log(`program        ${created.program.id}  ${created.program.name}`);
if (dryRun) {
  console.log('dry run: stopping before scope import');
  process.exit(0);
}

// --- Scope -------------------------------------------------------------------
if (Array.isArray(def.scope) && def.scope.length > 0) {
  const result = await api('POST', `/api/programs/${created.program.id}/scope/import`, {
    scope: def.scope,
    replace_existing: false,
  });
  created.scope = result.scope_entries || [];
  console.log(`scope entries  ${created.scope.length} imported`);
}

// --- Targets -----------------------------------------------------------------
for (const t of def.targets || []) {
  const target = await api('POST', '/api/targets', { ...t, program_id: created.program.id });
  created.targets.push(target);
  console.log(
    `target         ${target.id}  ${target.name}  ` +
      `scope=${target.scope_status} auth=${target.authorization_status}`
  );
}

// --- Investigation -----------------------------------------------------------
if (def.investigation && created.targets.length > 0) {
  const inv = await api('POST', '/api/investigations', {
    program_id: created.program.id,
    target_id: created.targets[0].id,
    title: def.investigation.title || `${def.program.name} research`,
    description: def.investigation.description || '',
  });
  created.investigation = inv;
  console.log(`investigation  ${inv.id}  ${inv.title}`);

  const gate = await api('GET', `/api/investigations/${inv.id}/gate?require_source=false`);
  console.log(`gate           passed=${gate.passed} reason=${gate.reason}`);
  for (const c of gate.checks || []) {
    console.log(`                 ${c.passed ? 'PASS' : 'FAIL'}  ${c.name}: ${c.message}`);
  }
}

console.log('\nsummarising scope decisions:');
for (const t of created.targets) {
  const full = await api('GET', `/api/targets/${t.id}`);
  console.log(`  ${full.name.padEnd(34)} ${full.scope_status}`);
}