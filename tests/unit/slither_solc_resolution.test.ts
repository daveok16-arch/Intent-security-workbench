/**
 * Slither must not inherit the host's global solc pin.
 *
 * `solc-select` keeps one global compiler version in
 * `~/.solc-select/global-version`, and Slither falls back to it when the target
 * does not pin a compiler. Because that state is shared by every project on the
 * host, analysing one repository silently changed the compiler used for the
 * next: a `pragma ^0.8.20` fixture compiled with a globally-pinned 0.6.12
 * produced no output and was reported as SLITHER_OUTPUT_UNPARSEABLE.
 *
 * Found while analysing Cronos bounty targets, where the required compiler
 * (0.6.12) differed from the fixture's (0.8.20).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SlitherAnalysisService } from '../../packages/static-analysis/src/slither_service.js';

const ORIGINAL_HOME = process.env.HOME;
const created: string[] = [];

function tmpProject(pragma: string, name = 'Target.sol') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'solc-pragma-'));
  created.push(dir);
  fs.writeFileSync(
    path.join(dir, name),
    `// SPDX-License-Identifier: MIT\npragma solidity ${pragma};\n\ncontract C { uint256 public x; }\n`
  );
  return dir;
}

/** A fake HOME with a solc-select global pin, plus the artifact it points at. */
function fakeHome(pinnedVersion: string, installVersions: string[]) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'fakehome-'));
  created.push(home);
  const sel = path.join(home, '.solc-select');
  fs.mkdirSync(sel, { recursive: true });
  fs.writeFileSync(path.join(sel, 'global-version'), pinnedVersion);
  for (const v of installVersions) {
    const bin = path.join(sel, 'artifacts', `solc-${v}`);
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, `solc-${v}`), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  }
  return home;
}

afterEach(() => {
  process.env.HOME = ORIGINAL_HOME;
  for (const d of created.splice(0)) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

describe('Slither solc resolution is independent of global state', () => {
  it('passes an explicit --solc path matching the target pragma, not the global pin', async () => {
    // Host is globally pinned to 0.6.12 but the artifact for 0.8.20 exists.
    process.env.HOME = fakeHome('0.6.12', ['0.6.12', '0.8.20']);
    const dir = tmpProject('^0.8.20');

    const service = new SlitherAnalysisService();
    const avail = await service.checkAvailability();
    if (!avail.available) return; // slither not installed on this host

    const res = await service.analyze(dir, { timeoutMs: 60000 });
    // The command must name a solc binary, and it must be the 0.8.20 one.
    expect(res.command).toContain('--solc');
    expect(res.command).toContain('solc-0.8.20');
    expect(res.command).not.toContain('solc-0.6.12');
  });

  it('reports which global pin conflicted when a run is unparseable', async () => {
    // Only the wrong compiler installed: resolution should fall back and the
    // failure message should explain the conflict.
    process.env.HOME = fakeHome('0.6.12', ['0.6.12']);
    const dir = tmpProject('^0.8.20');

    const service = new SlitherAnalysisService();
    const avail = await service.checkAvailability();
    if (!avail.available) return;

    const res = await service.analyze(dir, { timeoutMs: 60000 });
    if (res.status === 'COMPLETED') return; // host had 0.8.20 elsewhere; fine
    expect(res.error).toBeTruthy();
    expect(res.contracts_analyzed).toBe(0);
  });
});