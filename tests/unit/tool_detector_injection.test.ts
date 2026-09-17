/**
 * Regression tests for command injection via tool-detector version probing.
 *
 * The detectors previously built a shell string:
 *     execSync(`"${foundPath}" --version`)
 * `foundPath` is resolved from PATH and from project-local tool directories
 * (./usr/local/bin, ./node_modules/.bin). A directory name containing a double
 * quote therefore broke out of the quotes and executed arbitrary commands.
 *
 * The detectors now pass the path as an argv element to execFileSync, so no
 * shell is involved and the path cannot be interpreted.
 */

import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ToolDetector } from '../../packages/dynamic-verification/src/tool_detectors.js';
import { Z3Detector } from '../../packages/formal-verification/src/z3_detector.js';

const created: string[] = [];
const originalPath = process.env.PATH;
const originalCwd = process.cwd();

function makeHostileDir(suffix: string) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'intent-inj-'));
  created.push(root);
  return root;
}

afterEach(() => {
  process.env.PATH = originalPath;
  try {
    process.chdir(originalCwd);
  } catch {
    /* ignore */
  }
  for (const d of created.splice(0)) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

describe('Tool detector command-injection resistance', () => {
  it('does not execute a command embedded in a PATH directory name (forge)', () => {
    const root = makeHostileDir('forge');
    // Directory name carries a quote and a separator; the payload creates PWNED.
    const hostileDir = path.join(root, 'pwn";touch PWNED;"x');
    fs.mkdirSync(hostileDir);
    fs.writeFileSync(path.join(hostileDir, 'forge'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });

    process.env.PATH = `${hostileDir}:${originalPath}`;
    process.chdir(root);

    expect(() => ToolDetector.detectForge()).not.toThrow();
    expect(fs.existsSync(path.join(root, 'PWNED'))).toBe(false);
  });

  it('does not execute a command embedded in an explicit z3 path', () => {
    const root = makeHostileDir('z3');
    const hostileDir = path.join(root, 'pwn";touch Z3PWNED;"x');
    fs.mkdirSync(hostileDir);
    const fakeZ3 = path.join(hostileDir, 'z3');
    fs.writeFileSync(fakeZ3, '#!/bin/sh\necho "Z3 version 4.13.0"\n', { mode: 0o755 });

    process.chdir(root);

    const result = Z3Detector.detect(fakeZ3);
    // The path may or may not be considered usable, but nothing may execute.
    expect(fs.existsSync(path.join(root, 'Z3PWNED'))).toBe(false);
    if (result.installed) {
      expect(result.version).toContain('4.13');
    }
  });

  it('still resolves and versions a legitimate binary (no functional regression)', () => {
    const root = makeHostileDir('legit');
    const bindir = path.join(root, 'bin');
    fs.mkdirSync(bindir);
    fs.writeFileSync(path.join(bindir, 'forge'), '#!/bin/sh\necho "forge 1.2.3"\n', { mode: 0o755 });

    process.env.PATH = `${bindir}:${originalPath}`;

    const res = ToolDetector.detectForge();
    expect(res.installed).toBe(true);
    expect(res.executable_path).toBe(path.join(bindir, 'forge'));
    expect(res.version).toBe('1.2.3');
  });
});