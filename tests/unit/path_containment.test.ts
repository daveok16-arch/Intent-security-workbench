/**
 * Path containment tests.
 *
 * `candidate.startsWith(root)` is not containment: `/data/sources-evil` starts
 * with `/data/sources`. The old git provider used that check for both the clone
 * destination and `cleanup()`, which recursively deletes the resolved path — so
 * a sibling directory whose name merely began with the sandbox root could be
 * deleted.
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  isPathInside,
  isPathWithinAllowedRoots,
  assertContainedDirectory,
} from '../../packages/config/src/path_containment.js';

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'containment-'));
}

describe('isPathInside', () => {
  it('accepts the root itself', () => {
    expect(isPathInside('/data/sources', '/data/sources')).toBe(true);
  });

  it('accepts nested paths', () => {
    expect(isPathInside('/data/sources', '/data/sources/tgt-1/snap-1')).toBe(true);
  });

  it('rejects a sibling whose name merely shares the prefix', () => {
    expect(isPathInside('/data/sources', '/data/sources-evil')).toBe(false);
    expect(isPathInside('/data/sources', '/data/sources.bak')).toBe(false);
  });

  it('rejects traversal out of the root', () => {
    expect(isPathInside('/data/sources', '/data/sources/../../etc')).toBe(false);
    expect(isPathInside('/data/sources', '/etc/passwd')).toBe(false);
  });
});

describe('assertContainedDirectory', () => {
  it('accepts a real directory inside an allowed root', () => {
    const root = tmpdir();
    const inner = path.join(root, 'inner');
    fs.mkdirSync(inner);
    const result = assertContainedDirectory(inner, [root]);
    expect(result.ok).toBe(true);
    expect(result.resolved).toBe(fs.realpathSync(inner));
  });

  it('rejects a directory outside the allowed root', () => {
    const root = tmpdir();
    const outside = tmpdir();
    const result = assertContainedDirectory(outside, [root]);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/outside the permitted directories/);
  });

  it('rejects a sibling that shares a name prefix with the root', () => {
    const root = tmpdir();
    const sibling = `${root}-evil`;
    fs.mkdirSync(sibling);
    try {
      const result = assertContainedDirectory(sibling, [root]);
      expect(result.ok).toBe(false);
    } finally {
      fs.rmSync(sibling, { recursive: true, force: true });
    }
  });

  it('rejects a file, a missing path, and an empty value', () => {
    const root = tmpdir();
    const file = path.join(root, 'f.txt');
    fs.writeFileSync(file, 'x');
    expect(assertContainedDirectory(file, [root]).ok).toBe(false);
    expect(assertContainedDirectory(path.join(root, 'nope'), [root]).ok).toBe(false);
    expect(assertContainedDirectory('', [root]).ok).toBe(false);
  });

  it('rejects a symlink that points outside the allowed root', () => {
    const root = tmpdir();
    const outside = tmpdir();
    const link = path.join(root, 'link');
    try {
      fs.symlinkSync(outside, link, 'dir');
    } catch {
      return; // symlinks unavailable on this platform/privilege level
    }
    const result = assertContainedDirectory(link, [root]);
    expect(result.ok).toBe(false);
  });
});

describe('isPathWithinAllowedRoots', () => {
  it('permits the system temp directory when allowTmp is set', () => {
    const tmp = process.env.TMPDIR || '/tmp';
    expect(isPathWithinAllowedRoots(path.join(tmp, 'scratch'), ['/nope'], { allowTmp: true })).toBe(true);
    expect(isPathWithinAllowedRoots(path.join(tmp, 'scratch'), ['/nope'])).toBe(false);
  });
});