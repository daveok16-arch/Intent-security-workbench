/**
 * Executable Resolution
 * Intent Security Workbench
 *
 * Locates analysis binaries without relying on the caller's PATH alone.
 * A tool that is genuinely installed in a standard user or project directory
 * must never be reported as NOT_INSTALLED just because PATH was not exported.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

/** Directories searched in addition to PATH, in priority order. */
function candidateDirs(extraDirs: string[] = []): string[] {
  const home = os.homedir();
  return [
    ...extraDirs,
    path.join(home, '.foundry', 'bin'),
    path.join(home, '.local', 'bin'),
    path.join(home, '.cargo', 'bin'),
    path.join(home, '.bun', 'bin'),
    '/usr/local/bin',
    '/opt/bin',
    '/usr/bin',
    '/bin',
    // Project-local toolchain shipped with the workbench.
    path.resolve(process.cwd(), 'usr', 'local', 'bin'),
    path.resolve(process.cwd(), 'node_modules', '.bin'),
  ];
}

function isExecutableFile(p: string): boolean {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return false;
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves an executable name or explicit path to an absolute path.
 * Returns null when the binary genuinely does not exist.
 */
export function resolveExecutable(nameOrPath: string, extraDirs: string[] = []): string | null {
  if (!nameOrPath) return null;

  // Explicit path (absolute or containing a separator) is used verbatim.
  if (nameOrPath.includes('/') || nameOrPath.includes('\\')) {
    const abs = path.resolve(nameOrPath);
    return isExecutableFile(abs) ? abs : null;
  }

  const fromPath = (process.env.PATH || '')
    .split(path.delimiter)
    .filter(Boolean)
    .map((dir) => path.join(dir, nameOrPath))
    .find(isExecutableFile);
  if (fromPath) return fromPath;

  const found = candidateDirs(extraDirs)
    .map((dir) => path.join(dir, nameOrPath))
    .find(isExecutableFile);
  return found || null;
}