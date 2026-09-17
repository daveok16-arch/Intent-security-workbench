/**
 * Filesystem Path Containment
 * Intent Security Workbench
 *
 * A prefix comparison (`candidate.startsWith(root)`) is not a containment
 * check: `/data/sources-evil` starts with `/data/sources`, so a sibling
 * directory whose name merely begins with the root would pass. These helpers
 * compare path segments after resolution instead.
 */

import fs from 'fs';
import path from 'path';

/**
 * True when `candidate` is `root` itself or lies inside it.
 * Both paths are resolved first, so `..` segments cannot escape.
 */
export function isPathInside(root: string, candidate: string): boolean {
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);

  if (resolvedCandidate === resolvedRoot) return true;

  const withSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : resolvedRoot + path.sep;
  // Case-insensitive comparison on platforms with case-insensitive filesystems.
  return process.platform === 'win32' || process.platform === 'darwin'
    ? resolvedCandidate.toLowerCase().startsWith(withSep.toLowerCase())
    : resolvedCandidate.startsWith(withSep);
}

/**
 * Resolves `candidate` and confirms it lies within at least one allowed root.
 * `allowTmp` additionally permits locations under the system temp directory,
 * which is needed for sandbox scratch space.
 */
export function isPathWithinAllowedRoots(
  candidate: string,
  roots: string[],
  options: { allowTmp?: boolean } = {}
): boolean {
  if (!candidate) return false;
  for (const root of roots) {
    if (root && isPathInside(root, candidate)) return true;
  }
  if (options.allowTmp) {
    const tmp = process.env.TMPDIR || '/tmp';
    if (isPathInside(tmp, candidate)) return true;
  }
  return false;
}

/**
 * Confirms a path exists, is a directory, and is contained by an allowed root.
 * `realpathSync` is used when the path exists so that a symlink pointing outside
 * the allowed root is rejected rather than followed.
 */
export function assertContainedDirectory(
  candidate: string,
  roots: string[],
  options: { allowTmp?: boolean } = {}
): { ok: boolean; resolved?: string; error?: string } {
  if (!candidate || typeof candidate !== 'string') {
    return { ok: false, error: 'A directory path is required.' };
  }

  let resolved = path.resolve(candidate);
  try {
    if (fs.existsSync(resolved)) {
      // Resolve symlinks so a link inside the root pointing outside is caught.
      resolved = fs.realpathSync(resolved);
    }
  } catch {
    return { ok: false, error: `Unable to resolve path: ${candidate}` };
  }

  if (!isPathWithinAllowedRoots(resolved, roots, options)) {
    return {
      ok: false,
      error: `Path '${resolved}' is outside the permitted directories.`,
    };
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    return { ok: false, error: `Path does not exist: ${resolved}` };
  }
  if (!stat.isDirectory()) {
    return { ok: false, error: `Path is not a directory: ${resolved}` };
  }

  return { ok: true, resolved };
}