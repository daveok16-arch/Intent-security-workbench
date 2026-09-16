/**
 * Durable Persistence for the Workbench Database
 *
 * The workbench holds all domain state in in-memory Maps, so every program,
 * investigation, finding and evidence record was lost on process restart. This
 * module adds a write-through JSON snapshot with atomic file replacement so
 * research survives a restart, without introducing a database dependency.
 *
 * Design notes:
 * - Snapshots are written to a single JSON file via a temp file + rename, so a
 *   crash mid-write cannot corrupt the previous good snapshot.
 * - Writes are debounced and coalesced; a burst of mutations produces one write.
 * - Binary artifact content is NOT stored here (it lives in the artifact
 *   storage layer); only domain records are persisted.
 * - Persistence is opt-in via PERSISTENCE_ENABLED and never throws into the
 *   request path: a failed write is logged and retried on the next mutation.
 */

import fs from 'fs';
import path from 'path';

export interface PersistenceConfig {
  enabled: boolean;
  /** Directory that holds the snapshot file. */
  dir: string;
  /** Debounce window for coalescing writes, in milliseconds. */
  debounceMs: number;
}

export const DEFAULT_PERSISTENCE_DIR = path.resolve(process.cwd(), 'storage', 'db');

export function resolvePersistenceConfig(
  env: Record<string, string | undefined> = process.env
): PersistenceConfig {
  const raw = (env.PERSISTENCE_ENABLED ?? 'true').toLowerCase();
  const enabled = !['0', 'false', 'no', 'off'].includes(raw);
  const dir = env.PERSISTENCE_DIR || DEFAULT_PERSISTENCE_DIR;
  const debounceMs = Number.parseInt(env.PERSISTENCE_DEBOUNCE_MS || '150', 10);
  return { enabled, dir, debounceMs: Number.isFinite(debounceMs) ? debounceMs : 150 };
}

/**
 * A Map that notifies a listener on mutation.
 *
 * Domain state lives in Maps mutated directly (`programs.set(...)`), and there
 * are many such sites. Instrumenting each call site would be easy to miss, so
 * the collections themselves report writes instead.
 */
export class TrackedMap<K, V> extends Map<K, V> {
  constructor(private readonly onMutate: () => void, entries?: Iterable<[K, V]>) {
    super(entries);
  }

  set(key: K, value: V): this {
    super.set(key, value);
    this.onMutate();
    return this;
  }

  delete(key: K): boolean {
    const removed = super.delete(key);
    if (removed) this.onMutate();
    return removed;
  }

  clear(): void {
    const had = this.size > 0;
    super.clear();
    if (had) this.onMutate();
  }
}

/** Serialises Maps into plain objects for JSON transport. */
function encodeMaps(state: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(state)) {
    out[key] = value instanceof Map ? Object.fromEntries(value.entries()) : value;
  }
  return out;
}

export class PersistenceManager {
  private readonly config: PersistenceConfig;
  private timer: NodeJS.Timeout | null = null;
  private writing = false;
  private pending = false;
  private lastError: string | null = null;
  private loadWarnings: string[] = [];

  constructor(config: PersistenceConfig) {
    this.config = config;
  }

  get filePath(): string {
    return path.join(this.config.dir, 'workbench-state.json');
  }

  get enabled(): boolean {
    return this.config.enabled;
  }

  get errors(): string | null {
    return this.lastError;
  }

  get warnings(): string[] {
    return this.loadWarnings;
  }

  /**
   * Loads a snapshot if present. Returns null when persistence is disabled or no
   * snapshot exists. Never throws: a corrupt snapshot is reported and ignored so
   * the server still starts.
   */
  load(): Record<string, Record<string, unknown>> | null {
    if (!this.config.enabled) return null;
    try {
      if (!fs.existsSync(this.filePath)) return null;
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') {
        this.loadWarnings.push('Snapshot root is not an object; ignoring snapshot.');
        return null;
      }
      return parsed.collections || null;
    } catch (err: any) {
      this.loadWarnings.push(`Failed to load snapshot: ${err.message}`);
      return null;
    }
  }

  /** Schedules a debounced, coalesced snapshot write. */
  scheduleWrite(getState: () => Record<string, unknown>): void {
    if (!this.config.enabled) return;
    this.pending = true;
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush(getState);
    }, this.config.debounceMs);
    // Do not keep the event loop alive solely for a pending snapshot.
    if (typeof this.timer.unref === 'function') this.timer.unref();
  }

  /** Writes a snapshot immediately. Safe to call at shutdown. */
  flush(getState: () => Record<string, unknown>): void {
    if (!this.config.enabled) return;
    if (this.writing) {
      this.pending = true;
      return;
    }
    this.writing = true;
    try {
      fs.mkdirSync(this.config.dir, { recursive: true });
      const payload = {
        version: 1,
        saved_at: new Date().toISOString(),
        collections: encodeMaps(getState()),
      };
      const tmp = `${this.filePath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(payload), 'utf-8');
      // Atomic replace so a crash cannot leave a half-written snapshot.
      fs.renameSync(tmp, this.filePath);
      this.lastError = null;
      this.pending = false;
    } catch (err: any) {
      this.lastError = err.message;
      console.error('[PERSISTENCE] Snapshot write failed:', err.message);
    } finally {
      this.writing = false;
    }
  }

  /** Cancels any pending debounced write. */
  dispose(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
