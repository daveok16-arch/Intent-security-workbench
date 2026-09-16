import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { PersistenceManager, resolvePersistenceConfig } from '../../apps/api/persistence.js';

describe('Durable Persistence', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'persist-test-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const cfgFor = (overrides: Record<string, string> = {}) =>
    resolvePersistenceConfig({ PERSISTENCE_ENABLED: 'true', PERSISTENCE_DIR: dir, ...overrides });

  it('is enabled by default and honours an explicit disable', () => {
    expect(resolvePersistenceConfig({}).enabled).toBe(true);
    expect(resolvePersistenceConfig({ PERSISTENCE_ENABLED: 'false' }).enabled).toBe(false);
    expect(resolvePersistenceConfig({ PERSISTENCE_ENABLED: '0' }).enabled).toBe(false);
    expect(resolvePersistenceConfig({ PERSISTENCE_ENABLED: 'no' }).enabled).toBe(false);
  });

  it('returns null when no snapshot exists', () => {
    const p = new PersistenceManager(cfgFor());
    expect(p.load()).toBeNull();
  });

  it('writes and reloads Maps as plain collections', () => {
    const p = new PersistenceManager(cfgFor());
    const programs = new Map([['prog-1', { id: 'prog-1', name: 'Acme' }]]);
    p.flush(() => ({ programs }));

    const loaded = p.load();
    expect(loaded).not.toBeNull();
    expect(loaded!.programs).toEqual({ 'prog-1': { id: 'prog-1', name: 'Acme' } });
  });

  it('does not write when disabled', () => {
    const p = new PersistenceManager(resolvePersistenceConfig({ PERSISTENCE_ENABLED: 'false', PERSISTENCE_DIR: dir }));
    p.flush(() => ({ programs: new Map([['a', { id: 'a' }]]) }));
    expect(fs.existsSync(p.filePath)).toBe(false);
  });

  it('writes a versioned snapshot with a timestamp', () => {
    const p = new PersistenceManager(cfgFor());
    p.flush(() => ({ findings: new Map() }));
    const onDisk = JSON.parse(fs.readFileSync(p.filePath, 'utf-8'));
    expect(onDisk.version).toBe(1);
    expect(typeof onDisk.saved_at).toBe('string');
    expect(onDisk.collections).toHaveProperty('findings');
  });

  it('survives a corrupt snapshot without throwing', () => {
    const p = new PersistenceManager(cfgFor());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p.filePath, '{ not valid json');
    expect(p.load()).toBeNull();
    expect(p.warnings.join(' ')).toContain('Failed to load snapshot');
  });

  it('ignores a snapshot whose root is not an object', () => {
    const p = new PersistenceManager(cfgFor());
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p.filePath, '[1,2,3]');
    expect(p.load()).toBeNull();
  });

  it('replaces the snapshot atomically and leaves no temp files', () => {
    const p = new PersistenceManager(cfgFor());
    p.flush(() => ({ programs: new Map([['a', { id: 'a' }]]) }));
    p.flush(() => ({ programs: new Map([['a', { id: 'a' }], ['b', { id: 'b' }]]) }));

    expect(Object.keys(p.load()!.programs)).toHaveLength(2);
    const leftovers = fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'));
    expect(leftovers).toEqual([]);
  });

  it('creates the target directory when missing', () => {
    const nested = path.join(dir, 'deep', 'nested');
    const p = new PersistenceManager(resolvePersistenceConfig({ PERSISTENCE_ENABLED: 'true', PERSISTENCE_DIR: nested }));
    p.flush(() => ({ programs: new Map() }));
    expect(fs.existsSync(p.filePath)).toBe(true);
  });

  it('coalesces a burst of scheduled writes', async () => {
    const p = new PersistenceManager(cfgFor({ PERSISTENCE_DEBOUNCE_MS: '30' }));
    const state = { programs: new Map([['a', { id: 'a' }]]) };
    for (let i = 0; i < 25; i++) p.scheduleWrite(() => state);
    await new Promise((r) => setTimeout(r, 150));
    expect(fs.existsSync(p.filePath)).toBe(true);
    p.dispose();
  });

  it('cancels a pending write on dispose', async () => {
    const p = new PersistenceManager(cfgFor({ PERSISTENCE_DEBOUNCE_MS: '80' }));
    p.scheduleWrite(() => ({ programs: new Map() }));
    p.dispose();
    await new Promise((r) => setTimeout(r, 150));
    expect(fs.existsSync(p.filePath)).toBe(false);
  });
});