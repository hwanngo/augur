import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { loadSavedFilters, saveSavedFilter, deleteSavedFilter } from '../savedFilters';

interface DemoFilter { severity: string; zone: string }

beforeEach(() => {
  localStorage.clear();
});
afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('savedFilters store', () => {
  it('save → load round-trips per scope + user', () => {
    saveSavedFilter<DemoFilter>('dashboard', 'alice', 'crit-corp', { severity: 'CRITICAL', zone: 'corp' });
    const list = loadSavedFilters<DemoFilter>('dashboard', 'alice');
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('crit-corp');
    expect(list[0].value).toEqual({ severity: 'CRITICAL', zone: 'corp' });
    expect(typeof list[0].id).toBe('string');
    expect(list[0].id.length).toBeGreaterThan(0);
    expect(typeof list[0].createdAt).toBe('string');
  });

  it('upserts by name (same name overwrites the value, keeps one entry)', () => {
    saveSavedFilter<DemoFilter>('dashboard', 'alice', 'view', { severity: 'CRITICAL', zone: 'corp' });
    const after = saveSavedFilter<DemoFilter>('dashboard', 'alice', 'view', { severity: 'LOW', zone: 'dmz' });
    expect(after).toHaveLength(1);
    expect(after[0].name).toBe('view');
    expect(after[0].value).toEqual({ severity: 'LOW', zone: 'dmz' });
    expect(loadSavedFilters<DemoFilter>('dashboard', 'alice')).toHaveLength(1);
  });

  it('deletes by id', () => {
    saveSavedFilter<DemoFilter>('alerts', 'alice', 'a', { severity: 'CRITICAL', zone: '' });
    const list = saveSavedFilter<DemoFilter>('alerts', 'alice', 'b', { severity: 'LOW', zone: '' });
    const targetId = list.find((f) => f.name === 'a')!.id;
    const remaining = deleteSavedFilter<DemoFilter>('alerts', 'alice', targetId);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].name).toBe('b');
    expect(loadSavedFilters<DemoFilter>('alerts', 'alice')).toHaveLength(1);
  });

  it("user A's filters are invisible under user B's key", () => {
    saveSavedFilter<DemoFilter>('dashboard', 'alice', 'a-view', { severity: 'CRITICAL', zone: 'corp' });
    expect(loadSavedFilters<DemoFilter>('dashboard', 'bob')).toEqual([]);
    expect(loadSavedFilters<DemoFilter>('dashboard', 'alice')).toHaveLength(1);
  });

  it('null user falls back to the _anon namespace', () => {
    saveSavedFilter<DemoFilter>('dashboard', null, 'anon-view', { severity: 'HIGH', zone: '' });
    expect(loadSavedFilters<DemoFilter>('dashboard', null)).toHaveLength(1);
    expect(loadSavedFilters<DemoFilter>('dashboard', 'alice')).toEqual([]);
  });

  it('swallows a throwing localStorage.setItem and returns the in-memory list', () => {
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceeded');
    });
    // Must not throw; returns the would-be-persisted list.
    const list = saveSavedFilter<DemoFilter>('dashboard', 'alice', 'x', { severity: 'CRITICAL', zone: 'corp' });
    expect(spy).toHaveBeenCalled();
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('x');
  });

  it('returns [] when localStorage.getItem throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('private mode');
    });
    expect(loadSavedFilters<DemoFilter>('dashboard', 'alice')).toEqual([]);
  });
});
