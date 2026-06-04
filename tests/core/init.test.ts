import { describe, it, expect, vi } from 'vitest';
import { initAuthz } from '../../src/core/init.js';
import type { AuthzAdapter } from '../../src/types/adapter.js';
import type { ParsedPermissions } from '../../src/types/rbac.js';
import type { PolicyRecord } from '../../src/types/abac.js';

const mockDb: AuthzAdapter = {
  getUserPermissions: vi.fn().mockResolvedValue(new Set<string>()),
  getPoliciesForContext: vi.fn().mockResolvedValue([]),
  getUserRoleNames: vi.fn().mockResolvedValue([]),
};

const samplePerms: ParsedPermissions = {
  exactAllows: new Set(['read:post']),
  wildcardAllows: [],
  exactDenies: new Set(),
  wildcardDenies: [],
};

const samplePolicy: PolicyRecord = {
  id: 'p1',
  name: 'test',
  description: null,
  effect: 'allow',
  actions: ['read'],
  resources: ['post'],
  conditions: true,
  priority: 0,
  enabled: true,
};

describe('initAuthz cache config', () => {
  it('uses shared ttlMs for both caches when no per-cache override is given', () => {
    vi.useFakeTimers();
    const { cache } = initAuthz({ db: mockDb, cache: { ttlMs: 500 } });

    cache.permissions.set('u1', samplePerms);
    cache.policies.set('read', 'post', [samplePolicy]);

    vi.advanceTimersByTime(600);

    expect(cache.permissions.get('u1')).toBeUndefined();
    expect(cache.policies.get('read', 'post')).toBeUndefined();
    vi.useRealTimers();
  });

  it('per-cache permissions.ttlMs overrides the shared value', () => {
    vi.useFakeTimers();
    const { cache } = initAuthz({
      db: mockDb,
      cache: { ttlMs: 2000, permissions: { ttlMs: 100 } },
    });

    cache.permissions.set('u1', samplePerms);
    cache.policies.set('read', 'post', [samplePolicy]);

    vi.advanceTimersByTime(200);

    // permissions expired (100ms TTL), policies still alive (2000ms TTL)
    expect(cache.permissions.get('u1')).toBeUndefined();
    expect(cache.policies.get('read', 'post')).toEqual([samplePolicy]);
    vi.useRealTimers();
  });

  it('per-cache policies.ttlMs overrides the shared value', () => {
    vi.useFakeTimers();
    const { cache } = initAuthz({
      db: mockDb,
      cache: { ttlMs: 2000, policies: { ttlMs: 100 } },
    });

    cache.permissions.set('u1', samplePerms);
    cache.policies.set('read', 'post', [samplePolicy]);

    vi.advanceTimersByTime(200);

    // policies expired (100ms TTL), permissions still alive (2000ms TTL)
    expect(cache.policies.get('read', 'post')).toBeUndefined();
    expect(cache.permissions.get('u1')).toEqual(samplePerms);
    vi.useRealTimers();
  });

  it('cache.enabled=false disables both caches regardless of per-cache overrides', () => {
    vi.useFakeTimers();
    const { cache } = initAuthz({
      db: mockDb,
      cache: { enabled: false, permissions: { ttlMs: 99999 }, policies: { ttlMs: 99999 } },
    });

    cache.permissions.set('u1', samplePerms);
    cache.policies.set('read', 'post', [samplePolicy]);

    // TTL=0 means entries expire immediately on the next tick
    vi.advanceTimersByTime(1);

    expect(cache.permissions.get('u1')).toBeUndefined();
    expect(cache.policies.get('read', 'post')).toBeUndefined();
    vi.useRealTimers();
  });
});
