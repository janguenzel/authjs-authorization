import { describe, it, expect } from 'vitest';
import { PermissionCache, PolicyCache } from '../../src/cache/permission-cache.js';
import type { ParsedPermissions } from '../../src/types/rbac.js';
import type { PolicyRecord } from '../../src/types/abac.js';

const makePerms = (allows: string[] = [], denies: string[] = []): ParsedPermissions => ({
  exactAllows: new Set(allows),
  wildcardAllows: [],
  exactDenies: new Set(denies),
  wildcardDenies: [],
});

describe('PermissionCache', () => {
  it('stores and retrieves a parsed permission set', () => {
    const cache = new PermissionCache();
    const perms = makePerms(['create:post', 'read:post']);
    cache.set('user-1', perms);
    expect(cache.get('user-1')).toBe(perms);
  });

  it('returns undefined for unknown users', () => {
    const cache = new PermissionCache();
    expect(cache.get('unknown')).toBeUndefined();
  });

  it('invalidate() removes the entry for a specific user', () => {
    const cache = new PermissionCache();
    cache.set('user-1', makePerms(['read:post']));
    cache.set('user-2', makePerms(['create:post']));

    cache.invalidate('user-1');

    expect(cache.get('user-1')).toBeUndefined();
    expect(cache.get('user-2')).toBeDefined();
  });

  it('clear() removes all entries', () => {
    const cache = new PermissionCache();
    cache.set('user-1', makePerms(['read:post']));
    cache.set('user-2', makePerms(['create:post']));

    cache.clear();

    expect(cache.get('user-1')).toBeUndefined();
    expect(cache.get('user-2')).toBeUndefined();
  });
});

describe('PolicyCache', () => {
  const samplePolicy: PolicyRecord = {
    id: 'p1',
    name: 'test',
    description: null,
    effect: 'allow',
    actions: ['create'],
    resources: ['post'],
    conditions: true,
    priority: 0,
    enabled: true,
  };

  it('stores and retrieves policies by action + resource', () => {
    const cache = new PolicyCache();
    cache.set('create', 'post', [samplePolicy]);
    expect(cache.get('create', 'post')).toEqual([samplePolicy]);
  });

  it('returns undefined for unknown action/resource combinations', () => {
    const cache = new PolicyCache();
    expect(cache.get('delete', 'post')).toBeUndefined();
  });

  it('clear() removes all cached policies', () => {
    const cache = new PolicyCache();
    cache.set('create', 'post', [samplePolicy]);
    cache.clear();
    expect(cache.get('create', 'post')).toBeUndefined();
  });
});
