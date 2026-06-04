import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkRBAC } from '../../src/rbac/engine.js';
import { PermissionCache } from '../../src/cache/permission-cache.js';
import type { AuthzAdapter } from '../../src/types/adapter.js';

function makeAdapter(permissions: Set<string>): AuthzAdapter {
  return {
    getUserPermissions: vi.fn().mockResolvedValue(permissions),
    getPoliciesForContext: vi.fn(),
    getUserRoleNames: vi.fn(),
  };
}

describe('checkRBAC', () => {
  let cache: PermissionCache;

  beforeEach(() => {
    cache = new PermissionCache({ maxSize: 100, ttlMs: 60_000 });
    vi.clearAllMocks();
  });

  it('returns true when user has the required permission', async () => {
    const db = makeAdapter(new Set(['create:post', 'read:post']));
    const result = await checkRBAC('user-1', 'create', 'post', db, cache);
    expect(result).toBe(true);
  });

  it('returns false when user lacks the required permission', async () => {
    const db = makeAdapter(new Set(['read:post']));
    const result = await checkRBAC('user-1', 'delete', 'post', db, cache);
    expect(result).toBe(false);
  });

  it('uses cache on second call — adapter queried only once', async () => {
    const db = makeAdapter(new Set(['read:post']));

    await checkRBAC('user-2', 'read', 'post', db, cache);
    await checkRBAC('user-2', 'read', 'post', db, cache);

    expect(db.getUserPermissions).toHaveBeenCalledTimes(1);
  });

  it('queries adapter again after cache miss for a different user', async () => {
    const db = makeAdapter(new Set(['read:post']));

    await checkRBAC('user-A', 'read', 'post', db, cache);
    await checkRBAC('user-B', 'read', 'post', db, cache);

    expect(db.getUserPermissions).toHaveBeenCalledTimes(2);
  });

  it('returns false for empty permission set', async () => {
    const db = makeAdapter(new Set());
    const result = await checkRBAC('user-3', 'create', 'post', db, cache);
    expect(result).toBe(false);
  });

  // Wildcard permissions
  it('matches wildcard action "*:post"', async () => {
    const db = makeAdapter(new Set(['*:post']));
    expect(await checkRBAC('u', 'delete', 'post', db, cache)).toBe(true);
    expect(await checkRBAC('u', 'read', 'post', db, cache)).toBe(true);
  });

  it('does not match wildcard action "*:post" against a different resource', async () => {
    const db = makeAdapter(new Set(['*:post']));
    expect(await checkRBAC('u', 'read', 'comment', db, cache)).toBe(false);
  });

  it('matches wildcard resource "create:*"', async () => {
    const db = makeAdapter(new Set(['create:*']));
    expect(await checkRBAC('u', 'create', 'post', db, cache)).toBe(true);
    expect(await checkRBAC('u', 'create', 'comment', db, cache)).toBe(true);
  });

  it('does not match wildcard resource "create:*" against a different action', async () => {
    const db = makeAdapter(new Set(['create:*']));
    expect(await checkRBAC('u', 'delete', 'post', db, cache)).toBe(false);
  });

  it('global wildcard "*:*" allows everything', async () => {
    const db = makeAdapter(new Set(['*:*']));
    expect(await checkRBAC('u', 'create', 'post', db, cache)).toBe(true);
    expect(await checkRBAC('u', 'delete', 'user', db, cache)).toBe(true);
  });

  // Negative permissions
  it('explicit deny "!delete:post" blocks delete on post', async () => {
    const db = makeAdapter(new Set(['*:post', '!delete:post']));
    expect(await checkRBAC('u', 'read', 'post', db, cache)).toBe(true);
    expect(await checkRBAC('u', 'delete', 'post', db, cache)).toBe(false);
  });

  it('deny takes precedence over global wildcard allow', async () => {
    const db = makeAdapter(new Set(['*:*', '!delete:post']));
    expect(await checkRBAC('u', 'create', 'post', db, cache)).toBe(true);
    expect(await checkRBAC('u', 'delete', 'post', db, cache)).toBe(false);
  });

  it('wildcard deny "!*:post" blocks all actions on post', async () => {
    const db = makeAdapter(new Set(['*:*', '!*:post']));
    expect(await checkRBAC('u', 'read', 'post', db, cache)).toBe(false);
    expect(await checkRBAC('u', 'delete', 'post', db, cache)).toBe(false);
    expect(await checkRBAC('u', 'read', 'comment', db, cache)).toBe(true);
  });

  it('global deny "!*:*" blocks everything', async () => {
    const db = makeAdapter(new Set(['*:*', '!*:*']));
    expect(await checkRBAC('u', 'read', 'post', db, cache)).toBe(false);
    expect(await checkRBAC('u', 'create', 'user', db, cache)).toBe(false);
  });
});
