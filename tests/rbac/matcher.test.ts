import { describe, it, expect } from 'vitest';
import { parsePermissions, hasPermission } from '../../src/rbac/matcher.js';

// ─── parsePermissions ──────────────────────────────────────────────────────

describe('parsePermissions', () => {
  it('buckets exact allows correctly', () => {
    const parsed = parsePermissions(new Set(['create:post', 'read:comment']));
    expect(parsed.exactAllows).toEqual(new Set(['create:post', 'read:comment']));
    expect(parsed.wildcardAllows).toHaveLength(0);
    expect(parsed.exactDenies.size).toBe(0);
    expect(parsed.wildcardDenies).toHaveLength(0);
  });

  it('buckets wildcard allows correctly', () => {
    const parsed = parsePermissions(new Set(['*:post', 'create:*', '*:*']));
    expect(parsed.exactAllows.size).toBe(0);
    expect(parsed.wildcardAllows).toEqual(expect.arrayContaining(['*:post', 'create:*', '*:*']));
    expect(parsed.wildcardAllows).toHaveLength(3);
  });

  it('buckets bare global wildcard "*" as a wildcard allow', () => {
    const parsed = parsePermissions(new Set(['*']));
    expect(parsed.wildcardAllows).toContain('*');
    expect(parsed.exactAllows.size).toBe(0);
  });

  it('buckets exact denies correctly (strips "!")', () => {
    const parsed = parsePermissions(new Set(['!delete:post', '!read:comment']));
    expect(parsed.exactDenies).toEqual(new Set(['delete:post', 'read:comment']));
    expect(parsed.exactAllows.size).toBe(0);
    expect(parsed.wildcardDenies).toHaveLength(0);
  });

  it('buckets wildcard denies correctly (strips "!")', () => {
    const parsed = parsePermissions(new Set(['!*:post', '!delete:*', '!*:*']));
    expect(parsed.wildcardDenies).toEqual(expect.arrayContaining(['*:post', 'delete:*', '*:*']));
    expect(parsed.wildcardDenies).toHaveLength(3);
    expect(parsed.exactDenies.size).toBe(0);
  });

  it('handles empty set', () => {
    const parsed = parsePermissions(new Set());
    expect(parsed.exactAllows.size).toBe(0);
    expect(parsed.wildcardAllows).toHaveLength(0);
    expect(parsed.exactDenies.size).toBe(0);
    expect(parsed.wildcardDenies).toHaveLength(0);
  });

  it('handles mixed allows and denies in one set', () => {
    const parsed = parsePermissions(
      new Set(['*:post', '!delete:post', 'read:comment', '!*:admin']),
    );
    expect(parsed.exactAllows).toEqual(new Set(['read:comment']));
    expect(parsed.wildcardAllows).toContain('*:post');
    expect(parsed.exactDenies).toEqual(new Set(['delete:post']));
    expect(parsed.wildcardDenies).toContain('*:admin');
  });
});

// ─── hasPermission ─────────────────────────────────────────────────────────

describe('hasPermission', () => {
  const make = (allows: string[], denies: string[] = []) =>
    parsePermissions(new Set([...allows, ...denies.map((d) => `!${d}`)]));

  // Basic exact matches
  it('returns true for an exact allow match', () => {
    expect(hasPermission(make(['create:post']), 'create', 'post')).toBe(true);
  });

  it('returns false when permission is absent', () => {
    expect(hasPermission(make(['read:post']), 'delete', 'post')).toBe(false);
  });

  it('returns false for an empty permission set', () => {
    expect(hasPermission(make([]), 'create', 'post')).toBe(false);
  });

  // Wildcard — action position
  it('"*:post" allows any action on post', () => {
    const perms = make(['*:post']);
    expect(hasPermission(perms, 'read', 'post')).toBe(true);
    expect(hasPermission(perms, 'delete', 'post')).toBe(true);
    expect(hasPermission(perms, 'publish', 'post')).toBe(true);
  });

  it('"*:post" does not match a different resource', () => {
    expect(hasPermission(make(['*:post']), 'read', 'comment')).toBe(false);
  });

  // Wildcard — resource position
  it('"create:*" allows create on any resource', () => {
    const perms = make(['create:*']);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
    expect(hasPermission(perms, 'create', 'user')).toBe(true);
    expect(hasPermission(perms, 'create', 'comment')).toBe(true);
  });

  it('"create:*" does not match a different action', () => {
    expect(hasPermission(make(['create:*']), 'delete', 'post')).toBe(false);
  });

  // Global wildcards
  it('"*:*" allows everything', () => {
    const perms = make(['*:*']);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
    expect(hasPermission(perms, 'delete', 'user')).toBe(true);
    expect(hasPermission(perms, 'anything', 'anywhere')).toBe(true);
  });

  it('bare "*" (no colon) acts as global wildcard', () => {
    const perms = make(['*']);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
    expect(hasPermission(perms, 'delete', 'user')).toBe(true);
  });

  // Exact denies
  it('explicit deny "!delete:post" blocks delete on post', () => {
    expect(hasPermission(make(['*:post'], ['delete:post']), 'delete', 'post')).toBe(false);
  });

  it('explicit deny does not affect other actions', () => {
    const perms = make(['*:post'], ['delete:post']);
    expect(hasPermission(perms, 'read', 'post')).toBe(true);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
  });

  it('deny takes precedence over global wildcard allow', () => {
    const perms = make(['*:*'], ['delete:post']);
    expect(hasPermission(perms, 'delete', 'post')).toBe(false);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
  });

  // Wildcard denies
  it('"!*:post" blocks all actions on post', () => {
    const perms = make(['*:*'], ['*:post']);
    expect(hasPermission(perms, 'read', 'post')).toBe(false);
    expect(hasPermission(perms, 'delete', 'post')).toBe(false);
    expect(hasPermission(perms, 'read', 'comment')).toBe(true);
  });

  it('"!delete:*" blocks delete on any resource', () => {
    const perms = make(['*:*'], ['delete:*']);
    expect(hasPermission(perms, 'delete', 'post')).toBe(false);
    expect(hasPermission(perms, 'delete', 'user')).toBe(false);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
  });

  // Global deny
  it('"!*:*" blocks everything, even with global allow', () => {
    const perms = make(['*:*'], ['*:*']);
    expect(hasPermission(perms, 'read', 'post')).toBe(false);
    expect(hasPermission(perms, 'create', 'user')).toBe(false);
  });

  it('bare "!*" global deny blocks everything', () => {
    // "!*" strips "!" → "*" which is a wildcard deny
    const perms = parsePermissions(new Set(['*:*', '!*']));
    expect(hasPermission(perms, 'read', 'post')).toBe(false);
    expect(hasPermission(perms, 'create', 'user')).toBe(false);
  });

  // Overlapping wildcards
  it('overlapping wildcard allows both satisfied — still true', () => {
    const perms = make(['*:post', 'create:*']);
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
  });

  it('specific deny beats overlapping wildcard allows', () => {
    const perms = make(['*:post', 'create:*'], ['create:post']);
    expect(hasPermission(perms, 'create', 'post')).toBe(false);
    expect(hasPermission(perms, 'read', 'post')).toBe(true);
    expect(hasPermission(perms, 'create', 'comment')).toBe(true);
  });

  // Multi-role merges (combined Set)
  it('deny from one role overrides allow from another role', () => {
    // Simulates two roles merged into one Set before parsing
    const perms = parsePermissions(new Set(['*:post', '!delete:post', 'delete:user']));
    expect(hasPermission(perms, 'delete', 'post')).toBe(false);
    expect(hasPermission(perms, 'read', 'post')).toBe(true);
    expect(hasPermission(perms, 'delete', 'user')).toBe(true);
  });

  // Malformed strings
  it('ignores malformed strings without a colon (not "*")', () => {
    // "createpost" has no colon and is not a wildcard — treated as non-matching
    const perms = parsePermissions(new Set(['createpost', 'create:post']));
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
    // The malformed entry doesn't accidentally match anything
    expect(hasPermission(perms, 'createpost', '')).toBe(false);
  });

  it('ignores malformed deny strings without a colon', () => {
    const perms = parsePermissions(new Set(['create:post', '!deletepost']));
    // "!deletepost" strips "!" → "deletepost" (no colon, not "*") → skips in wildcard check
    expect(hasPermission(perms, 'create', 'post')).toBe(true);
    expect(hasPermission(perms, 'delete', 'post')).toBe(false); // still denied? No — not in denies
  });
});
