import { describe, it, expect, vi, beforeEach } from 'vitest';
import { authorize, authorizeWithResult } from '../../src/core/authorize.js';
import type { AuthzDeps } from '../../src/core/authorize.js';
import { PermissionCache, PolicyCache } from '../../src/cache/permission-cache.js';
import type { Session } from 'next-auth';
import * as rbacEngine from '../../src/rbac/engine.js';
import * as abacEvaluator from '../../src/abac/evaluator.js';
import type { ABACDecision } from '../../src/abac/evaluator.js';

vi.mock('../../src/rbac/engine.js');
vi.mock('../../src/abac/evaluator.js');

function makeSession(userId = 'user-1'): Session {
  return {
    user: { id: userId, email: 'test@example.com', name: 'Test User' },
    expires: new Date(Date.now() + 3600_000).toISOString(),
  };
}

describe('authorize()', () => {
  let deps: AuthzDeps;

  beforeEach(() => {
    deps = {
      db: {} as AuthzDeps['db'],
      permissionCache: new PermissionCache(),
      policyCache: new PolicyCache(),
    };
    vi.clearAllMocks();
  });

  // ── Session validation ────────────────────────────────────────────────────

  it('returns false when session is null', async () => {
    expect(await authorize({ session: null, action: 'read', resource: 'post' }, deps)).toBe(false);
  });

  it('returns false when session has no user id', async () => {
    const session = { user: { email: 'a@b.com' }, expires: '' } as unknown as Session;
    expect(await authorize({ session, action: 'read', resource: 'post' }, deps)).toBe(false);
  });

  // ── Fallback mode (default) ───────────────────────────────────────────────

  it('fallback: RBAC allow → returns true immediately without calling ABAC', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);

    const result = await authorize(
      { session: makeSession(), action: 'read', resource: 'post' },
      deps,
    );

    expect(result).toBe(true);
    expect(abacEvaluator.checkABAC).not.toHaveBeenCalled();
  });

  it('fallback: RBAC deny → calls ABAC, returns true on ABAC allow', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('allow' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'update', resource: 'post' },
      deps,
    );

    expect(result).toBe(true);
    expect(abacEvaluator.checkABAC).toHaveBeenCalledOnce();
  });

  it('fallback: RBAC deny + ABAC no-match → returns false', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('no-match' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'delete', resource: 'post' },
      deps,
    );

    expect(result).toBe(false);
  });

  it('fallback: RBAC deny + ABAC deny → returns false', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('deny' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'delete', resource: 'post' },
      deps,
    );

    expect(result).toBe(false);
  });

  // ── Constraint mode ───────────────────────────────────────────────────────

  it('constraint: RBAC deny → returns false immediately without calling ABAC', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);

    const result = await authorize(
      { session: makeSession(), action: 'delete', resource: 'post', abacMode: 'constraint' },
      deps,
    );

    expect(result).toBe(false);
    expect(abacEvaluator.checkABAC).not.toHaveBeenCalled();
  });

  it('constraint: RBAC allow + ABAC allow → returns true', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('allow' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'create', resource: 'post', abacMode: 'constraint' },
      deps,
    );

    expect(result).toBe(true);
  });

  it('constraint: RBAC allow + ABAC no-match → returns true (silent ABAC honors RBAC grant)', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('no-match' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'create', resource: 'post', abacMode: 'constraint' },
      deps,
    );

    expect(result).toBe(true);
  });

  it('constraint: RBAC allow + ABAC deny → returns false', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('deny' as ABACDecision);

    const result = await authorize(
      { session: makeSession(), action: 'publish', resource: 'post', abacMode: 'constraint' },
      deps,
    );

    expect(result).toBe(false);
  });

  // ── Resource normalization ────────────────────────────────────────────────

  it('accepts a string resource and passes its type to RBAC', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);

    await authorize({ session: makeSession(), action: 'read', resource: 'comment' }, deps);

    expect(rbacEngine.checkRBAC).toHaveBeenCalledWith(
      'user-1',
      'read',
      'comment',
      expect.anything(),
      expect.anything(),
    );
  });

  it('accepts a ResourceDescriptor and passes its type to RBAC', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);

    await authorize(
      { session: makeSession(), action: 'read', resource: { type: 'comment', id: 'c-1' } },
      deps,
    );

    expect(rbacEngine.checkRBAC).toHaveBeenCalledWith(
      'user-1',
      'read',
      'comment',
      expect.anything(),
      expect.anything(),
    );
  });
});

describe('authorizeWithResult()', () => {
  let deps: AuthzDeps;

  beforeEach(() => {
    deps = {
      db: {} as AuthzDeps['db'],
      permissionCache: new PermissionCache(),
      policyCache: new PolicyCache(),
    };
    vi.clearAllMocks();
  });

  it('returns no-session result when session is null', async () => {
    const result = await authorizeWithResult({ session: null, action: 'read', resource: 'post' }, deps);
    expect(result).toEqual({ allowed: false, reason: 'no-session' });
  });

  it('fallback: RBAC allow → { allowed: true, reason: "rbac-allowed" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'read', resource: 'post' },
      deps,
    );
    expect(result).toEqual({ allowed: true, reason: 'rbac-allowed' });
    expect(abacEvaluator.checkABAC).not.toHaveBeenCalled();
  });

  it('fallback: RBAC deny + ABAC allow → { allowed: true, reason: "abac-allowed" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('allow' as ABACDecision);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'update', resource: 'post' },
      deps,
    );
    expect(result).toEqual({ allowed: true, reason: 'abac-allowed' });
  });

  it('fallback: RBAC deny + ABAC deny → { allowed: false, reason: "abac-denied" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('deny' as ABACDecision);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'delete', resource: 'post' },
      deps,
    );
    expect(result).toEqual({ allowed: false, reason: 'abac-denied' });
  });

  it('constraint: RBAC deny → { allowed: false, reason: "rbac-denied" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(false);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'delete', resource: 'post', abacMode: 'constraint' },
      deps,
    );
    expect(result).toEqual({ allowed: false, reason: 'rbac-denied' });
    expect(abacEvaluator.checkABAC).not.toHaveBeenCalled();
  });

  it('constraint: RBAC allow + ABAC deny → { allowed: false, reason: "abac-denied" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('deny' as ABACDecision);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'publish', resource: 'post', abacMode: 'constraint' },
      deps,
    );
    expect(result).toEqual({ allowed: false, reason: 'abac-denied' });
  });

  it('constraint: RBAC allow + ABAC no-match → { allowed: true, reason: "rbac-allowed" }', async () => {
    vi.mocked(rbacEngine.checkRBAC).mockResolvedValue(true);
    vi.mocked(abacEvaluator.checkABAC).mockResolvedValue('no-match' as ABACDecision);
    const result = await authorizeWithResult(
      { session: makeSession(), action: 'create', resource: 'post', abacMode: 'constraint' },
      deps,
    );
    expect(result).toEqual({ allowed: true, reason: 'rbac-allowed' });
  });
});
