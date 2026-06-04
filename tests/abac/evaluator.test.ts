import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkABAC } from '../../src/abac/evaluator.js';
import { PolicyCache } from '../../src/cache/permission-cache.js';
import type { ABACEvalContext } from '../../src/types/abac.js';
import * as abacLoader from '../../src/abac/loader.js';

vi.mock('../../src/abac/loader.js');

const mockDb = {} as Parameters<typeof checkABAC>[1];

const baseUser: ABACEvalContext['user'] = {
  id: 'user-1',
  email: 'user@example.com',
  roles: ['editor'],
};

describe('checkABAC', () => {
  let cache: PolicyCache;

  beforeEach(() => {
    cache = new PolicyCache({ maxSize: 100, ttlMs: 60_000 });
    vi.clearAllMocks();
  });

  it('returns "allow" when a matching allow policy evaluates to true', async () => {
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([
      {
        id: 'p1',
        name: 'owner-update',
        description: null,
        effect: 'allow',
        actions: ['update'],
        resources: ['post'],
        conditions: { '===': [{ var: 'user.id' }, { var: 'resource.ownerId' }] },
        priority: 10,
        enabled: true,
      },
    ]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post', id: 'post-1', ownerId: 'user-1' },
      action: 'update',
    };

    expect(await checkABAC(ctx, mockDb, cache)).toBe('allow');
  });

  it('returns "no-match" when ownership check fails (policy condition is false)', async () => {
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([
      {
        id: 'p1',
        name: 'owner-update',
        description: null,
        effect: 'allow',
        actions: ['update'],
        resources: ['post'],
        conditions: { '===': [{ var: 'user.id' }, { var: 'resource.ownerId' }] },
        priority: 10,
        enabled: true,
      },
    ]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post', id: 'post-1', ownerId: 'other-user' },
      action: 'update',
    };

    expect(await checkABAC(ctx, mockDb, cache)).toBe('no-match');
  });

  it('returns "no-match" when no policies exist', async () => {
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post' },
      action: 'delete',
    };

    expect(await checkABAC(ctx, mockDb, cache)).toBe('no-match');
  });

  it('returns "deny" when a matching deny policy evaluates to true', async () => {
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([
      {
        id: 'p2',
        name: 'outside-hours-deny',
        description: null,
        effect: 'deny',
        actions: [],
        resources: [],
        conditions: {
          or: [
            { '<': [{ var: 'context.hour' }, 9] },
            { '>=': [{ var: 'context.hour' }, 18] },
          ],
        },
        priority: 100,
        enabled: true,
      },
    ]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post' },
      action: 'create',
      context: { hour: 22 }, // outside business hours
    };

    expect(await checkABAC(ctx, mockDb, cache)).toBe('deny');
  });

  it('skips malformed JSON Logic rules without throwing', async () => {
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([
      {
        id: 'bad',
        name: 'bad-rule',
        description: null,
        effect: 'allow',
        actions: [],
        resources: [],
        conditions: 'this is not valid json-logic',
        priority: 0,
        enabled: true,
      },
    ]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post' },
      action: 'read',
    };

    await expect(checkABAC(ctx, mockDb, cache)).resolves.toBe('no-match');
  });

  it('respects priority order — higher priority evaluated first', async () => {
    // DB returns policies sorted by priority DESC — high priority first
    vi.mocked(abacLoader.loadPolicies).mockResolvedValue([
      {
        id: 'high',
        name: 'high-deny',
        description: null,
        effect: 'deny',
        actions: [],
        resources: [],
        conditions: true,
        priority: 100,
        enabled: true,
      },
      {
        id: 'low',
        name: 'low-allow',
        description: null,
        effect: 'allow',
        actions: [],
        resources: [],
        conditions: true,
        priority: 1,
        enabled: true,
      },
    ]);

    const ctx: ABACEvalContext = {
      user: baseUser,
      resource: { type: 'post' },
      action: 'create',
    };

    expect(await checkABAC(ctx, mockDb, cache)).toBe('deny');
  });
});
