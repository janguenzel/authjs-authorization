import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthzBuilder, AuthzError } from '../../src/fluent/builder.js';
import type { AuthzDeps } from '../../src/core/authorize.js';
import { PermissionCache, PolicyCache } from '../../src/cache/permission-cache.js';
import type { Session } from 'next-auth';
import * as coreAuthorize from '../../src/core/authorize.js';

vi.mock('../../src/core/authorize.js', async (importOriginal) => {
  const actual = await importOriginal<typeof coreAuthorize>();
  return {
    ...actual,
    authorize: vi.fn(),
  };
});

function makeSession(userId = 'user-1'): Session {
  return {
    user: { id: userId, email: 'test@example.com', name: 'Test User' },
    expires: new Date(Date.now() + 3600_000).toISOString(),
  };
}

describe('AuthzBuilder (fluent API)', () => {
  let deps: AuthzDeps;

  beforeEach(() => {
    deps = {
      db: {} as AuthzDeps['db'],
      permissionCache: new PermissionCache(),
      policyCache: new PolicyCache(),
    };
    vi.clearAllMocks();
  });

  it('can(session).do(action).on(resource).check() calls authorize with correct args', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(true);

    const builder = new AuthzBuilder(makeSession(), deps);
    const result = await builder.do('create').on('post').check();

    expect(result).toBe(true);
    expect(coreAuthorize.authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'create',
        resource: 'post',
        abacMode: 'fallback',
      }),
      deps,
    );
  });

  it('passes null session to authorize', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(false);

    const builder = new AuthzBuilder(null, deps);
    const result = await builder.do('read').on('post').check();

    expect(result).toBe(false);
    expect(coreAuthorize.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ session: null }),
      deps,
    );
  });

  it('passes ResourceDescriptor to authorize', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(true);

    await new AuthzBuilder(makeSession(), deps)
      .do('delete')
      .on({ type: 'post', id: 'post-1', ownerId: 'user-1' })
      .check();

    expect(coreAuthorize.authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        resource: { type: 'post', id: 'post-1', ownerId: 'user-1' },
      }),
      deps,
    );
  });

  it('.withContext() passes context through to authorize', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(true);

    await new AuthzBuilder(makeSession(), deps)
      .do('read')
      .on('post')
      .withContext({ ip: '10.0.0.1', hour: 14 })
      .check();

    expect(coreAuthorize.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ context: { ip: '10.0.0.1', hour: 14 } }),
      deps,
    );
  });

  it('.withMode("constraint") sets abacMode on the authorize call', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(true);

    await new AuthzBuilder(makeSession(), deps)
      .do('publish')
      .on('post')
      .withMode('constraint')
      .check();

    expect(coreAuthorize.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ abacMode: 'constraint' }),
      deps,
    );
  });

  it('.allow() resolves without throwing when authorize returns true', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(true);

    await expect(
      new AuthzBuilder(makeSession(), deps).do('create').on('post').allow(),
    ).resolves.toBeUndefined();
  });

  it('.allow() throws AuthzError when authorize returns false', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(false);

    await expect(
      new AuthzBuilder(makeSession(), deps).do('delete').on('post').allow(),
    ).rejects.toThrow(AuthzError);
  });

  it('AuthzError has name "AuthzError"', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(false);

    const err = await new AuthzBuilder(makeSession(), deps)
      .do('delete')
      .on('post')
      .allow()
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(AuthzError);
    expect((err as AuthzError).name).toBe('AuthzError');
  });

  it('AuthzError message includes action and resource type', async () => {
    vi.mocked(coreAuthorize.authorize).mockResolvedValue(false);

    await expect(
      new AuthzBuilder(makeSession(), deps).do('delete').on('post').allow(),
    ).rejects.toThrow(/delete/);
  });
});
