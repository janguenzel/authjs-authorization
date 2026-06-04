import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createSessionCallback } from '../../../src/integrations/nextjs/session-callback.js';
import type { AuthzAdapter } from '../../../src/types/adapter.js';
import type { Session } from 'next-auth';

function makeAdapter(roleNames: string[] = [], rejectWith?: Error): AuthzAdapter {
  return {
    getUserPermissions: vi.fn(),
    getPoliciesForContext: vi.fn(),
    getUserRoleNames: rejectWith
      ? vi.fn().mockRejectedValue(rejectWith)
      : vi.fn().mockResolvedValue(roleNames),
  };
}

function makeSession(userId?: string): Session {
  const user: Session['user'] = { name: 'Alice', email: 'alice@example.com' };
  if (userId) (user as { id?: string }).id = userId;
  return {
    user,
    expires: new Date(Date.now() + 3600_000).toISOString(),
  };
}

describe('createSessionCallback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('injects user.id and user.roles into session when token.sub is present', async () => {
    const db = makeAdapter(['admin', 'editor']);
    const callback = createSessionCallback(db);
    const session = makeSession();

    const result = await callback({
      session,
      token: { sub: 'user-123', iat: 0, exp: 0, jti: 'x' },
    });

    expect((result.user as { id?: string }).id).toBe('user-123');
    expect((result.user as { roles?: string[] }).roles).toEqual(['admin', 'editor']);
    expect(db.getUserRoleNames).toHaveBeenCalledWith('user-123');
  });

  it('uses user.id when no token.sub is available (database session strategy)', async () => {
    const db = makeAdapter(['viewer']);
    const callback = createSessionCallback(db);
    const session = makeSession();

    const result = await callback({
      session,
      user: { id: 'user-456', email: 'alice@example.com', emailVerified: null },
    });

    expect((result.user as { id?: string }).id).toBe('user-456');
    expect((result.user as { roles?: string[] }).roles).toEqual(['viewer']);
  });

  it('returns session unchanged when no userId is available', async () => {
    const db = makeAdapter();
    const callback = createSessionCallback(db);
    const session = makeSession(); // no id on user
    const result = await callback({ session }); // no token, no user

    expect(result).toBe(session);
    expect(db.getUserRoleNames).not.toHaveBeenCalled();
  });

  it('swallows getUserRoleNames errors and returns the original session', async () => {
    const db = makeAdapter([], new Error('DB timeout'));
    const callback = createSessionCallback(db);
    const session = makeSession();

    await expect(
      callback({ session, token: { sub: 'user-1', iat: 0, exp: 0, jti: 'x' } }),
    ).resolves.toBe(session);
  });

  it('returns session unchanged when session has no user object', async () => {
    const db = makeAdapter();
    const callback = createSessionCallback(db);
    const session = { expires: new Date().toISOString() } as Session;

    const result = await callback({
      session,
      token: { sub: 'user-1', iat: 0, exp: 0, jti: 'x' },
    });

    expect(result).toBe(session);
    expect(db.getUserRoleNames).not.toHaveBeenCalled();
  });
});
