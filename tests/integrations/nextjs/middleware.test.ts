import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest, NextResponse } from 'next/server';
import { createWithAuthorization } from '../../../src/integrations/nextjs/middleware.js';
import { PermissionCache, PolicyCache } from '../../../src/cache/permission-cache.js';
import type { AuthzDeps } from '../../../src/core/authorize.js';
import type { Session } from 'next-auth';
import * as authorizeModule from '../../../src/core/authorize.js';

vi.mock('../../../src/core/authorize.js');

function makeSession(userId = 'user-1'): Session {
  return {
    user: { id: userId, email: 'test@example.com', name: 'Test User' },
    expires: new Date(Date.now() + 3600_000).toISOString(),
  };
}

function makeDeps(): AuthzDeps {
  return {
    db: {} as AuthzDeps['db'],
    permissionCache: new PermissionCache(),
    policyCache: new PolicyCache(),
  };
}

function makeRequest(headers: Record<string, string> = {}): NextRequest {
  return new NextRequest('https://example.com/api/test', { headers });
}

describe('createWithAuthorization', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ── Unauthenticated ─────────────────────────────────────────────────────────

  it('returns 401 when getSession returns null', async () => {
    const withAuthorization = createWithAuthorization(makeDeps(), async () => null);
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ ok: true }));

    const wrapped = withAuthorization(handler, { action: 'read', resource: 'post' });
    const res = await wrapped(makeRequest());

    expect(res.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
  });

  it('returns 401 when session has no user.id', async () => {
    const sessionWithoutId = {
      user: { email: 'a@b.com' },
      expires: '',
    } as unknown as Session;
    const withAuthorization = createWithAuthorization(makeDeps(), async () => sessionWithoutId);
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ ok: true }));

    const wrapped = withAuthorization(handler, { action: 'read', resource: 'post' });
    const res = await wrapped(makeRequest());

    expect(res.status).toBe(401);
  });

  it('calls custom onUnauthenticated when provided', async () => {
    const withAuthorization = createWithAuthorization(makeDeps(), async () => null);
    const customResponse = NextResponse.json({ error: 'login required' }, { status: 302 });
    const onUnauthenticated = vi.fn().mockReturnValue(customResponse);

    const wrapped = withAuthorization(vi.fn(), {
      action: 'read',
      resource: 'post',
      onUnauthenticated,
    });
    const res = await wrapped(makeRequest());

    expect(onUnauthenticated).toHaveBeenCalledOnce();
    expect(res.status).toBe(302);
  });

  // ── Unauthorized ────────────────────────────────────────────────────────────

  it('returns 403 when authorize returns false', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(false);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());
    const handler = vi.fn().mockResolvedValue(NextResponse.json({ ok: true }));

    const wrapped = withAuthorization(handler, { action: 'delete', resource: 'post' });
    const res = await wrapped(makeRequest());

    expect(res.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
  });

  it('calls custom onUnauthorized when provided', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(false);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());
    const customResponse = NextResponse.json({ error: 'nope' }, { status: 403 });
    const onUnauthorized = vi.fn().mockReturnValue(customResponse);

    const wrapped = withAuthorization(vi.fn(), {
      action: 'delete',
      resource: 'post',
      onUnauthorized,
    });
    await wrapped(makeRequest());

    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  // ── Authorized ──────────────────────────────────────────────────────────────

  it('calls the handler and returns its response when authorized', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());
    const handlerResponse = NextResponse.json({ data: 'secret' });
    const handler = vi.fn().mockResolvedValue(handlerResponse);

    const wrapped = withAuthorization(handler, { action: 'read', resource: 'post' });
    const res = await wrapped(makeRequest());

    expect(handler).toHaveBeenCalledOnce();
    expect(res).toBe(handlerResponse);
  });

  // ── Resource forms ──────────────────────────────────────────────────────────

  it('passes a static string resource to authorize', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'document',
    });
    await wrapped(makeRequest());

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ resource: 'document' }),
      expect.anything(),
    );
  });

  it('resolves a synchronous resource function and passes the descriptor', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());
    const descriptor = { type: 'post', id: 'p-1', ownerId: 'user-1' };

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'update',
      resource: () => descriptor,
    });
    await wrapped(makeRequest());

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ resource: descriptor }),
      expect.anything(),
    );
  });

  it('awaits an async resource function and passes the resolved descriptor', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());
    const descriptor = { type: 'post', id: 'p-42', ownerId: 'user-1' };

    const asyncResourceFn = vi.fn().mockResolvedValue(descriptor);

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'update',
      resource: asyncResourceFn,
    });
    await wrapped(makeRequest());

    expect(asyncResourceFn).toHaveBeenCalledOnce();
    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ resource: descriptor }),
      expect.anything(),
    );
  });

  // ── Request context ─────────────────────────────────────────────────────────

  it('populates reqContext.ip from x-forwarded-for', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    await wrapped(makeRequest({ 'x-forwarded-for': '1.2.3.4' }));

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ ip: '1.2.3.4' }),
      }),
      expect.anything(),
    );
  });

  it('falls back to x-real-ip when x-forwarded-for is absent', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    await wrapped(makeRequest({ 'x-real-ip': '5.6.7.8' }));

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ ip: '5.6.7.8' }),
      }),
      expect.anything(),
    );
  });

  it('populates reqContext.userAgent from user-agent header', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    await wrapped(makeRequest({ 'user-agent': 'Mozilla/5.0' }));

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ userAgent: 'Mozilla/5.0' }),
      }),
      expect.anything(),
    );
  });

  it('always sets timestamp and hour on reqContext', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    const before = Date.now();
    await wrapped(makeRequest());
    const after = Date.now();

    const call = vi.mocked(authorizeModule.authorize).mock.calls[0][0];
    expect(call.context?.timestamp).toBeGreaterThanOrEqual(before);
    expect(call.context?.timestamp).toBeLessThanOrEqual(after);
    expect(call.context?.hour).toBeGreaterThanOrEqual(0);
    expect(call.context?.hour).toBeLessThanOrEqual(23);
  });

  it('does not set ip or userAgent when those headers are absent', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    await wrapped(makeRequest());

    const call = vi.mocked(authorizeModule.authorize).mock.calls[0][0];
    expect(call.context).not.toHaveProperty('ip');
    expect(call.context).not.toHaveProperty('userAgent');
  });

  // ── ABAC mode passthrough ───────────────────────────────────────────────────

  it('forwards abacMode: constraint to authorize', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'publish',
      resource: 'post',
      abacMode: 'constraint',
    });
    await wrapped(makeRequest());

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ abacMode: 'constraint' }),
      expect.anything(),
    );
  });

  it('defaults abacMode to fallback when not specified', async () => {
    vi.mocked(authorizeModule.authorize).mockResolvedValue(true);
    const withAuthorization = createWithAuthorization(makeDeps(), async () => makeSession());

    const wrapped = withAuthorization(vi.fn().mockResolvedValue(NextResponse.json({})), {
      action: 'read',
      resource: 'post',
    });
    await wrapped(makeRequest());

    expect(authorizeModule.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ abacMode: 'fallback' }),
      expect.anything(),
    );
  });
});
