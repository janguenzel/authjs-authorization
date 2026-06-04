import type { AuthzAdapter } from '../types/adapter.js';
import type { Session } from 'next-auth';
import type { NextRequest } from 'next/server';
import type { AuthzOptions } from '../types/authz.js';
import type { LRUCacheOptions } from '../cache/lru.js';
import { PermissionCache, PolicyCache } from '../cache/permission-cache.js';
import { authorize, authorizeWithResult, type AuthzDeps } from './authorize.js';
import { AuthzBuilder } from '../fluent/builder.js';
import { createWithAuthorization, type WithAuthorizationOptions } from '../integrations/nextjs/middleware.js';

export interface AuthzConfig {
  /**
   * Database adapter providing the data access methods required by the authorization engine.
   * Use `createPrismaAdapter(prisma)` from `@janguenzel/authjs-authorization/prisma` for the
   * default Prisma implementation, or implement {@link AuthzAdapter} for any other database.
   */
  db: AuthzAdapter;
  /**
   * Your Auth.js `auth` function, exported from your `auth.ts` config.
   * Required to use `withAuthorization` without providing `getSession` per-route.
   *
   * @example
   * import { auth } from '@/auth'; // your NextAuth config
   * initAuthz({ db: prisma, auth });
   */
  auth?: (req?: NextRequest) => Promise<Session | null>;
  cache?: {
    /** Set false to disable caching (useful for testing). Default: true */
    enabled?: boolean;
    /** Shared TTL fallback in milliseconds. Default: 300_000 (5 min) */
    ttlMs?: number;
    /** Shared max entries fallback per cache. Default: 1000 */
    maxSize?: number;
    /** Per-cache overrides for the permission (RBAC) cache. Falls back to shared values. */
    permissions?: { ttlMs?: number; maxSize?: number };
    /** Per-cache overrides for the policy (ABAC) cache. Falls back to shared values. */
    policies?: { ttlMs?: number; maxSize?: number };
  };
}

export interface AuthzInstance {
  /**
   * Returns true if the session user is authorized.
   * Combines RBAC (fast path) and ABAC (policy evaluation) according to abacMode.
   */
  authorize(options: AuthzOptions): Promise<boolean>;

  /**
   * Like authorize() but returns a detailed result with a reason field.
   */
  authorizeWithResult(options: AuthzOptions): Promise<Awaited<ReturnType<typeof authorizeWithResult>>>;

  /**
   * Next.js App Router HOF — wraps a route handler with an authorization check.
   * Requires `auth` to be passed to `initAuthz`.
   *
   * @example
   * export const DELETE = withAuthorization(
   *   async (req) => NextResponse.json({ ok: true }),
   *   { action: 'delete', resource: 'post' },
   * );
   */
  withAuthorization: ReturnType<typeof createWithAuthorization>;

  /**
   * Fluent builder entry point.
   * @example
   * const allowed = await can(session).do('delete').on('post').check();
   */
  can(session: Session | null): AuthzBuilder;

  /** Direct access to the caches for manual invalidation */
  cache: {
    permissions: PermissionCache;
    policies: PolicyCache;
  };
}

/**
 * Initializes the authorization system and returns a bound instance.
 * Call this once at application startup alongside your Auth.js config.
 *
 * @example
 * // lib/authz.ts
 * import { initAuthz } from '@janguenzel/authjs-authorization';
 * import { auth } from '@/auth';
 * import { prisma } from './prisma';
 *
 * export const { authorize, withAuthorization, can } = initAuthz({ db: prisma, auth });
 */
export function initAuthz(config: AuthzConfig): AuthzInstance {
  const disabled = config.cache?.enabled === false;
  const sharedTtl = config.cache?.ttlMs ?? 300_000;
  const sharedMax = config.cache?.maxSize ?? 1000;

  const permissionOptions: LRUCacheOptions = disabled
    ? { maxSize: 0, ttlMs: 0 }
    : {
        ttlMs: config.cache?.permissions?.ttlMs ?? sharedTtl,
        maxSize: config.cache?.permissions?.maxSize ?? sharedMax,
      };
  const policyOptions: LRUCacheOptions = disabled
    ? { maxSize: 0, ttlMs: 0 }
    : {
        ttlMs: config.cache?.policies?.ttlMs ?? sharedTtl,
        maxSize: config.cache?.policies?.maxSize ?? sharedMax,
      };

  const permissionCache = new PermissionCache(permissionOptions);
  const policyCache = new PolicyCache(policyOptions);

  const deps: AuthzDeps = {
    db: config.db,
    permissionCache,
    policyCache,
  };

  // Session retrieval for withAuthorization — uses the consumer's auth() or throws
  const getSession = config.auth
    ? (req: NextRequest) => Promise.resolve(config.auth!(req))
    : (_req: NextRequest): Promise<Session | null> => {
        throw new Error(
          '[@janguenzel/authjs-authorization] withAuthorization requires an `auth` function. ' +
            'Pass it to initAuthz: initAuthz({ db, auth })',
        );
      };

  return {
    authorize: (options: AuthzOptions) => authorize(options, deps),
    authorizeWithResult: (options: AuthzOptions) => authorizeWithResult(options, deps),
    withAuthorization: createWithAuthorization(deps, getSession),
    can: (session: Session | null) => new AuthzBuilder(session, deps),
    cache: { permissions: permissionCache, policies: policyCache },
  };
}
