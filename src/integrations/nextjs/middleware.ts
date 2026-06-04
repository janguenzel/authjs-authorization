import type { NextRequest, NextResponse as NR } from 'next/server';
import type { Session } from 'next-auth';
import type { AuthzOptions, ABACMode, ResourceDescriptor, RequestContext } from '../../types/authz.js';
import type { AuthzDeps } from '../../core/authorize.js';
import { authorize } from '../../core/authorize.js';

type NextResponseType = NR<unknown>;

/** A function that retrieves the Auth.js session for a given request */
export type GetSessionFn = (req: NextRequest) => Promise<Session | null>;

export interface WithAuthorizationOptions {
  action: string;
  /** Static resource type string, or a function that derives it from the request (sync or async) */
  resource: string | ((req: NextRequest) => ResourceDescriptor | Promise<ResourceDescriptor>);
  abacMode?: ABACMode;
  /** Called when the user is not authenticated (no session). Defaults to 401 JSON response */
  onUnauthenticated?: (req: NextRequest) => NextResponseType;
  /** Called when authorization is denied. Defaults to 403 JSON response */
  onUnauthorized?: (req: NextRequest) => NextResponseType;
}

/**
 * Creates a withAuthorization HOF bound to the given deps and session retrieval function.
 * Pass the Auth.js `auth` function exported from your `auth.ts` config file.
 *
 * @example
 * // lib/authz.ts
 * import { auth } from '@/auth';
 * import { initAuthz } from '@janguenzel/authjs-authorization';
 * import { prisma } from './prisma';
 *
 * export const { authorize, withAuthorization, can } = initAuthz({ db: prisma, auth });
 */
export function createWithAuthorization(deps: AuthzDeps, getSession: GetSessionFn) {
  return function withAuthorization<T>(
    handler: (req: NextRequest) => Promise<NR<T>>,
    options: WithAuthorizationOptions,
  ): (req: NextRequest) => Promise<NR<T> | NextResponseType> {
    return async (req: NextRequest) => {
      const { NextResponse } = await import('next/server');

      const session = await getSession(req);

      if (!session?.user?.id) {
        if (options.onUnauthenticated) return options.onUnauthenticated(req);
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) as NextResponseType;
      }

      const resource =
        typeof options.resource === 'function' ? await options.resource(req) : options.resource;

      const reqContext: RequestContext = {
        timestamp: Date.now(),
        hour: new Date().getHours(),
      };
      const ip = req.headers.get('x-forwarded-for') ?? req.headers.get('x-real-ip');
      const ua = req.headers.get('user-agent');
      if (ip !== null) reqContext.ip = ip;
      if (ua !== null) reqContext.userAgent = ua;

      const authzOptions: AuthzOptions = {
        session,
        action: options.action,
        resource,
        abacMode: options.abacMode ?? 'fallback',
        context: reqContext,
      };

      const allowed = await authorize(authzOptions, deps);

      if (!allowed) {
        if (options.onUnauthorized) return options.onUnauthorized(req);
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 }) as NextResponseType;
      }

      return handler(req);
    };
  };
}
