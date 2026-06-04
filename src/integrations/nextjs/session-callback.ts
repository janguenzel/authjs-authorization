import type { AuthzAdapter } from '../../types/adapter.js';
import type { Session } from 'next-auth';
import type { AdapterUser } from 'next-auth/adapters';
import type { JWT } from 'next-auth/jwt';

interface SessionCallbackParams {
  session: Session;
  token?: JWT;
  user?: AdapterUser;
}

/**
 * Creates a session callback for Auth.js that injects role names into the session.
 *
 * Roles in the session are for convenience only (e.g. client-side UI decisions).
 * Authorization decisions always use the database as the authoritative source.
 *
 * @example
 * // auth.ts
 * import NextAuth from 'next-auth';
 * import { createSessionCallback } from '@janguenzel/authjs-authorization/nextjs';
 * import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';
 * import { prisma } from './prisma';
 *
 * export const { handlers, auth } = NextAuth({
 *   callbacks: {
 *     session: createSessionCallback(createPrismaAdapter(prisma)),
 *   },
 * });
 */
export function createSessionCallback(db: AuthzAdapter) {
  return async ({ session, token, user }: SessionCallbackParams): Promise<Session> => {
    const userId = token?.sub ?? user?.id;
    if (!userId || !session.user) return session;

    try {
      const roles = await db.getUserRoleNames(userId);
      const user = { ...session.user, id: userId, roles } as typeof session.user;
      return { ...session, user };
    } catch (err) {
      // Fail open — roles will be missing from this session but sign-in succeeds.
      console.error('[@janguenzel/authjs-authorization] Role lookup failed:', err);
    }

    return session;
  };
}
