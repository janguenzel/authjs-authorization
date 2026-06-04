/**
 * Example: Auth.js (NextAuth v5) configuration with authz session callback
 *
 * This shows how to wire createSessionCallback into your Auth.js config so that
 * role names are injected into the session object for client-side convenience.
 *
 * NOTE: Session roles are for UI display only. Authorization decisions
 * always query the database as the authoritative source.
 */
import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
import { PrismaAdapter } from '@auth/prisma-adapter';
import { PrismaClient } from '@prisma/client';
import { createSessionCallback } from '@janguenzel/authjs-authorization/nextjs';
import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';

const prisma = new PrismaClient();
const authzAdapter = createPrismaAdapter(prisma);

export const { handlers, auth, signIn, signOut } = NextAuth({
  adapter: PrismaAdapter(prisma),

  providers: [GitHub],

  session: { strategy: 'database' },

  callbacks: {
    // Injects user.id and user.roles into every session
    session: createSessionCallback(authzAdapter),
  },

  pages: {
    signIn: '/auth/signin',
  },
});
