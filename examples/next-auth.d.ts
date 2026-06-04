/**
 * Module augmentation for Auth.js session types.
 *
 * Copy this file into your project (e.g. src/types/next-auth.d.ts) and
 * include it in your tsconfig.json `include` or `typeRoots`.
 *
 * This gives you full TypeScript type safety for session.user.id and
 * session.user.roles throughout your application.
 */
import type { DefaultSession } from 'next-auth';
import type { ExtendedSessionUser } from '@janguenzel/authjs-authorization';

declare module 'next-auth' {
  interface Session {
    user: ExtendedSessionUser & DefaultSession['user'];
  }
}

export {};
