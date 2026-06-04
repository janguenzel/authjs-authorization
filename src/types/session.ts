import type { DefaultSession } from 'next-auth';

/** Extended user shape that includes authz fields injected via createSessionCallback */
export interface AuthzSessionUser {
  id: string;
  /** Role names injected by createSessionCallback — convenience only, not authoritative */
  roles?: string[];
}

/**
 * Merge type for consumers to use in their next-auth.d.ts module augmentation.
 *
 * @example
 * // In your project's src/types/next-auth.d.ts:
 * import type { DefaultSession } from 'next-auth';
 * import type { ExtendedSessionUser } from '@janguenzel/authjs-authorization';
 *
 * declare module 'next-auth' {
 *   interface Session {
 *     user: ExtendedSessionUser & DefaultSession['user'];
 *   }
 * }
 */
export type ExtendedSessionUser = AuthzSessionUser & DefaultSession['user'];
