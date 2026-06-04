import type { PolicyRecord } from './abac.js';

/**
 * Minimal data-access interface required by the authorization engine.
 * Implement this interface to connect any database or ORM to the authz system.
 *
 * @example
 * // Custom Drizzle adapter
 * const drizzleAdapter: AuthzAdapter = {
 *   async getUserPermissions(userId) { ... },
 *   async getPoliciesForContext(action, resourceType) { ... },
 *   async getUserRoleNames(userId) { ... },
 * };
 * initAuthz({ db: drizzleAdapter });
 */
export interface AuthzAdapter {
  /**
   * Returns the full permission set for a user, merged across all assigned roles.
   * Each string uses "action:resource" format and may contain wildcards ("*") or
   * denial prefixes ("!"). The authorization engine interprets these — the adapter
   * only needs to return raw strings as stored.
   */
  getUserPermissions(userId: string): Promise<Set<string>>;

  /**
   * Returns all enabled policies that may apply to the given action and resource type,
   * sorted by priority descending.
   *
   * Implementations may filter at the database level for efficiency. Policies with
   * empty `actions` or `resources` arrays match all values and must be included.
   */
  getPoliciesForContext(action: string, resourceType: string): Promise<PolicyRecord[]>;

  /**
   * Returns the names of all roles assigned to the user.
   * Used only by `createSessionCallback` to optionally inject roles into the session.
   */
  getUserRoleNames(userId: string): Promise<string[]>;
}
