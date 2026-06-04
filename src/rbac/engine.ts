import type { AuthzAdapter } from '../types/adapter.js';
import type { PermissionCache } from '../cache/permission-cache.js';
import { loadUserPermissions } from './loader.js';
import { hasPermission } from './matcher.js';

/**
 * Checks whether a user has RBAC permission to perform an action on a resource type.
 *
 * Permission format: "action:resourceType" (e.g. "create:post", "delete:comment")
 * Wildcards: "*" in either position matches any value ("*:post", "create:*", "*:*")
 * Negation: "!" prefix on the action field explicitly denies ("!delete:post", "!*:post")
 * Deny always takes precedence over any allow, regardless of specificity.
 */
export async function checkRBAC(
  userId: string,
  action: string,
  resourceType: string,
  db: AuthzAdapter,
  cache: PermissionCache,
): Promise<boolean> {
  const permissions = await loadUserPermissions(userId, db, cache);
  return hasPermission(permissions, action, resourceType);
}
