import type { AuthzAdapter } from '../types/adapter.js';
import type { ParsedPermissions } from '../types/rbac.js';
import type { PermissionCache } from '../cache/permission-cache.js';
import { parsePermissions } from './matcher.js';

/**
 * Loads the parsed permission set for a user, using the cache as L1.
 * On a cache miss, fetches raw strings from the adapter, parses them into
 * four buckets (exactAllows, wildcardAllows, exactDenies, wildcardDenies),
 * and caches the result.
 */
export async function loadUserPermissions(
  userId: string,
  db: AuthzAdapter,
  cache: PermissionCache,
): Promise<ParsedPermissions> {
  const cached = cache.get(userId);
  if (cached !== undefined) return cached;

  const raw = await db.getUserPermissions(userId);
  const parsed = parsePermissions(raw);
  cache.set(userId, parsed);
  return parsed;
}
