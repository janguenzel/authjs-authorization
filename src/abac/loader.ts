import type { AuthzAdapter } from '../types/adapter.js';
import type { PolicyRecord } from '../types/abac.js';
import type { PolicyCache } from '../cache/permission-cache.js';

/**
 * Loads ABAC policies applicable to the given action and resource type,
 * using the PolicyCache as L1.
 */
export async function loadPolicies(
  action: string,
  resourceType: string,
  db: AuthzAdapter,
  cache: PolicyCache,
): Promise<PolicyRecord[]> {
  const cached = cache.get(action, resourceType);
  if (cached !== undefined) return cached;

  const policies = await db.getPoliciesForContext(action, resourceType);
  cache.set(action, resourceType, policies);
  return policies;
}
