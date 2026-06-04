import type { PolicyRecord } from '../types/abac.js';

/**
 * Filters a list of policies to those that match the given action and resource type.
 * Policies with empty `actions` or `resources` arrays match everything.
 * Results are already sorted by priority DESC (from the DB query).
 */
export function filterPolicies(
  policies: PolicyRecord[],
  action: string,
  resourceType: string,
): PolicyRecord[] {
  return policies.filter(
    (p) =>
      p.enabled &&
      (p.actions.length === 0 || p.actions.includes(action)) &&
      (p.resources.length === 0 || p.resources.includes(resourceType)),
  );
}
