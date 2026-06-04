import type { ParsedPermissions } from '../types/rbac.js';

/**
 * Splits a flat Set of raw permission strings into four evaluation buckets.
 * Called once on a cache miss; the result is stored in the permission cache.
 *
 * Permission string format: "action:resource"
 * Prefix "!" → deny   (e.g. "!delete:post")
 * Value  "*" → wildcard in that position (e.g. "*:post", "create:*", "*:*")
 * Bare   "*" → global wildcard (no colon needed)
 */
export function parsePermissions(raw: Set<string>): ParsedPermissions {
  const exactAllows: Set<string> = new Set();
  const wildcardAllows: string[] = [];
  const exactDenies: Set<string> = new Set();
  const wildcardDenies: string[] = [];

  for (const entry of raw) {
    const negated = entry.startsWith('!');
    const perm = negated ? entry.slice(1) : entry;
    const hasWildcard = perm.includes('*');

    if (negated) {
      if (hasWildcard) wildcardDenies.push(perm);
      else exactDenies.add(perm);
    } else {
      if (hasWildcard) wildcardAllows.push(perm);
      else exactAllows.add(perm);
    }
  }

  return { exactAllows, wildcardAllows, exactDenies, wildcardDenies };
}

/**
 * Returns true if the action:resource combination is permitted by the parsed set.
 *
 * Precedence (deny-first):
 *   1. Exact deny   → false
 *   2. Wildcard deny → false
 *   3. Exact allow  → true
 *   4. Wildcard allow → true
 *   5. No match     → false
 */
export function hasPermission(
  parsed: ParsedPermissions,
  action: string,
  resource: string,
): boolean {
  const target = `${action}:${resource}`;
  if (isDenied(parsed, action, resource, target)) return false;
  return isAllowed(parsed, action, resource, target);
}

function isDenied(
  parsed: ParsedPermissions,
  action: string,
  resource: string,
  target: string,
): boolean {
  if (parsed.exactDenies.has(target)) return true;
  for (const pattern of parsed.wildcardDenies) {
    if (matchesWildcardPattern(pattern, action, resource)) return true;
  }
  return false;
}

function isAllowed(
  parsed: ParsedPermissions,
  action: string,
  resource: string,
  target: string,
): boolean {
  if (parsed.exactAllows.has(target)) return true;
  for (const pattern of parsed.wildcardAllows) {
    if (matchesWildcardPattern(pattern, action, resource)) return true;
  }
  return false;
}

/**
 * Returns true if the wildcard pattern matches the given action and resource.
 * Bare "*" (no colon) is treated as a global wildcard equivalent to "*:*".
 * Patterns without a colon that are not "*" are malformed and return false.
 */
function matchesWildcardPattern(pattern: string, action: string, resource: string): boolean {
  if (pattern === '*') return true;

  const colonIdx = pattern.indexOf(':');
  if (colonIdx === -1) return false;

  const pAction = pattern.slice(0, colonIdx);
  const pResource = pattern.slice(colonIdx + 1);

  return (pAction === '*' || pAction === action) && (pResource === '*' || pResource === resource);
}
