import jsonLogic from 'json-logic-js';
import type { AuthzAdapter } from '../types/adapter.js';
import type { ABACEvalContext } from '../types/abac.js';
import type { PolicyCache } from '../cache/permission-cache.js';
import { loadPolicies } from './loader.js';

/** Three-state result from ABAC evaluation. */
export type ABACDecision = 'allow' | 'deny' | 'no-match';

/**
 * Evaluates ABAC policies for the given context.
 *
 * Iterates policies in priority order (highest first). The first policy
 * whose JSON Logic conditions evaluate to `true` determines the outcome.
 *
 * Returns `'no-match'` when no policy matches, letting the caller decide
 * what the absence of a policy means (varies between fallback and constraint mode).
 */
export async function checkABAC(
  evalCtx: ABACEvalContext,
  db: AuthzAdapter,
  cache: PolicyCache,
): Promise<ABACDecision> {
  const { action, resource } = evalCtx;
  const policies = await loadPolicies(action, resource.type, db, cache);

  // Build the data object that JSON Logic rules can reference via "var"
  const data: Record<string, unknown> = {
    user: evalCtx.user,
    resource: evalCtx.resource,
    action: evalCtx.action,
    context: evalCtx.context ?? {},
  };

  for (const policy of policies) {
    let result: unknown;
    try {
      result = jsonLogic.apply(policy.conditions as Parameters<typeof jsonLogic.apply>[0], data);
    } catch {
      // Malformed rule — skip this policy, don't crash the authorization check
      continue;
    }

    if (result === true) {
      return policy.effect === 'allow' ? 'allow' : 'deny';
    }
  }

  return 'no-match'; // no policy matched — caller decides the default
}
