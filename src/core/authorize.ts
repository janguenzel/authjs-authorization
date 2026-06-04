import type { AuthzAdapter } from '../types/adapter.js';
import type { AuthzOptions, AuthzResult, ResourceDescriptor, RequestContext } from '../types/authz.js';
import type { PermissionCache, PolicyCache } from '../cache/permission-cache.js';
import { checkRBAC } from '../rbac/engine.js';
import { checkABAC } from '../abac/evaluator.js';

export interface AuthzDeps {
  db: AuthzAdapter;
  permissionCache: PermissionCache;
  policyCache: PolicyCache;
}

/**
 * Core authorization function.
 *
 * Combines RBAC and ABAC according to the requested `abacMode`:
 *
 * - "fallback" (default): RBAC grant → immediately allow.
 *   ABAC only runs when RBAC denies, and can expand access.
 *   'no-match' from ABAC = deny (RBAC is the only path to allow).
 *
 * - "constraint": RBAC deny → immediately deny.
 *   ABAC runs after RBAC grants and can restrict further.
 *   'no-match' from ABAC = honor the RBAC grant (ABAC is silent = allow).
 *   Only an explicit ABAC 'deny' overrides the RBAC grant.
 */
export async function authorize(
  options: AuthzOptions,
  deps: AuthzDeps,
): Promise<boolean> {
  const { session, action, resource, context, abacMode = 'fallback' } = options;

  if (!session?.user?.id) return false;

  const userId = session.user.id;
  const resourceDescriptor: ResourceDescriptor =
    typeof resource === 'string' ? { type: resource } : resource;

  const rbacAllowed = await checkRBAC(
    userId,
    action,
    resourceDescriptor.type,
    deps.db,
    deps.permissionCache,
  );

  const evalCtx = buildEvalCtx(session.user as ABACUser, resourceDescriptor, action, context);

  if (abacMode === 'fallback') {
    if (rbacAllowed) return true;
    // ABAC can grant; 'no-match' means deny (RBAC already denied)
    const abacDecision = await checkABAC(evalCtx, deps.db, deps.policyCache);
    return abacDecision === 'allow';
  }

  // constraint mode: RBAC must grant first
  if (!rbacAllowed) return false;
  // ABAC can restrict: only an explicit 'deny' overrides the RBAC grant
  const abacDecision = await checkABAC(evalCtx, deps.db, deps.policyCache);
  return abacDecision !== 'deny';
}

/** Authorizes and returns a detailed result object instead of a plain boolean */
export async function authorizeWithResult(
  options: AuthzOptions,
  deps: AuthzDeps,
): Promise<AuthzResult> {
  const { session, action, resource, context, abacMode = 'fallback' } = options;

  if (!session?.user?.id) {
    return { allowed: false, reason: 'no-session' };
  }

  const userId = session.user.id;
  const resourceDescriptor: ResourceDescriptor =
    typeof resource === 'string' ? { type: resource } : resource;

  const rbacAllowed = await checkRBAC(
    userId,
    action,
    resourceDescriptor.type,
    deps.db,
    deps.permissionCache,
  );

  const evalCtx = buildEvalCtx(session.user as ABACUser, resourceDescriptor, action, context);

  if (abacMode === 'fallback') {
    if (rbacAllowed) return { allowed: true, reason: 'rbac-allowed' };
    const abacDecision = await checkABAC(evalCtx, deps.db, deps.policyCache);
    const allowed = abacDecision === 'allow';
    return { allowed, reason: allowed ? 'abac-allowed' : 'abac-denied' };
  }

  // constraint mode
  if (!rbacAllowed) return { allowed: false, reason: 'rbac-denied' };
  const abacDecision = await checkABAC(evalCtx, deps.db, deps.policyCache);
  const allowed = abacDecision !== 'deny';
  return {
    allowed,
    reason: abacDecision === 'deny' ? 'abac-denied' : 'rbac-allowed',
  };
}

// Internal helper type — the session.user shape we pass to ABAC
type ABACUser = {
  id: string;
  email?: string | null;
  name?: string | null;
  roles?: string[];
  [key: string]: unknown;
};

function buildEvalCtx(
  user: ABACUser,
  resource: ResourceDescriptor,
  action: string,
  context: RequestContext | undefined,
): import('../types/abac.js').ABACEvalContext {
  const ctx: import('../types/abac.js').ABACEvalContext = { user, resource, action };
  if (context !== undefined) ctx.context = context;
  return ctx;
}
