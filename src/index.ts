// Factory
export { initAuthz } from './core/init.js';
export type { AuthzConfig, AuthzInstance } from './core/init.js';

// Adapter interface — implement to connect any database
export type { AuthzAdapter } from './types/adapter.js';

// Core types
export type {
  ABACMode,
  AuthzOptions,
  AuthzResult,
  ResourceDescriptor,
  RequestContext,
} from './types/authz.js';

// Session extension types — for consumers' next-auth.d.ts module augmentation
export type { AuthzSessionUser, ExtendedSessionUser } from './types/session.js';

// Fluent builder classes (for typing, rarely instantiated directly)
export { AuthzBuilder, ActionBuilder, ResourceBuilder, AuthzError } from './fluent/builder.js';

// Lower-level exports — useful for consumers who need fine-grained control
export { checkRBAC } from './rbac/engine.js';
export { checkABAC } from './abac/evaluator.js';
export { LRUCache } from './cache/lru.js';
export { PermissionCache, PolicyCache } from './cache/permission-cache.js';
