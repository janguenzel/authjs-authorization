import { LRUCache, type LRUCacheOptions } from './lru.js';
import type { ParsedPermissions } from '../types/rbac.js';
import type { PolicyRecord } from '../types/abac.js';

/**
 * Caches pre-parsed permission sets per user ID.
 * Key: userId, Value: ParsedPermissions (pre-split into allow/deny buckets)
 */
export class PermissionCache {
  private readonly inner: LRUCache<string, ParsedPermissions>;

  constructor(options?: LRUCacheOptions) {
    this.inner = new LRUCache<string, ParsedPermissions>(options);
  }

  get(userId: string): ParsedPermissions | undefined {
    return this.inner.get(userId);
  }

  set(userId: string, permissions: ParsedPermissions): void {
    this.inner.set(userId, permissions);
  }

  invalidate(userId: string): void {
    this.inner.delete(userId);
  }

  clear(): void {
    this.inner.clear();
  }
}

/**
 * Caches ABAC policy lists keyed by "action:resourceType".
 * Empty string key is used for policies that match all actions/resources.
 */
export class PolicyCache {
  private readonly inner: LRUCache<string, PolicyRecord[]>;

  constructor(options?: LRUCacheOptions) {
    this.inner = new LRUCache<string, PolicyRecord[]>(options);
  }

  get(action: string, resourceType: string): PolicyRecord[] | undefined {
    return this.inner.get(`${action}:${resourceType}`);
  }

  set(action: string, resourceType: string, policies: PolicyRecord[]): void {
    this.inner.set(`${action}:${resourceType}`, policies);
  }

  clear(): void {
    this.inner.clear();
  }
}
