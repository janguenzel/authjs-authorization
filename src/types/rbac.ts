/**
 * Pre-parsed permission set stored in the L1 cache.
 * Splitting into four buckets lets checkRBAC do O(1) exact checks
 * before falling back to the (tiny) wildcard arrays.
 */
export interface ParsedPermissions {
  exactAllows:    Set<string>;
  wildcardAllows: string[];
  exactDenies:    Set<string>;
  wildcardDenies: string[];
}

export interface RoleRecord {
  id: string;
  name: string;
  description: string | null;
}

export interface PermissionRecord {
  id: string;
  action: string;
  resource: string;
}

export interface UserRoleRecord {
  userId: string;
  roleId: string;
  role: RoleRecord;
}

export interface RoleWithPermissions extends RoleRecord {
  permissions: Array<{ permission: PermissionRecord }>;
}
