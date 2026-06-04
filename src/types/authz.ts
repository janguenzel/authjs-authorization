import type { Session } from 'next-auth';

export type ABACMode = 'fallback' | 'constraint';

export interface ResourceDescriptor {
  type: string;
  id?: string;
  ownerId?: string;
  attributes?: Record<string, unknown>;
}

export interface RequestContext {
  ip?: string;
  userAgent?: string;
  /** Unix timestamp in milliseconds */
  timestamp?: number;
  /** Hour of day (0–23) — convenience field for time-based ABAC rules */
  hour?: number;
  custom?: Record<string, unknown>;
}

export interface AuthzOptions {
  /** Auth.js session returned by auth() or getServerSession() */
  session: Session | null;
  /** The action being performed, e.g. "create", "delete", "read" */
  action: string;
  /** Resource type string or full descriptor with id/attributes */
  resource: string | ResourceDescriptor;
  /** Optional runtime context (IP, timestamp, etc.) */
  context?: RequestContext;
  /**
   * How RBAC and ABAC interact.
   * - "fallback" (default): RBAC grant → immediate allow; ABAC only runs on RBAC deny
   * - "constraint": RBAC deny → immediate deny; ABAC must also allow after RBAC grants
   */
  abacMode?: ABACMode;
}

export interface AuthzResult {
  allowed: boolean;
  reason:
    | 'no-session'
    | 'rbac-allowed'
    | 'rbac-denied'
    | 'abac-allowed'
    | 'abac-denied';
}
