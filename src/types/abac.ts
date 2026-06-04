import type { ResourceDescriptor, RequestContext } from './authz.js';

export interface PolicyRecord {
  id: string;
  name: string;
  description: string | null;
  effect: 'allow' | 'deny';
  /** Action pre-filter — empty means all actions */
  actions: string[];
  /** Resource type pre-filter — empty means all resource types */
  resources: string[];
  /** JSON Logic rule object */
  conditions: unknown;
  priority: number;
  enabled: boolean;
}

export interface ABACEvalContext {
  user: {
    id: string;
    email?: string | null;
    name?: string | null;
    roles?: string[];
    [key: string]: unknown;
  };
  resource: ResourceDescriptor;
  action: string;
  context?: RequestContext;
}
