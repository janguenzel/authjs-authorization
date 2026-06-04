import type { Session } from 'next-auth';
import type { AuthzOptions, ResourceDescriptor, RequestContext, ABACMode } from '../types/authz.js';
import type { AuthzDeps } from '../core/authorize.js';
import { authorize } from '../core/authorize.js';

/** Entry point for the fluent API. Created by can(session). */
export class AuthzBuilder {
  constructor(
    private readonly session: Session | null,
    private readonly deps: AuthzDeps,
  ) {}

  /** Specify the action to check (e.g. "create", "delete") */
  do(action: string): ActionBuilder {
    return new ActionBuilder(this.session, action, this.deps);
  }
}

export class ActionBuilder {
  constructor(
    private readonly session: Session | null,
    private readonly action: string,
    private readonly deps: AuthzDeps,
  ) {}

  /** Specify the resource type or descriptor */
  on(resource: string | ResourceDescriptor): ResourceBuilder {
    return new ResourceBuilder(this.session, this.action, resource, this.deps);
  }
}

export class ResourceBuilder {
  private _context: RequestContext | undefined;
  private _mode: ABACMode = 'fallback';

  constructor(
    private readonly session: Session | null,
    private readonly action: string,
    private readonly resource: string | ResourceDescriptor,
    private readonly deps: AuthzDeps,
  ) {}

  /** Attach runtime context (IP, timestamp, custom attributes) */
  withContext(context: RequestContext): this {
    this._context = context;
    return this;
  }

  /** Override ABAC mode (default: "fallback") */
  withMode(mode: ABACMode): this {
    this._mode = mode;
    return this;
  }

  /** Returns true if the action is authorized */
  check(): Promise<boolean> {
    const opts: AuthzOptions = {
      session: this.session,
      action: this.action,
      resource: this.resource,
      abacMode: this._mode,
    };
    if (this._context !== undefined) opts.context = this._context;
    return authorize(opts, this.deps);
  }

  /**
   * Resolves the authorization check and throws AuthzError if denied.
   * Useful in server actions where you want to fail loudly.
   */
  async allow(): Promise<void> {
    const allowed = await this.check();
    if (!allowed) {
      throw new AuthzError(
        `Not authorized to perform "${this.action}" on "${
          typeof this.resource === 'string' ? this.resource : this.resource.type
        }"`,
      );
    }
  }
}

export class AuthzError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthzError';
  }
}
