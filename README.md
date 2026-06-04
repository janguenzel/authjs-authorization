# @janguenzel/authjs-authorization

**Flexible RBAC + ABAC authorization layer for [Auth.js](https://authjs.dev) (NextAuth v5)**

[![CI](https://github.com/janguenzel/authjs-authorization/actions/workflows/ci.yml/badge.svg)](https://github.com/janguenzel/authjs-authorization/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@janguenzel/authjs-authorization)](https://www.npmjs.com/package/@janguenzel/authjs-authorization)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Auth.js handles authentication beautifully — but it ships no authorization primitives. This package adds a production-ready authorization layer on top of your existing Auth.js setup, reusing its session and Prisma adapter without touching any Auth.js internals.

---

## Features

- **RBAC** — Users → Roles → Permissions (`action:resource` format, wildcards, and explicit denials)
- **ABAC** — JSON Logic policies stored in your database, evaluated at runtime
- **Hybrid** — Two modes: ABAC as a fallback expander or as a constraint on top of RBAC
- **LRU Cache** — Built-in two-tier cache (per-user permissions + per-action policies) with configurable TTL
- **Next.js helpers** — `withAuthorization` HOF for App Router route handlers
- **Fluent API** — `can(session).do('delete').on({ type: 'post', id }).check()`
- **Auth.js integration** — Optional session callback injects roles into the Auth.js session
- **Prisma schema** — Additive schema extensions; never modifies Auth.js tables
- **TypeScript-first** — Strict mode, full type declarations, module augmentation helpers

---

## Installation

```bash
npm install @janguenzel/authjs-authorization
```

### Peer dependencies

| Package | Required | Notes |
|---------|----------|-------|
| `next-auth` | ✅ Yes | `>=5.0.0-beta.0` (Auth.js v5 beta) |
| `@prisma/client` | ⚠️ Optional | `>=5.0.0` — only when using `createPrismaAdapter` |
| `next` | ⚠️ Optional | `>=14.0.0` — only for `withAuthorization` |

---

## Quick Start

### 1. Add the Prisma models

Add the authorization models to your existing `schema.prisma`. Copy from [`prisma/schema.prisma`](prisma/schema.prisma) or add them manually:

```prisma
// Add this relation to your existing User model:
model User {
  // ... existing fields
  userRoles UserRole[]
}

// New authorization models:
model Role {
  id          String           @id @default(cuid())
  name        String           @unique
  description String?
  userRoles   UserRole[]
  permissions RolePermission[]
  createdAt   DateTime         @default(now())
  updatedAt   DateTime         @updatedAt
}

model Permission {
  id              String           @id @default(cuid())
  action          String
  resource        String
  rolePermissions RolePermission[]
  @@unique([action, resource])
}

model UserRole {
  userId     String
  roleId     String
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  role       Role     @relation(fields: [roleId], references: [id], onDelete: Cascade)
  assignedAt DateTime @default(now())
  @@id([userId, roleId])
  @@index([userId])
}

model RolePermission {
  roleId       String
  permissionId String
  role         Role       @relation(fields: [roleId], references: [id], onDelete: Cascade)
  permission   Permission @relation(fields: [permissionId], references: [id], onDelete: Cascade)
  @@id([roleId, permissionId])
}

model Policy {
  id          String   @id @default(cuid())
  name        String   @unique
  effect      String   // "allow" | "deny"
  actions     String[] // empty = all actions
  resources   String[] // empty = all resource types
  conditions  Json     // JSON Logic rule
  priority    Int      @default(0)
  enabled     Boolean  @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  @@index([enabled])
}
```

Then run `npx prisma migrate dev`.

### 2. Initialize authz

Create a shared module that initializes authz once at startup:

```ts
// lib/authz.ts
import { initAuthz } from '@janguenzel/authjs-authorization';
import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';
import { auth } from '@/auth'; // your Auth.js config
import { prisma } from '@/lib/prisma';

export const { authorize, authorizeWithResult, withAuthorization, can, cache } = initAuthz({
  db: createPrismaAdapter(prisma),
  auth,   // required for withAuthorization to retrieve the session
  cache: {
    ttlMs: 5 * 60 * 1000, // 5 minutes
    maxSize: 1000,
  },
});
```

### 3. Protect a route

```ts
// app/api/posts/route.ts
import { authorize } from '@/lib/authz';
import { auth } from '@/auth';

export async function DELETE(req: Request) {
  const session = await auth();

  if (!await authorize({ session, action: 'delete', resource: 'post' })) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // ... delete logic
  return Response.json({ ok: true });
}
```

---

## Prisma Schema

The full additive schema is in [`prisma/schema.prisma`](prisma/schema.prisma). The key points:

- **Auth.js tables are untouched** — only a `userRoles UserRole[]` relation is added to `User`
- **`Permission`** stores individual `action + resource` pairs (e.g. `create` + `post`)
- **`Role`** groups permissions; users can have multiple roles via `UserRole`
- **`Policy`** stores ABAC rules as JSON Logic expressions with pre-filter arrays

---

## Core Concepts

### RBAC

Roles map to permissions. A permission is an `action:resource` pair stored in the `Permission` table. The `action` and `resource` columns both support wildcards (`*`) and the `action` column supports a denial prefix (`!`):

```ts
// Exact permission — allow create on post
{ action: 'create', resource: 'post' }

// Wildcard resource — allow create on any resource
{ action: 'create', resource: '*' }

// Wildcard action — allow any action on post
{ action: '*', resource: 'post' }

// Global wildcard — allow everything
{ action: '*', resource: '*' }

// Explicit deny — deny delete on post (overrides any allow)
{ action: '!delete', resource: 'post' }

// Wildcard deny — deny all actions on post
{ action: '!*', resource: 'post' }
```

**Deny always takes precedence over any allow, regardless of specificity.** A user with `{ action: '*', resource: '*' }` and `{ action: '!delete', resource: 'post' }` can do anything *except* delete a post.

#### Seeding example

```ts
await prisma.permission.createMany({
  data: [
    // Admin: everything
    { action: '*',       resource: '*'    },

    // Editor: all post operations except delete
    { action: '*',       resource: 'post' },
    { action: '!delete', resource: 'post' },

    // Viewer: read-only on everything
    { action: 'read',    resource: '*'    },
  ],
  skipDuplicates: true,
});
```

#### Permission precedence rules

| Pattern | Matches |
|---------|---------|
| `action:resource` | Exact match only |
| `*:resource` | Any action on that resource |
| `action:*` | That action on any resource |
| `*:*` | Everything |
| `!action:resource` | Deny exact (overrides any allow) |
| `!*:resource` | Deny all actions on that resource |
| `!action:*` | Deny that action on all resources |
| `!*:*` | Deny everything |

### ABAC

Policies are JSON Logic rules stored in the database. They are evaluated against a context object:

```json
{
  "user":     { "id": "...", "email": "...", "roles": ["editor"] },
  "resource": { "type": "post", "id": "...", "ownerId": "..." },
  "action":   "delete",
  "context":  { "ip": "...", "hour": 14, "timestamp": 1234567890 }
}
```

### ABAC modes

The `abacMode` option controls how RBAC and ABAC interact:

| Mode | Behavior |
|------|----------|
| `"fallback"` (default) | RBAC grant → **immediately allow**. ABAC only runs when RBAC denies, and can grant access. |
| `"constraint"` | RBAC deny → **immediately deny**. After an RBAC grant, ABAC runs and can restrict. `no-match` from ABAC honors the RBAC grant. |

---

## API Reference

### `initAuthz(config)`

Creates a bound authorization instance. Call once at startup.

```ts
const authz = initAuthz({
  db: prisma,           // PrismaClient instance
  auth,                 // Auth.js auth() function (required for withAuthorization)
  cache: {
    enabled: true,      // default: true
    ttlMs: 300_000,     // default: 5 minutes
    maxSize: 1000,      // default: 1000 entries
  },
});
```

Returns `{ authorize, authorizeWithResult, withAuthorization, can, cache }`.

---

### `authorize(options)`

```ts
const allowed: boolean = await authorize({
  session,              // Auth.js Session | null
  action: 'delete',     // string
  resource: 'post',     // string | ResourceDescriptor
  abacMode: 'fallback', // 'fallback' | 'constraint' — default: 'fallback'
  context: {            // optional runtime context
    ip: '10.0.0.1',
    hour: 14,
  },
});
```

**`ResourceDescriptor`** — use when you need ABAC to access resource attributes:

```ts
resource: { type: 'post', id: '123', ownerId: 'user-abc', attributes: { sensitivity: 'internal' } }
```

---

### `authorizeWithResult(options)`

Same signature as `authorize`, but returns a detailed result:

```ts
const result = await authorizeWithResult({ session, action: 'publish', resource: 'post' });
// { allowed: false, reason: 'rbac-denied' }
// reason: 'rbac-allowed' | 'rbac-denied' | 'abac-allowed' | 'abac-denied' | 'no-session'
```

---

### `can(session).do(action).on(resource)`

Fluent API — reads naturally in server actions:

```ts
import { can } from '@/lib/authz';

// Returns boolean
const allowed = await can(session).do('update').on({ type: 'post', id: postId }).check();

// Throws AuthzError if denied
await can(session).do('delete').on('post').withMode('constraint').allow();

// With runtime context
const allowed = await can(session)
  .do('publish')
  .on({ type: 'post', id: postId })
  .withContext({ ip: req.headers.get('x-forwarded-for') ?? '' })
  .check();
```

---

### `withAuthorization(handler, options)` — Next.js

HOF for App Router route handlers. Requires `auth` to be passed to `initAuthz`.

```ts
// app/api/posts/[id]/route.ts
import { withAuthorization } from '@/lib/authz';

export const DELETE = withAuthorization(
  async (req) => {
    // only reached if authorized
    return Response.json({ deleted: true });
  },
  {
    action: 'delete',
    resource: (req) => ({
      type: 'post',
      id: new URL(req.url).pathname.split('/').pop() ?? '',
    }),
    abacMode: 'constraint',
    onUnauthorized: () => Response.json({ error: 'Forbidden' }, { status: 403 }),
  },
);
```

---

### `createSessionCallback(db)` — Auth.js integration

Injects user ID and role names into the Auth.js session. Session roles are for **UI convenience only** — authorization decisions always use the database.

```ts
// auth.ts
import NextAuth from 'next-auth';
import { PrismaAdapter } from '@auth/prisma-adapter';
import { createSessionCallback } from '@janguenzel/authjs-authorization/nextjs';
import { prisma } from '@/lib/prisma';

export const { handlers, auth } = NextAuth({
  adapter: PrismaAdapter(prisma),
  callbacks: {
    session: createSessionCallback(prisma),
  },
});
```

---

## ABAC Policies

Policies are stored in the `Policy` table and evaluated using [JSON Logic](https://jsonlogic.com/). The `conditions` field is a JSON Logic rule evaluated against the authorization context.

### Example policies

```ts
// Allow: editors may update or delete their own posts
await prisma.policy.create({
  data: {
    name: 'editor-own-post-write',
    effect: 'allow',
    actions: ['update', 'delete'],
    resources: ['post'],
    priority: 10,
    conditions: {
      '===': [{ var: 'user.id' }, { var: 'resource.ownerId' }],
    },
  },
});

// Deny: block all writes outside business hours (09:00–18:00)
await prisma.policy.create({
  data: {
    name: 'business-hours-writes-only',
    effect: 'deny',
    actions: ['create', 'update', 'delete'],
    resources: [],    // empty = applies to all resources
    priority: 100,    // higher priority evaluated first
    conditions: {
      or: [
        { '<': [{ var: 'context.hour' }, 9] },
        { '>=': [{ var: 'context.hour' }, 18] },
      ],
    },
  },
});
```

### Context variables available in rules

| Path | Type | Description |
|------|------|-------------|
| `user.id` | `string` | User ID from session |
| `user.email` | `string \| null` | User email |
| `user.roles` | `string[]` | Role names (if `createSessionCallback` is used) |
| `resource.type` | `string` | Resource type (e.g. `"post"`) |
| `resource.id` | `string?` | Resource ID |
| `resource.ownerId` | `string?` | Resource owner ID |
| `resource.attributes.*` | `unknown` | Custom resource attributes |
| `action` | `string` | The action being checked |
| `context.ip` | `string?` | Client IP address |
| `context.hour` | `number?` | Hour of day (0–23) |
| `context.timestamp` | `number?` | Unix timestamp (ms) |
| `context.custom.*` | `unknown` | Custom context values |

---

## TypeScript

### Extending the Auth.js session type

Add a `src/types/next-auth.d.ts` (or equivalent) to get type-safe `session.user.id` and `session.user.roles`:

```ts
import type { DefaultSession } from 'next-auth';
import type { ExtendedSessionUser } from '@janguenzel/authjs-authorization';

declare module 'next-auth' {
  interface Session {
    user: ExtendedSessionUser & DefaultSession['user'];
  }
}
```

---

## Custom Database Adapters

The core authorization logic is fully database-agnostic. It depends only on the `AuthzAdapter`
interface — a plain object with three async methods:

```ts
import type { AuthzAdapter } from '@janguenzel/authjs-authorization';

const myAdapter: AuthzAdapter = {
  /** Returns "action:resource" permission strings for the user's combined roles */
  async getUserPermissions(userId: string): Promise<Set<string>> { ... },

  /** Returns enabled policies sorted by priority DESC */
  async getPoliciesForContext(action: string, resourceType: string): Promise<PolicyRecord[]> { ... },

  /** Returns role names for the user (used by createSessionCallback) */
  async getUserRoleNames(userId: string): Promise<string[]> { ... },
};

export const authz = initAuthz({ db: myAdapter });
```

The Prisma implementation ships as a separate subpath to avoid bundling `@prisma/client` for
non-Prisma projects:

```ts
import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';
initAuthz({ db: createPrismaAdapter(prisma) });
```

Implement `AuthzAdapter` for any ORM or database supported by Auth.js (Drizzle, MongoDB,
SQL adapters, etc.) and pass it to `initAuthz` — no other changes needed.

---

## Caching

Permission sets and ABAC policies are cached with a built-in LRU cache. When you change a user's roles, invalidate their cache entry:

```ts
import { cache } from '@/lib/authz';

// After updating a user's roles:
cache.permissions.invalidate(userId);

// Clear all cached permissions (e.g. after a bulk role update):
cache.permissions.clear();
cache.policies.clear();
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, development workflow, and contribution guidelines.

---

## License

[MIT](LICENSE) — Jan Henning Günzel
