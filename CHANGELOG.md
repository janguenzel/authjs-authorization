# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `resource` option in `createWithAuthorization` now accepts an async function (`(req: NextRequest) => Promise<ResourceDescriptor>`), enabling dynamic resource resolution in async contexts.

## [0.1.0] - 2026-06-04

Initial public release.

### Added

#### Core authorization

- `initAuthz(config)` factory function — initializes the authorization system and returns a bound instance with shared caches and database client
- `authorize(options)` — main authorization function combining RBAC and ABAC; returns `boolean`
- `authorizeWithResult(options)` — same as `authorize` but returns a detailed `AuthzResult` with a `reason` field (`rbac-allowed | rbac-denied | abac-allowed | abac-denied | no-session`)
- Two `abacMode` options for hybrid authorization:
  - `"fallback"` (default) — RBAC grant immediately allows; ABAC only runs on RBAC deny and can expand access
  - `"constraint"` — RBAC deny immediately denies; after RBAC grants, ABAC can restrict further; ABAC `no-match` honors the RBAC grant

#### Database adapter layer

- Introduced `AuthzAdapter` interface — the authorization engine now depends only on this minimal three-method abstraction, not on any specific ORM or database
- `createPrismaAdapter(prisma: PrismaClient): AuthzAdapter` — default Prisma implementation, exported from the new `@janguenzel/authjs-authorization/prisma` subpath
- `@prisma/client` is now an optional peer dependency; non-Prisma projects no longer need it installed
- **Migration:** replace `db: prisma` with `db: createPrismaAdapter(prisma)` in `initAuthz` and `createSessionCallback` calls
- Custom adapters can be created by implementing `AuthzAdapter` (Drizzle, MongoDB, SQL, etc.)

#### RBAC engine

- Role-based permission resolution using `action:resource` permission strings (e.g. `create:post`, `delete:post`)
- Wildcard support in either position: `*:post` (any action on post), `create:*` (create on any resource), `*:*` (global allow)
- Explicit denial via `!` prefix on the `action` field: `!delete:post`, `!*:post`, `!*:*` — deny always overrides any allow
- Multi-role support — permissions from all assigned roles are merged; a deny in any role blocks the action
- `checkRBAC(userId, action, resourceType, db, cache)` — exported for advanced use
- `ParsedPermissions` internal type — raw permission strings are parsed into four evaluation buckets on first cache load (exactAllows, wildcardAllows, exactDenies, wildcardDenies); subsequent checks within the TTL window are O(1) for exact matches

#### ABAC engine

- JSON Logic policy evaluation ([json-logic-js](https://www.npmjs.com/package/json-logic-js))
- Policies stored in the database (`Policy` table) with JSON Logic `conditions`
- Three-state decision: `allow | deny | no-match` — absence of a matching policy is distinct from an explicit deny
- Policy `priority` field — higher priority evaluated first
- Pre-filter arrays (`actions`, `resources`) for efficient policy loading; empty array means "match all"
- Policies are evaluated against a rich context: `user`, `resource`, `action`, `context` (IP, hour, timestamp, custom)
- `checkABAC(evalCtx, db, cache)` — exported for advanced use

#### Caching

- Built-in `LRUCache<K, V>` — Map-backed LRU eviction with configurable TTL and max size
- `PermissionCache` — caches resolved per-user permission sets (key: `userId`)
- `PolicyCache` — caches loaded policy lists (key: `action:resourceType`)
- `cache.permissions.invalidate(userId)` — invalidate a single user's cache after role changes
- Cache configuration via `initAuthz({ cache: { enabled, ttlMs, maxSize } })`

#### Prisma schema extensions

- `Role` model — named roles with description
- `Permission` model — `action + resource` pairs with unique constraint
- `UserRole` join table — many-to-many user ↔ role assignment with `@@index([userId])`
- `RolePermission` join table — many-to-many role ↔ permission assignment
- `Policy` model — ABAC rules with JSON Logic `conditions`, `priority`, `effect`, `enabled`, and pre-filter arrays
- Auth.js `User` model extended with `userRoles UserRole[]` relation only; all other Auth.js tables untouched

#### Fluent API

- `can(session).do(action).on(resource)` — chainable authorization builder
- `.withContext(context)` — attach runtime context to the check
- `.withMode(abacMode)` — override ABAC mode per call
- `.check()` → `Promise<boolean>`
- `.allow()` → `Promise<void>` — throws `AuthzError` when denied
- `AuthzError` — typed error class with `name: 'AuthzError'`

#### Next.js integration (`@janguenzel/authjs-authorization/nextjs`)

- `withAuthorization(handler, options)` — HOF wrapping App Router route handlers; handles session retrieval, authorization check, and 401/403 responses
- `createSessionCallback(db)` — Auth.js session callback that injects `user.id` and `user.roles` into the session; errors are swallowed to never break sign-in
- `GetSessionFn` type — for custom session retrieval in `withAuthorization`

#### TypeScript

- Full strict TypeScript (strict mode + `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`)
- `ExtendedSessionUser` — merge type for `declare module 'next-auth'` augmentation
- `AuthzSessionUser` — base shape for session user with `id` and optional `roles`
- `ResourceDescriptor` — typed resource shape with `type`, `id`, `ownerId`, `attributes`
- `RequestContext` — typed context with `ip`, `userAgent`, `timestamp`, `hour`, `custom`
- `ABACMode`, `AuthzOptions`, `AuthzResult`, `AuthzConfig`, `AuthzInstance` — all exported
- `PolicyRecord`, `ABACEvalContext`, `RoleRecord`, `PermissionRecord` — exported for advanced use
- Dual ESM + CJS output with `.d.ts` and `.d.cts` declarations
