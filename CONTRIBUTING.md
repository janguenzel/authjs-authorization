# Contributing to @janguenzel/authjs-authorization

Thank you for your interest in contributing. This document explains how to set up the project, how development works, and what rules to follow when submitting changes.

## Code of Conduct

Be respectful. Constructive criticism of code is welcome; personal attacks are not. Issues and PRs that violate this will be closed.

## Prerequisites

- **Node.js** ^20.19.0 || >=22.12.0
- **npm** ≥ 9
- A **PostgreSQL** (or compatible) database for integration testing with Prisma (optional — unit tests use mocks)

## Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/janguenzel/authjs-authorization.git
cd authjs-authorization

# 2. Install dependencies
npm install

# 3. Build the package
npm run build

# 4. Run the tests
npm test
```

That's it. No database is required for the unit test suite — all database calls are mocked via Vitest.

## Project Structure

```
src/
  core/          authorize() function + initAuthz() factory
  rbac/          RBAC engine and permission loader
  abac/          ABAC evaluator, policy loader, matcher
  cache/         LRU cache and typed wrappers
  db/            Prisma queries (all DB access in one file)
  fluent/        Fluent API builder classes
  integrations/
    nextjs/      withAuthorization HOF + createSessionCallback
  types/         TypeScript types (authz, rbac, abac, session)
  index.ts       Public API barrel export

tests/           Unit tests (mirrors src/ structure)
prisma/          Prisma schema extensions
examples/        Usage examples (not part of the published package)
```

## Development Workflow

| Command | What it does |
|---------|-------------|
| `npm run build` | Compile ESM + CJS + types via tsup |
| `npm run dev` | Watch mode build |
| `npm run typecheck` | Type-check without emitting (strict mode) |
| `npm test` | Run all tests once |
| `npm run test:watch` | Run tests in watch mode |
| `npm run test:coverage` | Run tests with coverage report |
| `npm run clean` | Delete the `dist/` folder |
| `npm run release` | Cut a release on `main` (see below) |

## Feature Branch Workflow

All work happens on feature branches merged into `main`.

```
git checkout -b feat/your-feature main   # branch from main
# ... commit with conventional messages: feat:, fix:, docs:, chore:
# ... add entry under ## [Unreleased] in CHANGELOG.md
git push -u origin feat/your-feature
# open a PR → merge to main
```

Branches should be named `feat/`, `fix/`, `chore/`, or `docs/` followed by a short slug.

## Release Process

Releases are cut from `main` only, using `release-it`. Never tag or bump versions on a feature branch.

```bash
# 1. Ensure you're on main and fully up to date
git checkout main && git pull origin main

# 2. Promote [Unreleased] in CHANGELOG.md to the new version and today's date
#    e.g.  ## [Unreleased]  →  ## [0.2.0] - 2026-06-04
#    then stage it:
git add CHANGELOG.md

# 3. Run release-it with the bump type (major | minor | patch)
npm run release -- minor
#    release-it will:
#      - bump version in package.json
#      - commit both package.json and the staged CHANGELOG as "chore: release vX.Y.Z"
#      - create a git tag vX.Y.Z
#      - push the commit and tag to origin

# 4. Publish to npm
npm run build && npm publish
```

## Contribution Rules

### Before submitting

1. **All tests must pass** — `npm test` must exit 0
2. **No type errors** — `npm run typecheck` must exit 0
3. **Build must succeed** — `npm run build` must produce clean output

### Code style

- **TypeScript strict mode** — no `any`, no `!` non-null assertions without a comment explaining why
- **exactOptionalPropertyTypes** — never assign `undefined` to an optional property; use `if (x !== undefined) obj.prop = x`
- **No comments on obvious code** — only add a comment when the *why* is non-obvious (a constraint, a workaround, a subtle invariant)
- Follow the existing pattern of small, single-responsibility modules

### Tests

- Every new public API function must be accompanied by at least one test
- Tests must mock at the boundary (DB queries), not at intermediate layers
- Do not test implementation details — test observable behavior

### CHANGELOG

Update `CHANGELOG.md` for any user-facing change. Add your entry under an `## [Unreleased]` section at the top if it doesn't exist yet. Use Keep a Changelog conventions (`Added`, `Changed`, `Fixed`, `Removed`, `Deprecated`).

## Pull Request Process

1. **One feature or fix per PR** — avoid bundling unrelated changes
2. **Describe the change** — explain *what* and *why* in the PR description; link to related issues if applicable
3. **Update CHANGELOG.md** — required for any user-facing change
4. **CI must pass** — the GitHub Actions CI workflow runs typecheck, build, and tests on Node.js 20.19.x, 22.12.x, 24.x, and 26.x

## Reporting Bugs

Open an issue at [github.com/janguenzel/authjs-authorization/issues](https://github.com/janguenzel/authjs-authorization/issues). Include:

- A minimal reproduction
- Node.js version (`node --version`)
- Auth.js version (`npm list next-auth`)
- Prisma version (`npm list @prisma/client`)
- Expected vs actual behavior

## Questions

For usage questions, open a [GitHub Discussion](https://github.com/janguenzel/authjs-authorization/discussions) rather than an issue.
