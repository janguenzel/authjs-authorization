/**
 * Example: Initialize the authz system once at application startup.
 *
 * Export the bound helpers from a shared module so every route/action
 * can import them without re-creating caches.
 */
import { PrismaClient } from '@prisma/client';
import { initAuthz } from '@janguenzel/authjs-authorization';
import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';

const prisma = new PrismaClient();

export const { authorize, authorizeWithResult, can, cache } = initAuthz({
  db: createPrismaAdapter(prisma),
  cache: {
    ttlMs: 5 * 60 * 1000, // 5 minutes
    maxSize: 2000,
  },
});

/**
 * Example: Seed roles with wildcard and negative permissions.
 *
 * Permission format: { action, resource }
 *   - Wildcard "*" in either field matches any value
 *   - "!" prefix on action explicitly denies (always wins over any allow)
 */
async function seedPermissions() {
  await prisma.permission.createMany({
    data: [
      // ── Admin: unrestricted access ─────────────────────────────────────
      { action: '*',       resource: '*'       }, // allow everything

      // ── Editor: full post control except deletion ──────────────────────
      { action: '*',       resource: 'post'    }, // allow all actions on post
      { action: '!delete', resource: 'post'    }, // but deny delete

      // ── Viewer: read-only on all resources ─────────────────────────────
      { action: 'read',    resource: '*'       },

      // ── Moderator: manage comments but not delete users ────────────────
      { action: '*',       resource: 'comment' },
      { action: '!delete', resource: 'user'    },
    ],
    skipDuplicates: true,
  });
}
