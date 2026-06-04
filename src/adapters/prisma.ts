import type { PrismaClient } from '@prisma/client';
import type { AuthzAdapter } from '../types/adapter.js';
import type { PolicyRecord } from '../types/abac.js';

/**
 * Creates an {@link AuthzAdapter} backed by a Prisma client.
 *
 * Pass the returned adapter to `initAuthz` as the `db` option:
 *
 * @example
 * import { initAuthz } from '@janguenzel/authjs-authorization';
 * import { createPrismaAdapter } from '@janguenzel/authjs-authorization/prisma';
 * import { prisma } from '@/lib/prisma';
 *
 * export const { authorize, can, withAuthorization } = initAuthz({
 *   db: createPrismaAdapter(prisma),
 *   auth,
 * });
 */
export function createPrismaAdapter(prisma: PrismaClient): AuthzAdapter {
  return {
    async getUserPermissions(userId: string): Promise<Set<string>> {
      const userRoles = await prisma.userRole.findMany({
        where: { userId },
        include: {
          role: {
            include: {
              permissions: {
                include: {
                  permission: {
                    select: { action: true, resource: true },
                  },
                },
              },
            },
          },
        },
      });

      const permissions = new Set<string>();
      for (const ur of userRoles) {
        for (const rp of ur.role.permissions) {
          permissions.add(`${rp.permission.action}:${rp.permission.resource}`);
        }
      }
      return permissions;
    },

    async getPoliciesForContext(
      action: string,
      resourceType: string,
    ): Promise<PolicyRecord[]> {
      const policies = await prisma.policy.findMany({
        where: { enabled: true },
        orderBy: { priority: 'desc' },
      });

      // DB-level pre-filter isn't straightforward for "empty = all" semantics,
      // so we do a lightweight JS filter on the already-indexed result set.
      return policies.filter(
        (p) =>
          (p.actions.length === 0 || p.actions.includes(action)) &&
          (p.resources.length === 0 || p.resources.includes(resourceType)),
      ) as PolicyRecord[];
    },

    async getUserRoleNames(userId: string): Promise<string[]> {
      const userRoles = await prisma.userRole.findMany({
        where: { userId },
        include: { role: { select: { name: true } } },
      });
      return userRoles.map((ur) => ur.role.name);
    },
  };
}
