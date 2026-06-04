/**
 * Example: Seeding ABAC policies using Prisma
 *
 * Run this once (or as part of your seed script) to populate the Policy table.
 * JSON Logic rules are evaluated against ABACEvalContext:
 *   { user: { id, email, roles, ... }, resource: { type, id, ownerId, ... },
 *     action: string, context: { ip, timestamp, hour, ... } }
 */
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function seedPolicies() {
  await prisma.policy.createMany({
    skipDuplicates: true,
    data: [
      // ── Ownership: editors can update/delete their own posts ──────────────
      {
        name: 'editor-own-post-write',
        description: 'Editors may update or delete posts they authored',
        effect: 'allow',
        actions: ['update', 'delete'],
        resources: ['post'],
        priority: 10,
        conditions: {
          '===': [{ var: 'user.id' }, { var: 'resource.ownerId' }],
        },
      },

      // ── Time restriction: deny all writes outside 09:00–18:00 ─────────────
      {
        name: 'business-hours-write-only',
        description: 'Deny write operations outside business hours (9–18)',
        effect: 'deny',
        actions: ['create', 'update', 'delete', 'publish'],
        resources: [],  // applies to all resource types
        priority: 100,  // high priority — evaluated first
        conditions: {
          or: [
            { '<': [{ var: 'context.hour' }, 9] },
            { '>=': [{ var: 'context.hour' }, 18] },
          ],
        },
      },

      // ── Sensitivity: only admins can access confidential resources ────────
      {
        name: 'confidential-resource-admin-only',
        description: 'Only users with "admin" role can access confidential resources',
        effect: 'allow',
        actions: [],   // all actions
        resources: [],
        priority: 20,
        conditions: {
          and: [
            { '===': [{ var: 'resource.attributes.sensitivity' }, 'confidential'] },
            { in: ['admin', { var: 'user.roles' }] },
          ],
        },
      },

      // ── IP allowlist: restrict admin operations to internal network ────────
      {
        name: 'admin-ops-internal-network',
        description: 'Admin-level actions require an internal IP',
        effect: 'deny',
        actions: ['admin:access'],
        resources: [],
        priority: 50,
        conditions: {
          '!': {
            in: [
              { var: 'context.ip' },
              ['10.0.0.1', '10.0.0.2', '192.168.1.100'],
            ],
          },
        },
      },
    ],
  });

  console.log('Policies seeded.');
  await prisma.$disconnect();
}

seedPolicies().catch(console.error);
