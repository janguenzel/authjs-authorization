/**
 * Example: Protecting Next.js Server Actions with the fluent API
 */
'use server';

import { auth } from './auth';
import { initAuthz, AuthzError } from '@janguenzel/authjs-authorization';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const { authorize, authorizeWithResult, can } = initAuthz({ db: prisma, auth });

// ── Fluent API with allow() ───────────────────────────────────────────────────

export async function deletePost(postId: string, ownerId: string) {
  const session = await auth();

  // Throws AuthzError if denied — propagates as a server action error
  await can(session)
    .do('delete')
    .on({ type: 'post', id: postId, ownerId })
    .allow();

  // ... proceed with deletion
}

// ── Fluent API with check() ───────────────────────────────────────────────────

export async function updatePost(postId: string, data: { title: string }) {
  const session = await auth();

  const allowed = await can(session)
    .do('update')
    .on({ type: 'post', id: postId })
    .withMode('constraint') // RBAC + no explicit ABAC deny required
    .check();

  if (!allowed) {
    return { error: 'Not authorized to update this post' };
  }

  // ... update logic
  return { success: true };
}

// ── authorizeWithResult for detailed audit logging ────────────────────────────

export async function publishPost(postId: string) {
  const session = await auth();

  const result = await authorizeWithResult({
    session,
    action: 'publish',
    resource: { type: 'post', id: postId },
    abacMode: 'fallback',
  });

  if (!result.allowed) {
    console.warn(`Publish denied for ${session?.user?.id} — reason: ${result.reason}`);
    return { error: 'Forbidden' };
  }

  return { published: true };
}
