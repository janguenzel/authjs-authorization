/**
 * Example: Protecting a Next.js App Router API route with withAuthorization
 *
 * Demonstrates both the HOF wrapper and direct authorize() call patterns.
 */
import { NextRequest, NextResponse } from 'next/server';
import { auth } from './auth';
import { initAuthz } from '@janguenzel/authjs-authorization';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Initialize once — auth() from your Auth.js config is passed here
const { authorize, withAuthorization } = initAuthz({ db: prisma, auth });

// ── Pattern 1: HOF wrapper ────────────────────────────────────────────────────

export const DELETE = withAuthorization(
  async (req: NextRequest) => {
    const { searchParams } = new URL(req.url);
    const postId = searchParams.get('id');
    // ... delete logic
    return NextResponse.json({ deleted: postId });
  },
  {
    action: 'delete',
    // Dynamic resource descriptor derived from the request
    resource: (req) => {
      const postId = new URL(req.url).searchParams.get('id') ?? '';
      return { type: 'post', id: postId };
    },
    abacMode: 'constraint', // RBAC grants, ABAC can still restrict
  },
);

// ── Pattern 2: Inline authorize() call ───────────────────────────────────────

export async function GET(_req: NextRequest) {
  const session = await auth();

  const allowed = await authorize({
    session,
    action: 'read',
    resource: 'post',
  });

  if (!allowed) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }

  return NextResponse.json({ posts: [] });
}
