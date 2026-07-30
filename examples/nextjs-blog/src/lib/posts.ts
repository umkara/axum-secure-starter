/**
 * The blog's own data. Nothing here talks to Bastion.
 *
 * One rule runs through the whole file: **every author-facing query takes the
 * author id and puts it in the `where` clause.** Not as a filter applied to the
 * results, and not only as a check in the page — knowing a post id is not
 * permission to edit it. The public queries pair with `published`, for the same
 * reason: knowing a slug is not permission to read a draft.
 */

import { randomBytes } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";

import { db } from "@/db";
import { author, post, type Author, type Post } from "@/db/schema";

export type PostWithAuthor = Post & { author: Author };

// ---------------------------------------------------------------------------
// Authors
// ---------------------------------------------------------------------------

/**
 * Creates the public profile for an account the first time it signs in.
 *
 * The handle comes from the email's local part, which is not unique, so a
 * collision gets a short suffix rather than an error — a sign-in must never
 * fail because somebody else picked the same name first.
 */
export function ensureAuthor(bastionUserId: string, email: string): Author {
  const existing = db
    .select()
    .from(author)
    .where(eq(author.bastionUserId, bastionUserId))
    .get();
  if (existing) return existing;

  const base =
    email
      .split("@")[0]
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "author";

  let handle = base;
  while (db.select().from(author).where(eq(author.handle, handle)).get()) {
    handle = `${base}-${randomBytes(2).toString("hex")}`;
  }

  return db
    .insert(author)
    .values({ bastionUserId, handle, displayName: base })
    .returning()
    .get();
}

export function authorByHandle(handle: string): Author | undefined {
  return db.select().from(author).where(eq(author.handle, handle)).get();
}

export function updateProfile(
  bastionUserId: string,
  input: { displayName: string; bio: string },
): void {
  db.update(author)
    .set({ displayName: input.displayName, bio: input.bio })
    .where(eq(author.bastionUserId, bastionUserId))
    .run();
}

// ---------------------------------------------------------------------------
// Reading — public
// ---------------------------------------------------------------------------

export function publishedPosts(limit = 20): PostWithAuthor[] {
  return db
    .select({ post, author })
    .from(post)
    .innerJoin(author, eq(post.authorId, author.bastionUserId))
    .where(eq(post.published, true))
    .orderBy(desc(post.publishedAt))
    .limit(limit)
    .all()
    .map((row) => ({ ...row.post, author: row.author }));
}

/** `published` is in the `where`, so a draft's slug returns nothing to the public. */
export function publishedPostBySlug(slug: string): PostWithAuthor | undefined {
  const row = db
    .select({ post, author })
    .from(post)
    .innerJoin(author, eq(post.authorId, author.bastionUserId))
    .where(and(eq(post.slug, slug), eq(post.published, true)))
    .get();

  return row ? { ...row.post, author: row.author } : undefined;
}

export function publishedPostsByAuthor(bastionUserId: string): Post[] {
  return db
    .select()
    .from(post)
    .where(and(eq(post.authorId, bastionUserId), eq(post.published, true)))
    .orderBy(desc(post.publishedAt))
    .all();
}

// ---------------------------------------------------------------------------
// Reading and writing — the author's own
// ---------------------------------------------------------------------------

export function postsByAuthor(bastionUserId: string): Post[] {
  return db
    .select()
    .from(post)
    .where(eq(post.authorId, bastionUserId))
    .orderBy(desc(post.updatedAt))
    .all();
}

/** Scoped by author on purpose: this is the authorisation check, not a filter. */
export function ownedPost(id: string, bastionUserId: string): Post | undefined {
  return db
    .select()
    .from(post)
    .where(and(eq(post.id, id), eq(post.authorId, bastionUserId)))
    .get();
}

function slugify(title: string): string {
  const base =
    title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 60) || "post";
  // A suffix rather than a uniqueness loop: two posts may legitimately share a
  // title, and a slug collision should not be an error the writer has to solve.
  return `${base}-${randomBytes(3).toString("hex")}`;
}

export function createPost(input: {
  authorId: string;
  title: string;
  body: string;
  publish: boolean;
}): Post {
  const now = Date.now();
  return db
    .insert(post)
    .values({
      id: randomBytes(16).toString("hex"),
      authorId: input.authorId,
      slug: slugify(input.title),
      title: input.title,
      body: input.body,
      published: input.publish,
      publishedAt: input.publish ? now : null,
      createdAt: now,
      updatedAt: now,
    })
    .returning()
    .get();
}

/** Returns the updated row, or `undefined` when the post is not this author's. */
export function updatePost(input: {
  id: string;
  authorId: string;
  title: string;
  body: string;
}): Post | undefined {
  return db
    .update(post)
    .set({ title: input.title, body: input.body, updatedAt: Date.now() })
    .where(and(eq(post.id, input.id), eq(post.authorId, input.authorId)))
    .returning()
    .get();
}

export function setPublished(input: {
  id: string;
  authorId: string;
  published: boolean;
}): Post | undefined {
  const existing = ownedPost(input.id, input.authorId);
  if (!existing) return undefined;

  return db
    .update(post)
    .set({
      published: input.published,
      // First publication stamps the date; unpublishing and republishing keeps
      // the original, so a post does not jump to the top of the feed for having
      // been edited.
      publishedAt: input.published ? (existing.publishedAt ?? Date.now()) : existing.publishedAt,
      updatedAt: Date.now(),
    })
    .where(and(eq(post.id, input.id), eq(post.authorId, input.authorId)))
    .returning()
    .get();
}

export function deletePost(id: string, bastionUserId: string): boolean {
  return (
    db
      .delete(post)
      .where(and(eq(post.id, id), eq(post.authorId, bastionUserId)))
      .returning()
      .all().length === 1
  );
}
