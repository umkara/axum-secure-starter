/**
 * Three tables, and the split between them is the example.
 *
 * `session` holds what Bastion issued. `author` and `post` are the blog's own,
 * and they key on Bastion's user id rather than owning an identity of their
 * own — so there is exactly one source of truth for who somebody is.
 */

import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

/**
 * A signed-in browser, and the Bastion token pair behind it.
 *
 * `id` is what the cookie carries: 32 random bytes, meaningless on its own. The
 * tokens are sealed at rest (`lib/seal.ts`) so a stolen database file is not a
 * stolen set of live sessions.
 *
 * `generation` and `lockedUntil` are the refresh lease. See `lib/session.ts` —
 * they are the reason two concurrent requests cannot both spend the refresh
 * token and get the whole family revoked.
 */
export const session = sqliteTable(
  "session",
  {
    id: text("id").primaryKey(),
    bastionUserId: text("bastion_user_id").notNull(),
    email: text("email").notNull(),
    role: text("role", { enum: ["user", "admin"] })
      .notNull()
      .default("user"),

    accessToken: text("access_token").notNull(),
    refreshToken: text("refresh_token").notNull(),
    accessTokenExpiresAt: integer("access_token_expires_at").notNull(),

    generation: integer("generation").notNull().default(0),
    lockedUntil: integer("locked_until"),
    /**
     * `poisoned` is not a synonym for `revoked`. It means a refresh left this
     * process and the outcome is unknown: retrying might be replay, so the
     * session is abandoned rather than risked.
     */
    status: text("status", { enum: ["active", "revoked", "poisoned"] })
      .notNull()
      .default("active"),

    createdAt: integer("created_at")
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (table) => [index("session_bastion_user").on(table.bastionUserId)],
);

/** The public face of an account. Created on first sign-in. */
export const author = sqliteTable("author", {
  bastionUserId: text("bastion_user_id").primaryKey(),
  handle: text("handle").notNull().unique(),
  displayName: text("display_name").notNull(),
  bio: text("bio").notNull().default(""),
  createdAt: integer("created_at")
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
});

export const post = sqliteTable(
  "post",
  {
    id: text("id").primaryKey(),
    authorId: text("author_id")
      .notNull()
      .references(() => author.bastionUserId, { onDelete: "cascade" }),
    slug: text("slug").notNull().unique(),
    title: text("title").notNull(),
    body: text("body").notNull(),
    /**
     * Draft or published. Every public query filters on this, and every
     * author-facing query pairs it with `authorId` — knowing a slug is not
     * permission to read an unpublished post.
     */
    published: integer("published", { mode: "boolean" }).notNull().default(false),
    publishedAt: integer("published_at"),
    createdAt: integer("created_at")
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer("updated_at")
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (table) => [
    index("post_author").on(table.authorId),
    index("post_published").on(table.published, table.publishedAt),
  ],
);

export type Session = typeof session.$inferSelect;
export type Author = typeof author.$inferSelect;
export type Post = typeof post.$inferSelect;
