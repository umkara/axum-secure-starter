/**
 * BetterAuth's tables, plus the `bastionCredential` table the plugin declares.
 *
 * This mirrors `src/lib/bastion/schema.ts` by hand rather than generating it,
 * so the shape stays visible in one place. Regenerate with
 * `npx @better-auth/cli generate` if you change the plugin's schema.
 *
 * All timestamps are `timestamp_ms` — milliseconds since epoch — because
 * `lib/bastion/store.ts` writes `Date.now()` straight into these columns.
 * Drizzle's plain `timestamp` mode is *seconds*, and mixing the two would put
 * expiry dates in 1970.
 */

import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const user = sqliteTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: integer("emailVerified", { mode: "boolean" }).notNull().default(false),
  image: text("image"),

  /** Bastion's uuid. Written server-side only — see the plugin's schema. */
  bastionUserId: text("bastionUserId").unique(),
  /** Mirror of the JWT `role` claim, so `/admin` needs no Bastion call. */
  role: text("role").notNull().default("user"),

  createdAt: integer("createdAt", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp_ms" }).notNull(),
});

export const session = sqliteTable("session", {
  id: text("id").primaryKey(),
  token: text("token").notNull().unique(),
  userId: text("userId")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  expiresAt: integer("expiresAt", { mode: "timestamp_ms" }).notNull(),
  ipAddress: text("ipAddress"),
  userAgent: text("userAgent"),
  createdAt: integer("createdAt", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp_ms" }).notNull(),
});

export const account = sqliteTable("account", {
  id: text("id").primaryKey(),
  accountId: text("accountId").notNull(),
  providerId: text("providerId").notNull(),
  userId: text("userId")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  accessToken: text("accessToken"),
  refreshToken: text("refreshToken"),
  idToken: text("idToken"),
  accessTokenExpiresAt: integer("accessTokenExpiresAt", { mode: "timestamp_ms" }),
  refreshTokenExpiresAt: integer("refreshTokenExpiresAt", { mode: "timestamp_ms" }),
  scope: text("scope"),
  password: text("password"),
  createdAt: integer("createdAt", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp_ms" }).notNull(),
});

export const verification = sqliteTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: integer("expiresAt", { mode: "timestamp_ms" }).notNull(),
  createdAt: integer("createdAt", { mode: "timestamp_ms" }).notNull(),
  updatedAt: integer("updatedAt", { mode: "timestamp_ms" }).notNull(),
});

/**
 * One row per session — see `lib/bastion/schema.ts` for why it is not one row
 * per user. `ON DELETE CASCADE` means BetterAuth expiring a session also drops
 * the credential, so a stale token pair cannot outlive the session that owned it.
 */
export const bastionCredential = sqliteTable(
  "bastionCredential",
  {
    id: text("id").primaryKey(),
    sessionId: text("sessionId")
      .notNull()
      .unique()
      .references(() => session.id, { onDelete: "cascade" }),
    bastionUserId: text("bastionUserId").notNull(),
    /** AES-256-GCM sealed. */
    accessToken: text("accessToken").notNull(),
    /** AES-256-GCM sealed. */
    refreshToken: text("refreshToken").notNull(),
    accessTokenExpiresAt: integer("accessTokenExpiresAt", { mode: "timestamp_ms" }).notNull(),
    /** Compare-and-swap target for the refresh lease. */
    generation: integer("generation").notNull().default(0),
    lockedUntil: integer("lockedUntil", { mode: "timestamp_ms" }),
    /** `active` | `revoked` | `poisoned`. */
    status: text("status").notNull().default("active"),
    createdAt: integer("createdAt", { mode: "timestamp_ms" })
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    updatedAt: integer("updatedAt", { mode: "timestamp_ms" })
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (table) => [index("bastionCredential_bastionUserId_idx").on(table.bastionUserId)],
);
