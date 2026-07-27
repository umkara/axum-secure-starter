/**
 * One SQLite file, two concerns: BetterAuth's session tables and the shop's
 * own catalogue/cart/orders. They share a database because they share
 * transactions in exactly one place — checkout, which reads a cart and writes
 * an order.
 *
 * Note what is *not* here: no user credentials, no password hashes. Those live
 * in Bastion, which is the entire point of the example.
 */

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";

import * as authSchema from "./schema/auth";
import * as commerceSchema from "./schema/commerce";

const url = process.env.DATABASE_URL ?? "./shop.db";

/**
 * The raw handle. `lib/bastion/store.ts` uses it directly so its
 * compare-and-swap stays readable as SQL.
 */
export const sqlite = new Database(url);

// `busy_timeout` goes first, and the order is load-bearing. Switching to WAL
// takes a brief exclusive lock, and `next build` spawns a worker per core that
// all open this file at once — without a retry window already in place, the
// losers get SQLITE_BUSY and the build fails collecting page data.
sqlite.pragma("busy_timeout = 5000");

// WAL itself matters because the refresh lease is a write: in rollback mode a
// concurrent reader blocks the writer, and lease acquisition times out under
// exactly the concurrency it exists to handle.
sqlite.pragma("journal_mode = WAL");
sqlite.pragma("foreign_keys = ON");

export const schema = { ...authSchema, ...commerceSchema };

export const db = drizzle(sqlite, { schema });

export type Db = typeof db;
