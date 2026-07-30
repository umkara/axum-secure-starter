/**
 * One SQLite file holding the blog's own data — posts, authors — and the
 * server-side sessions.
 *
 * What is *not* here: passwords, password hashes, or any credential. Those
 * live in Bastion, which is the entire point of the example. The token pair is
 * here, sealed, because it has to live somewhere the browser cannot reach.
 */

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";

import * as schema from "./schema";

const url = process.env.DATABASE_URL ?? "./blog.db";

/** The raw handle. `lib/session.ts` uses it directly so its compare-and-swap stays readable as SQL. */
export const sqlite = new Database(url);

// `busy_timeout` goes first, and the order is load-bearing. Switching to WAL
// takes a brief exclusive lock, and `next build` spawns a worker per core that
// all open this file at once — without a retry window already in place, the
// losers get SQLITE_BUSY and the build fails collecting page data.
sqlite.pragma("busy_timeout = 5000");

// WAL itself matters because the refresh lease is a write: in rollback mode a
// concurrent reader blocks the writer, and lease acquisition times out under
// exactly the concurrency it exists to handle.
//
// Retried, because `busy_timeout` does not cover this path. Switching to WAL
// takes a brief exclusive lock, and `next build` opens this file from one
// worker per core at once — on a *cold* database several of them attempt the
// switch simultaneously and the losers get SQLITE_BUSY immediately rather than
// waiting. It reproduces in proportion to core count, so a laptop fails where a
// two-core CI runner gets away with it.
for (let attempt = 0; ; attempt++) {
  try {
    sqlite.pragma("journal_mode = WAL");
    break;
  } catch (error) {
    if (attempt === 20) throw error;
    // A synchronous sleep: this runs at module load, before anything is async.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
}
sqlite.pragma("foreign_keys = ON");

export const db = drizzle(sqlite, { schema });
