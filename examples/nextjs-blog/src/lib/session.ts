/**
 * The session: an opaque cookie, a row in `blog.db`, and the single-flight
 * refresh that keeps Bastion's token family intact.
 *
 * This is the file the BetterAuth plugin in the other example replaces. Hand
 * rolled it is about two hundred lines, and every line of the concurrency story
 * is visible rather than delegated — which is the reason this example exists.
 *
 * ## What the browser holds
 *
 * A `blog_session` cookie containing 32 random bytes. That is all. The Bastion
 * access and refresh tokens live in the `session` row, sealed. Bastion sets
 * `allow_credentials(false)` and has no cookie auth, so tokens in the browser
 * would buy nothing and cost a refresh token sitting in a jar.
 *
 * ## Why refresh needs a lock rather than a retry
 *
 * Bastion's refresh tokens are single-use, and *losing* the rotation race
 * revokes the entire family — every session descended from that login. So two
 * concurrent refreshes do not merely waste a call, they sign the user out
 * everywhere. Deduplicating is not enough; concurrency has to be prevented.
 *
 * The lease is a compare-and-swap on `generation`, written as raw SQL below so
 * it is legible. A process wins iff its `UPDATE` reports exactly one changed
 * row. Losers poll for the winner's rotation, bounded by the lease so a crashed
 * winner does not strand everyone.
 */

import { randomBytes } from "node:crypto";
import { cookies } from "next/headers";

import * as bastion from "./bastion";
import { open, seal } from "./seal";
import { sqlite } from "@/db";

const COOKIE = "blog_session";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 14; // Matches Bastion's refresh lifetime.

/** Refresh this long before the access token actually expires. */
const SKEW_MS = 30_000;
/** How long one process may hold the refresh lease. */
const LEASE_MS = 10_000;

export interface CurrentUser {
  sessionId: string;
  bastionUserId: string;
  email: string;
  role: "user" | "admin";
}

interface Row {
  id: string;
  bastion_user_id: string;
  email: string;
  role: "user" | "admin";
  access_token: string;
  refresh_token: string;
  access_token_expires_at: number;
  generation: number;
  status: "active" | "revoked" | "poisoned";
}

function findRow(sessionId: string): Row | undefined {
  return sqlite.prepare("SELECT * FROM session WHERE id = ?").get(sessionId) as Row | undefined;
}

// ---------------------------------------------------------------------------
// Reading the current user — the hot path, and it never calls Bastion
// ---------------------------------------------------------------------------

/**
 * Who is signed in, or `null`.
 *
 * Deliberately makes **zero** Bastion calls: the row already carries the id,
 * email and role. Rendering a page — including every public blog page — costs
 * one local SELECT. That is what keeps Bastion's per-IP rate limit a non-issue
 * when every request from this app leaves from a single address.
 */
export async function currentUser(): Promise<CurrentUser | null> {
  const jar = await cookies();
  const sessionId = jar.get(COOKIE)?.value;
  if (!sessionId) return null;

  const row = findRow(sessionId);
  if (!row || row.status !== "active") return null;

  return {
    sessionId: row.id,
    bastionUserId: row.bastion_user_id,
    email: row.email,
    role: row.role,
  };
}

// ---------------------------------------------------------------------------
// Starting and ending a session — callable only from actions/route handlers
// ---------------------------------------------------------------------------

/**
 * Records a fresh token pair and sets the cookie.
 *
 * Only callable from a Server Action or Route Handler; Next forbids writing
 * cookies during a render.
 */
export async function startSession(input: {
  email: string;
  tokens: bastion.TokenPair;
}): Promise<CurrentUser> {
  const claims = bastion.readClaims(input.tokens.access_token);
  const sessionId = randomBytes(32).toString("base64url");

  // `sub` is Bastion's user id. Falling back to the email keeps the app working
  // under the token formats whose payload is not readable (paseto-local,
  // opaque) — the value is only ever a local key, never an authorisation input.
  const bastionUserId = claims.subject ?? input.email;

  sqlite
    .prepare(
      `INSERT INTO session
         (id, bastion_user_id, email, role, access_token, refresh_token,
          access_token_expires_at, generation, status)
       VALUES (?, ?, ?, 'user', ?, ?, ?, 0, 'active')`,
    )
    .run(
      sessionId,
      bastionUserId,
      input.email,
      seal(input.tokens.access_token),
      seal(input.tokens.refresh_token),
      claims.expiresAt,
    );

  const jar = await cookies();
  jar.set(COOKIE, sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: COOKIE_MAX_AGE,
  });

  return { sessionId, bastionUserId, email: input.email, role: "user" };
}

/**
 * Ends the session here and at Bastion.
 *
 * Best-effort remotely: if Bastion cannot be reached the local row goes anyway.
 * A user who clicked "sign out" must end up signed out of this app whatever the
 * network did, and Bastion expires the family on its own schedule regardless.
 */
export async function endSession(): Promise<void> {
  const jar = await cookies();
  const sessionId = jar.get(COOKIE)?.value;
  jar.delete(COOKIE);
  if (!sessionId) return;

  const row = findRow(sessionId);
  if (row && row.status === "active") {
    try {
      await bastion.logout(open(row.refresh_token));
    } catch {
      // Deliberately swallowed; see above.
    }
  }

  sqlite.prepare("DELETE FROM session WHERE id = ?").run(sessionId);
}

/** Drops the row without telling Bastion — for a session Bastion has already rejected. */
export async function forgetSession(sessionId: string): Promise<void> {
  sqlite.prepare("DELETE FROM session WHERE id = ?").run(sessionId);
  const jar = await cookies();
  jar.delete(COOKIE);
}

// ---------------------------------------------------------------------------
// The access token, and the lease that protects it
// ---------------------------------------------------------------------------

/** The session is finished; the caller should sign the user out. */
export class SessionExpired extends Error {}

/**
 * Runs `call` with a live Bastion access token.
 *
 * Only two things in this app need one — changing a password, and nothing else
 * today. Everything about rendering the blog is local.
 *
 * `retryOnUnauthorized` defaults to true so a token that went stale between the
 * expiry check and the call gets one forced refresh. Turn it **off** where a
 * 401 means something other than a stale token: `/auth/password` answers 401
 * for a wrong *current password*, and retrying would spend a rotation to
 * rediscover the same 401.
 */
export async function withAccessToken<T>(
  sessionId: string,
  call: (accessToken: string) => Promise<T>,
  options: { retryOnUnauthorized?: boolean } = {},
): Promise<T> {
  const token = await accessTokenFor(sessionId);

  try {
    return await call(token);
  } catch (error) {
    if (!(error instanceof bastion.Unauthorized) || options.retryOnUnauthorized === false) {
      throw error;
    }

    const row = findRow(sessionId);
    if (!row || row.status !== "active") throw new SessionExpired("session is no longer usable");

    return call(await rotate(sessionId, row.generation));
  }
}

async function accessTokenFor(sessionId: string): Promise<string> {
  const row = findRow(sessionId);
  if (!row) throw new SessionExpired("no session");
  if (row.status !== "active") throw new SessionExpired(`session is ${row.status}`);

  if (row.access_token_expires_at - SKEW_MS > Date.now()) {
    return open(row.access_token);
  }

  return rotate(sessionId, row.generation);
}

/**
 * Acquires the lease, or waits for whoever did.
 *
 * The `UPDATE` is guarded on the `generation` this caller observed, so a caller
 * working from a stale read cannot win. `changes === 1` is the entire mutual
 * exclusion mechanism.
 */
async function rotate(sessionId: string, observedGeneration: number): Promise<string> {
  const now = Date.now();
  const won =
    sqlite
      .prepare(
        `UPDATE session
            SET locked_until = ?
          WHERE id = ?
            AND generation = ?
            AND status = 'active'
            AND (locked_until IS NULL OR locked_until < ?)`,
      )
      .run(now + LEASE_MS, sessionId, observedGeneration, now).changes === 1;

  if (!won) return awaitWinner(sessionId, observedGeneration);

  const row = findRow(sessionId);
  if (!row) throw new SessionExpired("session vanished mid-refresh");

  try {
    const tokens = await bastion.refresh(open(row.refresh_token));
    const claims = bastion.readClaims(tokens.access_token);

    // Bumping the generation releases the lease and invalidates any other
    // holder's compare-and-swap in the same statement.
    sqlite
      .prepare(
        `UPDATE session
            SET access_token = ?, refresh_token = ?, access_token_expires_at = ?,
                generation = generation + 1, locked_until = NULL
          WHERE id = ? AND generation = ?`,
      )
      .run(
        seal(tokens.access_token),
        seal(tokens.refresh_token),
        claims.expiresAt,
        sessionId,
        observedGeneration,
      );

    return tokens.access_token;
  } catch (error) {
    if (error instanceof bastion.RateLimited) {
      // The limiter rejected before the handler ran, so the refresh token is
      // unspent. Releasing the lease is safe and lets the next caller try.
      release(sessionId);
      throw error;
    }

    if (error instanceof bastion.Unauthorized) {
      // Bastion has definitively rejected this family — replayed, logged out
      // elsewhere, or the password changed. Nothing to salvage.
      setStatus(sessionId, "revoked");
      throw new SessionExpired("Bastion rejected the refresh token");
    }

    if (error instanceof bastion.Ambiguous) {
      // The token may have been consumed with the response lost. Retrying it
      // would look like replay and revoke every session in the family, so this
      // one session is sacrificed instead.
      setStatus(sessionId, "poisoned");
      throw new SessionExpired("refresh outcome unknown; session abandoned");
    }

    release(sessionId);
    throw error;
  }
}

/**
 * Polls for the winner's rotation, bounded by the lease — so a winner that died
 * mid-flight lets the next caller become the winner instead of everyone waiting
 * forever.
 */
async function awaitWinner(sessionId: string, observedGeneration: number): Promise<string> {
  const deadline = Date.now() + LEASE_MS;

  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));

    const row = findRow(sessionId);
    if (!row) throw new SessionExpired("session removed while awaiting refresh");
    if (row.status !== "active") throw new SessionExpired(`session is ${row.status}`);
    if (row.generation > observedGeneration) return open(row.access_token);
  }

  throw new SessionExpired("timed out waiting for the refresh lease holder");
}

function release(sessionId: string): void {
  sqlite.prepare("UPDATE session SET locked_until = NULL WHERE id = ?").run(sessionId);
}

function setStatus(sessionId: string, status: "revoked" | "poisoned"): void {
  sqlite
    .prepare("UPDATE session SET status = ?, locked_until = NULL WHERE id = ?")
    .run(status, sessionId);
}
