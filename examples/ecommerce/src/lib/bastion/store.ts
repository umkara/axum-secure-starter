/**
 * The only reader and writer of `bastionCredential`.
 *
 * Written as raw SQL rather than through Drizzle so the compare-and-swap is
 * literally visible: the lease is acquired iff a single `UPDATE` guarded on the
 * observed `generation` reports `changes === 1`. That check is the whole
 * concurrency story, and burying it under a query builder would hide it.
 *
 * **Rewire this import when copying the plugin into another app** — it is the
 * only line that knows where the database lives.
 */

import { sqlite } from "@/db";

import { open, seal } from "./crypto";
import type { CredentialStatus } from "./schema";

const TABLE = '"bastionCredential"';

interface CredentialRow {
  id: string;
  sessionId: string;
  bastionUserId: string;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
  generation: number;
  lockedUntil: number | null;
  status: CredentialStatus;
}

/** A credential with its tokens unsealed. Never let one of these leave the server. */
export interface Credential {
  id: string;
  sessionId: string;
  bastionUserId: string;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
  generation: number;
  status: CredentialStatus;
}

function unseal(row: CredentialRow): Credential {
  return {
    id: row.id,
    sessionId: row.sessionId,
    bastionUserId: row.bastionUserId,
    accessToken: open(row.accessToken),
    refreshToken: open(row.refreshToken),
    accessTokenExpiresAt: row.accessTokenExpiresAt,
    generation: row.generation,
    status: row.status,
  };
}

export function create(input: {
  sessionId: string;
  bastionUserId: string;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
}): void {
  const now = Date.now();
  sqlite
    .prepare(
      `INSERT INTO ${TABLE}
         (id, sessionId, bastionUserId, accessToken, refreshToken,
          accessTokenExpiresAt, generation, lockedUntil, status, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, 0, NULL, 'active', ?, ?)
       ON CONFLICT(sessionId) DO UPDATE SET
         bastionUserId = excluded.bastionUserId,
         accessToken = excluded.accessToken,
         refreshToken = excluded.refreshToken,
         accessTokenExpiresAt = excluded.accessTokenExpiresAt,
         generation = generation + 1,
         lockedUntil = NULL,
         status = 'active',
         updatedAt = excluded.updatedAt`,
    )
    .run(
      crypto.randomUUID(),
      input.sessionId,
      input.bastionUserId,
      seal(input.accessToken),
      seal(input.refreshToken),
      input.accessTokenExpiresAt,
      now,
      now,
    );
}

export function findBySessionId(sessionId: string): Credential | null {
  const row = sqlite
    .prepare(`SELECT * FROM ${TABLE} WHERE sessionId = ?`)
    .get(sessionId) as CredentialRow | undefined;

  return row ? unseal(row) : null;
}

/**
 * Tries to claim the right to refresh this credential.
 *
 * Wins iff the row is still at `observedGeneration` and no live lease is held.
 * A loser must re-read the row: by the time it does, the winner has usually
 * written a fresh token, which is exactly the outcome it wanted anyway.
 *
 * @returns true if the caller now holds the lease.
 */
export function acquireLease(input: {
  sessionId: string;
  observedGeneration: number;
  leaseMs: number;
}): boolean {
  const now = Date.now();
  const result = sqlite
    .prepare(
      `UPDATE ${TABLE}
          SET lockedUntil = ?, updatedAt = ?
        WHERE sessionId = ?
          AND generation = ?
          AND status = 'active'
          AND (lockedUntil IS NULL OR lockedUntil < ?)`,
    )
    .run(now + input.leaseMs, now, input.sessionId, input.observedGeneration, now);

  return result.changes === 1;
}

/**
 * Stores a rotated pair and bumps the generation, which simultaneously releases
 * the lease and invalidates any other holder's CAS.
 */
export function commitRotation(input: {
  sessionId: string;
  observedGeneration: number;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: number;
}): void {
  sqlite
    .prepare(
      `UPDATE ${TABLE}
          SET accessToken = ?, refreshToken = ?, accessTokenExpiresAt = ?,
              generation = generation + 1, lockedUntil = NULL, updatedAt = ?
        WHERE sessionId = ? AND generation = ?`,
    )
    .run(
      seal(input.accessToken),
      seal(input.refreshToken),
      input.accessTokenExpiresAt,
      Date.now(),
      input.sessionId,
      input.observedGeneration,
    );
}

/**
 * Releases the lease without rotating. Only safe when the refresh token is
 * known to be **unspent** — i.e. after a 429, which the limiter rejects before
 * the handler ever sees it.
 */
export function releaseLease(sessionId: string): void {
  sqlite
    .prepare(`UPDATE ${TABLE} SET lockedUntil = NULL, updatedAt = ? WHERE sessionId = ?`)
    .run(Date.now(), sessionId);
}

/**
 * Marks the credential unusable.
 *
 * `poisoned` is for an ambiguous refresh: the token may or may not have been
 * consumed, and retrying a consumed one revokes every session in the family.
 * Signing this one session out is strictly cheaper than that.
 */
export function markStatus(sessionId: string, status: CredentialStatus): void {
  sqlite
    .prepare(`UPDATE ${TABLE} SET status = ?, lockedUntil = NULL, updatedAt = ? WHERE sessionId = ?`)
    .run(status, Date.now(), sessionId);
}

export function deleteBySessionId(sessionId: string): void {
  sqlite.prepare(`DELETE FROM ${TABLE} WHERE sessionId = ?`).run(sessionId);
}
