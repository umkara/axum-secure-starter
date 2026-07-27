/**
 * `getAccessToken()` — the one function the rest of the app calls to obtain a
 * live Bastion access token, and the single-flight machinery behind it.
 *
 * ## Why refresh is never proactive
 *
 * Commerce data is local, and the BetterAuth session already carries
 * `bastionUserId`, `email` and `role`. Rendering a page therefore needs *zero*
 * Bastion calls. Only password change and admin revocation need a live token,
 * so refresh happens here, on demand, and nowhere else. That is a design rule
 * rather than an optimisation: it is what keeps the shared-IP rate limit
 * (every request in this app leaves from one address) a non-issue.
 *
 * ## Why the lock is in the database
 *
 * Bastion's refresh tokens are single-use, and *losing* the `mark_used` race
 * revokes the entire token family — so two concurrent refreshes do not merely
 * waste a call, they sign the user out everywhere. The in-process promise map
 * below is an optimisation only; `next dev` compiles route handlers in separate
 * workers, and a production deploy may run several instances. The lease in
 * `store.ts` is the actual mutual exclusion.
 */

import { bastionConfig } from "./config";
import { decodeAccessTokenClaimsUnverified, expiresAtMs } from "./claims";
import {
  AmbiguousRefresh,
  BastionRateLimited,
  BastionUnauthorized,
  CredentialRevoked,
} from "./errors";
import * as api from "./api";
import * as store from "./store";

/** Coalesces refreshes inside one process. Not a correctness mechanism. */
const inFlight = new Map<string, Promise<string>>();

/**
 * Returns an access token for this session, refreshing first if it is within
 * `BASTION_REFRESH_SKEW_SECONDS` of expiry.
 *
 * @throws {CredentialRevoked} when the session must be torn down — the caller
 *   should sign the user out rather than surface an error.
 */
export async function getAccessToken(sessionId: string): Promise<string> {
  const credential = store.findBySessionId(sessionId);

  if (!credential) {
    throw new CredentialRevoked("no Bastion credential for this session");
  }
  if (credential.status !== "active") {
    throw new CredentialRevoked(`credential is ${credential.status}`);
  }

  const skewMs = bastionConfig.refreshSkewSeconds * 1_000;
  if (credential.accessTokenExpiresAt - skewMs > Date.now()) {
    return credential.accessToken;
  }

  const existing = inFlight.get(sessionId);
  if (existing) {
    return existing;
  }

  const attempt = refreshOnce(sessionId, credential.generation).finally(() => {
    inFlight.delete(sessionId);
  });
  inFlight.set(sessionId, attempt);
  return attempt;
}

async function refreshOnce(sessionId: string, observedGeneration: number): Promise<string> {
  const won = store.acquireLease({
    sessionId,
    observedGeneration,
    leaseMs: bastionConfig.refreshLeaseMs,
  });

  if (!won) {
    return awaitWinner(sessionId, observedGeneration);
  }

  const credential = store.findBySessionId(sessionId);
  if (!credential) {
    throw new CredentialRevoked("credential vanished mid-refresh");
  }

  try {
    const tokens = await api.refresh(credential.refreshToken);
    const claims = decodeAccessTokenClaimsUnverified(tokens.access_token);

    store.commitRotation({
      sessionId,
      observedGeneration,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      accessTokenExpiresAt: expiresAtMs(claims),
    });

    return tokens.access_token;
  } catch (error) {
    if (error instanceof BastionRateLimited) {
      // The limiter rejected before the handler, so the token is unspent.
      // Releasing the lease is safe and lets the next caller try.
      store.releaseLease(sessionId);
      throw error;
    }

    if (error instanceof BastionUnauthorized) {
      // Bastion has definitively rejected this family — replayed, logged out
      // elsewhere, or password changed. Nothing to salvage.
      store.markStatus(sessionId, "revoked");
      throw new CredentialRevoked("Bastion rejected the refresh token");
    }

    if (error instanceof AmbiguousRefresh) {
      // The token may have been consumed with the response lost. Retrying it
      // would look like replay and revoke every session in the family, so this
      // one session is sacrificed instead.
      store.markStatus(sessionId, "poisoned");
      throw new CredentialRevoked("refresh outcome unknown; credential poisoned");
    }

    store.releaseLease(sessionId);
    throw error;
  }
}

/**
 * Polls for the lease winner's rotation.
 *
 * Bounded by the lease duration: if the winner dies mid-flight, the lease
 * expires and the next `getAccessToken` becomes the new winner rather than
 * everyone waiting forever.
 */
async function awaitWinner(sessionId: string, observedGeneration: number): Promise<string> {
  const deadline = Date.now() + bastionConfig.refreshLeaseMs;

  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));

    const credential = store.findBySessionId(sessionId);
    if (!credential) {
      throw new CredentialRevoked("credential removed while awaiting refresh");
    }
    if (credential.status !== "active") {
      throw new CredentialRevoked(`credential is ${credential.status}`);
    }
    if (credential.generation > observedGeneration) {
      return credential.accessToken;
    }
  }

  throw new AmbiguousRefresh("timed out waiting for the refresh lease holder");
}

export interface WithAccessTokenOptions {
  /**
   * Whether a 401 from `call` should be read as "the token went stale" and
   * retried after a forced refresh. Defaults to true.
   *
   * Turn it **off** for calls where Bastion answers 401 for a reason that has
   * nothing to do with the token. `/auth/password` is the case that matters: a
   * wrong *current password* returns 401 exactly like an expired token does
   * (`account_service.rs:159`), and retrying would spend a refresh rotation to
   * discover the same 401 a second time.
   */
  retryOnUnauthorized?: boolean;
}

/**
 * Runs `call` with a live access token, retrying once on an unexpected 401.
 *
 * The retry exists because Bastion can reject a token we still believe is
 * valid — a clock skew, or a revocation that happened between our expiry check
 * and the call. One forced refresh distinguishes that from a genuinely dead
 * session.
 */
export async function withAccessToken<T>(
  sessionId: string,
  call: (accessToken: string) => Promise<T>,
  options: WithAccessTokenOptions = {},
): Promise<T> {
  const token = await getAccessToken(sessionId);

  try {
    return await call(token);
  } catch (error) {
    if (!(error instanceof BastionUnauthorized) || options.retryOnUnauthorized === false) {
      throw error;
    }

    const credential = store.findBySessionId(sessionId);
    if (!credential || credential.status !== "active") {
      throw new CredentialRevoked("session is no longer usable");
    }

    const fresh = await refreshOnce(sessionId, credential.generation);
    return call(fresh);
  }
}

/** Called on sign-out. Best-effort: a failed revocation must not block sign-out. */
export async function revoke(sessionId: string): Promise<void> {
  const credential = store.findBySessionId(sessionId);
  if (!credential) return;

  try {
    if (credential.status === "active") {
      await api.logout(credential.refreshToken);
    }
  } catch {
    // Bastion will expire the family on its own schedule. Losing the local row
    // matters more than the remote revocation succeeding right now.
  } finally {
    store.deleteBySessionId(sessionId);
  }
}

/** Stores the pair a fresh login produced. */
export function persist(input: {
  sessionId: string;
  bastionUserId: string;
  tokens: api.TokenResponse;
}): void {
  const claims = decodeAccessTokenClaimsUnverified(input.tokens.access_token);

  store.create({
    sessionId: input.sessionId,
    bastionUserId: input.bastionUserId,
    accessToken: input.tokens.access_token,
    refreshToken: input.tokens.refresh_token,
    accessTokenExpiresAt: expiresAtMs(claims),
  });
}
