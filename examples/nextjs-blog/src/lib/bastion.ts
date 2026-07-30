/**
 * Every call this app makes to Bastion, and nothing else.
 *
 * Six endpoints. No SDK, no auth library — that is the point of this example:
 * the whole integration is one readable file plus the session store beside it.
 * (The other example, `examples/nextjs`, does the same job through a BetterAuth
 * plugin. Same server, two integration styles.)
 *
 * Three properties of Bastion shape everything here:
 *
 * 1. **`allow_credentials(false)`, and no cookie auth.** Tokens are useless to
 *    a browser, so they never go there. They live server-side in `blog.db`,
 *    sealed, and the browser holds an opaque session id.
 * 2. **Register does not return tokens.** Signing up is register-then-login.
 * 3. **Refresh tokens are single-use, and losing the rotation race revokes the
 *    whole family.** Two concurrent refreshes do not waste a call — they sign
 *    the user out everywhere. `session.ts` prevents that with a lease.
 */

import { z } from "zod";

const BASE = process.env.BASTION_URL ?? "http://127.0.0.1:8080";
const API = `${BASE}/api/v1`;

/** Bastion never takes longer than this to answer; past it, assume the worst. */
const TIMEOUT_MS = 5_000;

export const tokenPair = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1),
  token_type: z.string(),
  expires_in: z.number(),
});

export type TokenPair = z.infer<typeof tokenPair>;

/** The credential was rejected: wrong password, or a token Bastion will not honour. */
export class Unauthorized extends Error {}

/** The address is taken. Bastion answers 409 on a duplicate registration. */
export class Conflict extends Error {}

/** Per-IP limiter. Every request from this app leaves from one address, so this is real. */
export class RateLimited extends Error {}

/**
 * The request may or may not have been applied.
 *
 * Only refresh cares, and it cares a great deal: retrying a refresh token that
 * *was* consumed looks like replay to Bastion, which revokes the family. When
 * this is thrown during refresh the session is abandoned rather than retried.
 */
export class Ambiguous extends Error {}

async function call(
  path: string,
  init: { method: string; body?: unknown; accessToken?: string },
): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (init.body !== undefined) headers["content-type"] = "application/json";
  if (init.accessToken) headers.authorization = `Bearer ${init.accessToken}`;

  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      method: init.method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
      cache: "no-store",
    });
  } catch (cause) {
    // The request left this process; whether Bastion applied it is unknowable.
    throw new Ambiguous(`${init.method} ${path} did not complete`, { cause });
  }

  if (response.ok) {
    return response.status === 204 ? null : await response.json();
  }

  // 429 is the one response that is not Bastion's JSON error envelope — it is
  // the rate limiter's own plain text. Do not try to parse it.
  if (response.status === 429) {
    throw new RateLimited("Bastion rate limit; try again shortly");
  }
  if (response.status === 401) {
    throw new Unauthorized(`${init.method} ${path} was rejected`);
  }
  if (response.status === 409) {
    throw new Conflict("that email address is already registered");
  }
  if (response.status >= 500) {
    // A 5xx after the request arrived may still have been applied.
    throw new Ambiguous(`Bastion returned ${response.status}`);
  }

  const detail = await response.text().catch(() => "");
  throw new Error(`Bastion returned ${response.status}: ${detail.slice(0, 200)}`);
}

/**
 * Creates an account. Returns nothing — Bastion issues no tokens here, so a
 * sign-up flow follows this with [`login`].
 *
 * @throws {Conflict} when the address is taken.
 */
export async function register(email: string, password: string): Promise<void> {
  await call("/auth/register", { method: "POST", body: { email, password } });
}

/** @throws {Unauthorized} on a wrong password *or* an unknown address — Bastion does not distinguish them, deliberately. */
export async function login(email: string, password: string): Promise<TokenPair> {
  return tokenPair.parse(await call("/auth/login", { method: "POST", body: { email, password } }));
}

/** Rotates the pair. The old refresh token is spent whether or not this returns. */
export async function refresh(refreshToken: string): Promise<TokenPair> {
  return tokenPair.parse(
    await call("/auth/refresh", { method: "POST", body: { refresh_token: refreshToken } }),
  );
}

export async function logout(refreshToken: string): Promise<void> {
  await call("/auth/logout", { method: "POST", body: { refresh_token: refreshToken } });
}

/**
 * Changes the password, which ends every session for the account — including
 * this one. The caller has to sign the user out afterwards.
 *
 * @throws {Unauthorized} when the *current* password is wrong. Note that this
 *   is the same 401 a stale access token produces, which is why the caller must
 *   not treat it as "refresh and retry".
 */
export async function changePassword(
  accessToken: string,
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  await call("/auth/password", {
    method: "POST",
    accessToken,
    body: { current_password: currentPassword, new_password: newPassword },
  });
}

/**
 * The `sub` claim, read without verifying the signature.
 *
 * Safe here and only here: the token came from Bastion over a channel we
 * control, seconds ago, and the value is used to key local rows — never to
 * decide authorisation. Bastion verifies for real on every call that matters.
 *
 * Returns the expiry too, so the session store knows when to refresh. Works for
 * JWT and PASETO-public; under `APP_TOKEN_FORMAT=paseto-local` or `opaque` the
 * token is not readable, and the fallback is a short assumed lifetime.
 */
export function readClaims(accessToken: string): { subject?: string; expiresAt: number } {
  const assumed = Date.now() + 10 * 60 * 1_000;

  const parts = accessToken.split(".");
  const payload = parts.length === 3 ? parts[1] : parts.length === 4 ? parts[2] : undefined;
  if (!payload) return { expiresAt: assumed };

  try {
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    const expiresAt = typeof json.exp === "number" ? json.exp * 1_000 : assumed;
    return { subject: typeof json.sub === "string" ? json.sub : undefined, expiresAt };
  } catch {
    return { expiresAt: assumed };
  }
}
