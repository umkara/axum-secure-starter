/**
 * Typed bindings for the five Bastion endpoints this integration uses.
 *
 * Deliberately policy-free: no retries beyond the transport's, no token
 * storage, no session semantics. That all lives in `tokens.ts` and `plugin.ts`.
 * Field names are snake_case because Bastion serialises its DTOs verbatim.
 */

import { request } from "./http";
import { BastionUnavailable } from "./errors";

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  /** Lifetime of the access token in seconds, from the moment it was issued. */
  expires_in: number;
}

export interface UserResponse {
  id: string;
  email: string;
  role: "user" | "admin";
  created_at: string;
}

interface CallContext {
  clientIp?: string;
  requestId?: string;
}

/** `POST /auth/register` → 201. Returns the user; **no tokens**. */
export async function register(
  input: { email: string; password: string },
  ctx: CallContext = {},
): Promise<UserResponse> {
  const user = await request<UserResponse>({
    method: "POST",
    path: "/auth/register",
    body: input,
    tier: "auth",
    ...ctx,
  });
  if (!user) throw new BastionUnavailable("register returned no body");
  return user;
}

/** `POST /auth/login` → 200 with a fresh token pair. */
export async function login(
  input: { email: string; password: string },
  ctx: CallContext = {},
): Promise<TokenResponse> {
  const tokens = await request<TokenResponse>({
    method: "POST",
    path: "/auth/login",
    body: input,
    tier: "auth",
    ...ctx,
  });
  if (!tokens) throw new BastionUnavailable("login returned no body");
  return tokens;
}

/**
 * `POST /auth/refresh` → 200 with a rotated pair.
 *
 * `retryable: false` is the important part. The refresh token is single-use and
 * losing the rotation race revokes the entire family, so a retry here can log
 * the user out of every device.
 */
export async function refresh(refreshToken: string, ctx: CallContext = {}): Promise<TokenResponse> {
  const tokens = await request<TokenResponse>({
    method: "POST",
    path: "/auth/refresh",
    body: { refresh_token: refreshToken },
    tier: "auth",
    retryable: false,
    ...ctx,
  });
  if (!tokens) throw new BastionUnavailable("refresh returned no body");
  return tokens;
}

/** `POST /auth/logout` → 204. Revokes the refresh family. Idempotent enough to retry. */
export async function logout(refreshToken: string, ctx: CallContext = {}): Promise<void> {
  await request<void>({
    method: "POST",
    path: "/auth/logout",
    body: { refresh_token: refreshToken },
    tier: "auth",
    ...ctx,
  });
}

/**
 * `POST /auth/password` → 204. Requires a live access token.
 *
 * Bastion revokes **all** of the account's sessions on success, so the caller
 * must re-login afterwards rather than assume its own tokens survived.
 */
export async function changePassword(
  accessToken: string,
  input: { current_password: string; new_password: string },
  ctx: CallContext = {},
): Promise<void> {
  await request<void>({
    method: "POST",
    path: "/auth/password",
    body: input,
    accessToken,
    tier: "global",
    ...ctx,
  });
}

/** `DELETE /admin/users/{id}/sessions` → 204. Admin-only break-glass revocation. */
export async function revokeUserSessions(
  accessToken: string,
  userId: string,
  ctx: CallContext = {},
): Promise<void> {
  await request<void>({
    method: "DELETE",
    path: `/admin/users/${encodeURIComponent(userId)}/sessions`,
    accessToken,
    tier: "global",
    ...ctx,
  });
}
