/**
 * The BetterAuth server plugin.
 *
 * BetterAuth owns the browser session; Bastion owns the credentials. This
 * plugin is the seam: it exposes sign-in / sign-up / change-password endpoints
 * that authenticate against Bastion, mirror the resulting identity into
 * BetterAuth's `user` table, and stash the Bastion token pair server-side.
 *
 * Structurally this follows the shipped `siwe` plugin, which solves the same
 * problem — verify against an external authority, upsert a user, mint a session.
 *
 * `emailAndPassword` must stay **disabled** in the host app's config. Leaving
 * it on would expose `/sign-up/email`, `/forget-password` and `/reset-password`
 * routes that write passwords BetterAuth-side and silently diverge from Bastion.
 */

import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
  sessionMiddleware,
} from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import * as z from "zod";

import * as api from "./api";
import { decodeAccessTokenClaimsUnverified } from "./claims";
import {
  BastionConflict,
  BastionError,
  BastionRateLimited,
  BastionUnauthorized,
  BastionValidation,
  CredentialRevoked,
} from "./errors";
import { bastionSchema } from "./schema";
import * as tokens from "./tokens";

const PROVIDER_ID = "bastion";

/**
 * Bastion normalises emails as `trim().to_lowercase()` before both lookup and
 * insert (`account_service.rs`). Matching that exactly here keeps the local
 * user row keyed the same way Bastion keys its account — otherwise
 * ` Alice@example.com ` and `alice@example.com` become one Bastion account and
 * two local users.
 */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

const credentialsSchema = z.object({
  email: z.string().min(1).max(254),
  password: z.string().min(1).max(128),
});

/** Maps a Bastion failure onto the HTTP shape BetterAuth clients expect. */
function toApiError(error: unknown): never {
  if (error instanceof BastionValidation) {
    throw new APIError("BAD_REQUEST", { message: error.message, details: error.fields });
  }
  if (error instanceof BastionConflict) {
    throw new APIError("UNPROCESSABLE_ENTITY", { message: "an account with that email exists" });
  }
  if (error instanceof BastionUnauthorized) {
    throw new APIError("UNAUTHORIZED", { message: "invalid email or password" });
  }
  if (error instanceof BastionRateLimited) {
    throw new APIError("TOO_MANY_REQUESTS", { message: "too many attempts; try again shortly" });
  }
  if (error instanceof CredentialRevoked) {
    throw new APIError("UNAUTHORIZED", { message: "your session expired; sign in again" });
  }
  if (error instanceof BastionError) {
    throw new APIError("SERVICE_UNAVAILABLE", { message: "the identity service is unavailable" });
  }
  throw error;
}

export const bastion = () =>
  ({
    id: "bastion",
    schema: bastionSchema,

    endpoints: {
      /**
       * `POST /sign-in/bastion` — one Bastion call.
       *
       * Email is taken from the form rather than the token because Bastion's
       * JWT carries only `sub`, `role`, `exp`, `iat` and `jti`; there is no
       * `email` claim and no `/me` endpoint to ask.
       */
      signInBastion: createAuthEndpoint(
        "/sign-in/bastion",
        { method: "POST", body: credentialsSchema },
        async (ctx) => {
          const email = normalizeEmail(ctx.body.email);

          try {
            const issued = await api.login({ email, password: ctx.body.password });
            const claims = decodeAccessTokenClaimsUnverified(issued.access_token);
            const user = await upsertUser(ctx, { bastionUserId: claims.sub, email, role: claims.role });

            const session = await ctx.context.internalAdapter.createSession(user.id);
            if (!session) {
              throw new APIError("INTERNAL_SERVER_ERROR", { message: "could not create a session" });
            }

            tokens.persist({
              sessionId: session.id,
              bastionUserId: claims.sub,
              tokens: issued,
            });

            await setSessionCookie(ctx, { session, user });
            return ctx.json({ token: session.token, user });
          } catch (error) {
            return toApiError(error);
          }
        },
      ),

      /**
       * `POST /sign-up/bastion` — two Bastion calls.
       *
       * Register returns the user but **no tokens**, so a login has to follow.
       * They are deliberately not wrapped in anything transaction-like: if the
       * login fails the account still exists, and the user can simply sign in.
       */
      signUpBastion: createAuthEndpoint(
        "/sign-up/bastion",
        { method: "POST", body: credentialsSchema },
        async (ctx) => {
          const email = normalizeEmail(ctx.body.email);

          try {
            const created = await api.register({ email, password: ctx.body.password });
            const issued = await api.login({ email, password: ctx.body.password });
            const claims = decodeAccessTokenClaimsUnverified(issued.access_token);

            const user = await upsertUser(ctx, {
              bastionUserId: created.id,
              email: created.email,
              role: claims.role,
            });

            const session = await ctx.context.internalAdapter.createSession(user.id);
            if (!session) {
              throw new APIError("INTERNAL_SERVER_ERROR", { message: "could not create a session" });
            }

            tokens.persist({ sessionId: session.id, bastionUserId: created.id, tokens: issued });

            await setSessionCookie(ctx, { session, user });
            return ctx.json({ token: session.token, user });
          } catch (error) {
            return toApiError(error);
          }
        },
      ),

      /**
       * `POST /change-password/bastion`.
       *
       * Bastion revokes every session on the account when a password changes,
       * so the token pair held here dies with them. Rather than leave the user
       * staring at a broken session, this re-logs in with the new password and
       * replaces the stored credential in place — same BetterAuth session, new
       * Bastion family.
       */
      changePasswordBastion: createAuthEndpoint(
        "/change-password/bastion",
        {
          method: "POST",
          use: [sessionMiddleware],
          body: z.object({
            currentPassword: z.string().min(1).max(128),
            newPassword: z.string().min(12).max(128),
          }),
        },
        async (ctx) => {
          const { session, user } = ctx.context.session;

          try {
            await tokens.withAccessToken(
              session.id,
              (accessToken) =>
                api.changePassword(accessToken, {
                  current_password: ctx.body.currentPassword,
                  new_password: ctx.body.newPassword,
                }),
              // A wrong current password is a 401 here, indistinguishable from
              // a stale token — retrying would spend a rotation to learn nothing.
              { retryOnUnauthorized: false },
            );

            const issued = await api.login({
              email: normalizeEmail(user.email),
              password: ctx.body.newPassword,
            });

            tokens.persist({
              sessionId: session.id,
              bastionUserId: decodeAccessTokenClaimsUnverified(issued.access_token).sub,
              tokens: issued,
            });

            return ctx.json({ status: true });
          } catch (error) {
            return toApiError(error);
          }
        },
      ),
    },

    hooks: {
      before: [
        {
          /**
           * Revoke the Bastion refresh family before BetterAuth drops its own
           * session. Doing it *before* means the session is still readable;
           * after the session row is gone there is no way back to the
           * credential row.
           */
          matcher: (context) => context.path === "/sign-out",
          handler: createAuthMiddleware(async (ctx) => {
            const current = await getSessionFromCtx(ctx);
            if (current?.session) {
              await tokens.revoke(current.session.id);
            }
          }),
        },
      ],
    },
  }) satisfies BetterAuthPlugin;

/**
 * Finds the local user for a Bastion account, creating it on first sight.
 *
 * The lookup goes through the `account` table rather than matching on email:
 * email is mutable in principle, the Bastion uuid is not. `role` is refreshed
 * on every sign-in so a promotion in Bastion takes effect at the next login
 * without any sync job.
 */
async function upsertUser(
  ctx: { context: { internalAdapter: any } },
  input: { bastionUserId: string; email: string; role: "user" | "admin" },
) {
  const { internalAdapter } = ctx.context;

  const account = await internalAdapter.findAccountByProviderId(input.bastionUserId, PROVIDER_ID);

  if (account) {
    return internalAdapter.updateUser(account.userId, {
      email: input.email,
      role: input.role,
      bastionUserId: input.bastionUserId,
    });
  }

  const user = await internalAdapter.createUser({
    email: input.email,
    name: input.email.split("@")[0],
    emailVerified: false,
    bastionUserId: input.bastionUserId,
    role: input.role,
  });

  await internalAdapter.createAccount({
    userId: user.id,
    providerId: PROVIDER_ID,
    accountId: input.bastionUserId,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  return user;
}
