/**
 * The `bastionCredential` table, declared in BetterAuth's plugin-schema shape
 * so `better-auth` CLI migrations and Drizzle both see it.
 *
 * **One row per BetterAuth session, not per user.** BetterAuth's own `account`
 * table is keyed by (user, provider), which would be the obvious home — but
 * Bastion mints a separate refresh-token family per login. Two devices sharing
 * one row would rotate each other's token out from under themselves, and
 * Bastion reads a reused token as replay and revokes the family. Keying by
 * session gives each device its own family, which is what Bastion expects.
 */

import type { BetterAuthPlugin } from "better-auth";

/**
 * Reached through `BetterAuthPlugin` rather than imported from
 * `@better-auth/core/db`, where it actually lives. That package is a transitive
 * dependency of `better-auth`, and a strict package manager (pnpm, Yarn PnP)
 * will not resolve it from here. This keeps the directory at one dependency,
 * which is the point of it being copy-pasteable.
 */
type PluginDBSchema = NonNullable<BetterAuthPlugin["schema"]>;

export const bastionSchema = {
  user: {
    fields: {
      /**
       * Bastion's user uuid — the join key between the two systems.
       *
       * `input: false` on both of these matters: without it BetterAuth would
       * accept them from a request body, and a browser could hand itself
       * `role: "admin"` or point its local user at somebody else's Bastion
       * account. They are only ever written server-side from JWT claims.
       */
      bastionUserId: { type: "string", required: false, input: false },
      /** Mirror of the `role` claim, so `/admin` can be gated without a Bastion call. */
      role: { type: "string", required: false, input: false, defaultValue: "user" },
    },
  },
  bastionCredential: {
    fields: {
      /** FK to `session.id`. Unique — one credential per session. */
      sessionId: {
        type: "string",
        required: true,
        unique: true,
        references: { model: "session", field: "id", onDelete: "cascade" },
      },
      /** Bastion user uuid; denormalised so admin actions need no join. */
      bastionUserId: { type: "string", required: true },
      /** AES-256-GCM sealed. */
      accessToken: { type: "string", required: true },
      /** AES-256-GCM sealed. */
      refreshToken: { type: "string", required: true },
      /** Access-token expiry, ms since epoch, from the `exp` claim. */
      accessTokenExpiresAt: { type: "date", required: true },
      /**
       * Bumped on every successful rotation. The refresh lease is a
       * compare-and-swap on this value, which is what makes the single-flight
       * lock correct across processes rather than merely likely.
       */
      generation: { type: "number", required: true, defaultValue: 0 },
      /** Lease held until this instant; null when free. */
      lockedUntil: { type: "date", required: false },
      /**
       * `active` — usable.
       * `revoked` — Bastion said no; sign the user out.
       * `poisoned` — a refresh outcome was ambiguous. Never retried, because
       *   the token may already be spent and a retry would revoke the family.
       */
      status: { type: "string", required: true, defaultValue: "active" },
      createdAt: { type: "date", required: true },
      updatedAt: { type: "date", required: true },
    },
  },
} satisfies PluginDBSchema;

export type CredentialStatus = "active" | "revoked" | "poisoned";
