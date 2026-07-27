/**
 * Bastion ⇄ BetterAuth integration.
 *
 * Server code should import from here rather than reaching into the individual
 * modules; `store.ts` in particular is private to `tokens.ts` and touching it
 * directly is how the refresh lease gets bypassed.
 *
 * See `README.md` in this directory for what to change when copying it into
 * another app.
 */

export { bastion } from "./plugin";
export { bastionClient } from "./client";
export { bastionSchema, type CredentialStatus } from "./schema";
export { bastionConfig, type BastionConfig } from "./config";

export { getAccessToken, withAccessToken, revoke as revokeCredential } from "./tokens";
export { decodeAccessTokenClaimsUnverified, type AccessTokenClaims } from "./claims";
export { revokeUserSessions } from "./api";

export {
  AmbiguousRefresh,
  BastionConflict,
  BastionError,
  BastionForbidden,
  BastionRateLimited,
  BastionUnauthorized,
  BastionUnavailable,
  BastionValidation,
  CredentialRevoked,
  type BastionFieldError,
} from "./errors";
