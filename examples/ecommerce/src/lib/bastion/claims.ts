/**
 * Reads claims out of an access token **without verifying the signature**.
 *
 * This is safe here and nowhere else. The token arrived over TLS as the direct
 * response to our own `/auth/login` call, so its provenance is already
 * established; we only want `sub`, `role` and `exp` out of it. Bastion itself
 * verifies the signature on every protected route, which is where the security
 * decision actually gets made.
 *
 * Never call this on a token that came from a browser.
 */

export interface AccessTokenClaims {
  /** Bastion user uuid. This is the join key between the two systems. */
  sub: string;
  role: "user" | "admin";
  /** Expiry, seconds since epoch. */
  exp: number;
  iat: number;
  jti: string;
}

export function decodeAccessTokenClaimsUnverified(token: string): AccessTokenClaims {
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new Error("malformed access token: expected three JWT segments");
  }

  const payload = Buffer.from(segments[1], "base64url").toString("utf8");
  const claims = JSON.parse(payload) as Partial<AccessTokenClaims>;

  if (typeof claims.sub !== "string" || typeof claims.exp !== "number") {
    throw new Error("malformed access token: missing sub or exp");
  }

  return {
    sub: claims.sub,
    // Bastion always sets `role`, but an old token from a prior deploy might
    // not — treating an absent role as "user" fails closed.
    role: claims.role === "admin" ? "admin" : "user",
    exp: claims.exp,
    iat: claims.iat ?? 0,
    jti: claims.jti ?? "",
  };
}

/** Milliseconds-since-epoch expiry, for storing alongside the token. */
export function expiresAtMs(claims: AccessTokenClaims): number {
  return claims.exp * 1_000;
}
