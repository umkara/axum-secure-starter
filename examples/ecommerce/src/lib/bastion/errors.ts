/**
 * One error type per thing a caller can sensibly do about it.
 *
 * The distinction that matters most is {@link BastionRateLimited} versus
 * {@link AmbiguousRefresh}: a 429 means the request never reached Bastion's
 * handler, so a refresh token is still unspent and may be retried. A timeout
 * or 5xx means the opposite — the token may have been consumed with the
 * response lost, and retrying it would trip Bastion's replay detection and
 * revoke the whole token family.
 */

/** A field-level complaint from Bastion's `validation_failed` envelope. */
export interface BastionFieldError {
  field: string;
  message: string;
}

export class BastionError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** 401 — bad credentials, or an access token Bastion no longer accepts. */
export class BastionUnauthorized extends BastionError {
  constructor(message = "invalid credentials") {
    super(message, 401, "unauthorized");
  }
}

/** 403 — authenticated, but the role does not allow it. */
export class BastionForbidden extends BastionError {
  constructor(message = "forbidden") {
    super(message, 403, "forbidden");
  }
}

/** 409 — an account with that email already exists. */
export class BastionConflict extends BastionError {
  constructor(message = "already exists") {
    super(message, 409, "conflict");
  }
}

/** 422 — the payload failed Bastion's own validation. */
export class BastionValidation extends BastionError {
  constructor(
    message: string,
    readonly fields: BastionFieldError[] = [],
  ) {
    super(message, 422, "validation_failed");
  }
}

/**
 * 429 — rate limited. Safe to retry: the limiter rejects before the handler,
 * so nothing was consumed.
 */
export class BastionRateLimited extends BastionError {
  constructor(readonly retryAfterMs: number = 1_000) {
    super("rate limited by Bastion", 429, "rate_limited");
  }
}

/** The stored credential was revoked, poisoned, or never existed. */
export class CredentialRevoked extends BastionError {
  constructor(message = "Bastion credential is no longer usable") {
    super(message, 401, "credential_revoked");
  }
}

/**
 * A refresh failed in a way that leaves the token's fate unknown. The
 * credential is poisoned rather than retried, because a second attempt with a
 * possibly-spent token revokes every session in the family.
 */
export class AmbiguousRefresh extends BastionError {
  constructor(cause: string) {
    super(`refresh outcome unknown (${cause}); credential poisoned`, 503, "ambiguous_refresh");
  }
}

/** Bastion was unreachable, or answered with something unparseable. */
export class BastionUnavailable extends BastionError {
  constructor(message = "Bastion is unreachable") {
    super(message, 503, "service_unavailable");
  }
}
