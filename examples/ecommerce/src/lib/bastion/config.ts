/**
 * Environment for the Bastion integration, parsed once at module load.
 *
 * Parsing eagerly is deliberate: a missing `BASTION_TOKEN_SECRET` should stop
 * the process at boot, not produce a decrypt failure on somebody's first
 * sign-in three hours later.
 */

import { z } from "zod";

const schema = z.object({
  /** Base URL of the Bastion API, without a trailing slash. */
  BASTION_URL: z
    .url()
    .transform((value) => value.replace(/\/+$/, ""))
    .default("http://127.0.0.1:8080"),

  /** Path prefix Bastion mounts its versioned routes under. */
  BASTION_API_PREFIX: z.string().startsWith("/").default("/api/v1"),

  /**
   * 32 bytes, base64. Seals refresh tokens at rest.
   * Generate with: openssl rand -base64 32
   */
  BASTION_TOKEN_SECRET: z.string().min(1),

  /** Abandon a Bastion call after this long. */
  BASTION_TIMEOUT_MS: z.coerce.number().int().positive().max(60_000).default(8_000),

  /**
   * Refresh when the access token has less than this many seconds left.
   * Raise it to force a refresh on every call when testing single-flight.
   */
  BASTION_REFRESH_SKEW_SECONDS: z.coerce.number().int().nonnegative().default(30),

  /** How long one process may hold the refresh lease before another may steal it. */
  BASTION_REFRESH_LEASE_MS: z.coerce.number().int().positive().default(15_000),

  /**
   * Forward the end user's IP as `X-Forwarded-For` so Bastion's rate limiter
   * buckets per user instead of per Next process.
   *
   * Default false. Only turn this on when Bastion runs behind a proxy you
   * control with `APP_TRUST_PROXY_HEADERS=true` — otherwise it is either
   * ignored or, worse, spoofable.
   */
  BASTION_FORWARD_CLIENT_IP: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues
    .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
    .join("\n");
  throw new Error(`Invalid Bastion configuration:\n${issues}`);
}

const env = parsed.data;

export const bastionConfig = {
  baseUrl: `${env.BASTION_URL}${env.BASTION_API_PREFIX}`,
  tokenSecret: env.BASTION_TOKEN_SECRET,
  timeoutMs: env.BASTION_TIMEOUT_MS,
  refreshSkewSeconds: env.BASTION_REFRESH_SKEW_SECONDS,
  refreshLeaseMs: env.BASTION_REFRESH_LEASE_MS,
  forwardClientIp: env.BASTION_FORWARD_CLIENT_IP,
} as const;

export type BastionConfig = typeof bastionConfig;
