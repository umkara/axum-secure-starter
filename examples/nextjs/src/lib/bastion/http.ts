/**
 * The single place that speaks HTTP to Bastion.
 *
 * Everything above this file deals in typed results and the error classes from
 * `errors.ts`; nothing above it should ever see a `Response`.
 */

import { bastionConfig } from "./config";
import {
  AmbiguousRefresh,
  BastionConflict,
  BastionError,
  BastionFieldError,
  BastionForbidden,
  BastionRateLimited,
  BastionUnauthorized,
  BastionUnavailable,
  BastionValidation,
} from "./errors";
import { acquire, jitteredDelay, type Tier } from "./throttle";

/** Bastion's error envelope: `{ "error": { code, message, details? } }`. */
interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    details?: BastionFieldError[];
  };
}

export interface RequestOptions {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  body?: unknown;
  accessToken?: string;
  tier: Tier;
  /** End-user IP to forward, when `BASTION_FORWARD_CLIENT_IP` is on. */
  clientIp?: string;
  /**
   * Whether a 429 or network failure may be retried. False for refresh, whose
   * token is single-use — see {@link AmbiguousRefresh}.
   */
  retryable?: boolean;
  /** Correlates this call with Bastion's log line. */
  requestId?: string;
}

const MAX_ATTEMPTS = 3;

/**
 * Performs the call and returns the parsed JSON body, or `undefined` for 204.
 *
 * @throws {BastionError} for any non-2xx, mapped to the narrowest subclass.
 */
export async function request<T>(options: RequestOptions): Promise<T | undefined> {
  const retryable = options.retryable ?? true;
  let lastRateLimit: BastionRateLimited | undefined;

  for (let attempt = 0; attempt < (retryable ? MAX_ATTEMPTS : 1); attempt += 1) {
    if (attempt > 0) {
      const waitMs = jitteredDelay(lastRateLimit?.retryAfterMs ?? 250, attempt);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }

    await acquire(options.tier);

    try {
      return await attempt_(options);
    } catch (error) {
      if (error instanceof BastionRateLimited && retryable) {
        lastRateLimit = error;
        continue;
      }
      throw error;
    }
  }

  throw lastRateLimit ?? new BastionUnavailable("exhausted retries");
}

async function attempt_<T>(options: RequestOptions): Promise<T | undefined> {
  const headers: Record<string, string> = { accept: "application/json" };

  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
  }
  if (options.accessToken) {
    headers.authorization = `Bearer ${options.accessToken}`;
  }
  if (options.requestId) {
    headers["x-request-id"] = options.requestId;
  }
  if (bastionConfig.forwardClientIp && options.clientIp) {
    headers["x-forwarded-for"] = options.clientIp;
  }

  let response: Response;
  try {
    response = await fetch(`${bastionConfig.baseUrl}${options.path}`, {
      method: options.method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: AbortSignal.timeout(bastionConfig.timeoutMs),
      cache: "no-store",
    });
  } catch (cause) {
    // A transport failure is *ambiguous* for a non-retryable call: the request
    // may have been handled and only the response lost.
    if (options.retryable === false) {
      throw new AmbiguousRefresh(cause instanceof Error ? cause.message : "network error");
    }
    throw new BastionUnavailable(cause instanceof Error ? cause.message : "network error");
  }

  if (response.status === 204) {
    return undefined;
  }

  if (response.ok) {
    return (await response.json()) as T;
  }

  throw await toError(response, options);
}

async function toError(response: Response, options: RequestOptions): Promise<BastionError> {
  // Rate-limit and body-size rejections come from middleware, which does not
  // always emit Bastion's JSON envelope — so parsing must tolerate anything.
  let envelope: ErrorEnvelope | undefined;
  try {
    envelope = (await response.json()) as ErrorEnvelope;
  } catch {
    envelope = undefined;
  }

  const message = envelope?.error?.message ?? response.statusText ?? "request failed";
  const code = envelope?.error?.code ?? "unknown";

  switch (response.status) {
    case 401:
      return new BastionUnauthorized(message);
    case 403:
      return new BastionForbidden(message);
    case 409:
      return new BastionConflict(message);
    case 422:
      return new BastionValidation(message, envelope?.error?.details ?? []);
    case 429: {
      const header = response.headers.get("retry-after");
      const seconds = header ? Number.parseFloat(header) : Number.NaN;
      return new BastionRateLimited(Number.isFinite(seconds) ? seconds * 1_000 : 1_000);
    }
    default:
      if (response.status >= 500 && options.retryable === false) {
        return new AmbiguousRefresh(`HTTP ${response.status}`);
      }
      return response.status >= 500
        ? new BastionUnavailable(message)
        : new BastionError(message, response.status, code);
  }
}
