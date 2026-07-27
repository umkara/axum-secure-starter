/**
 * Client-side token buckets mirroring Bastion's server-side limiter.
 *
 * Every call from this app arrives at Bastion from one IP, so the whole
 * storefront shares a single bucket. Pacing here turns what would be a 429
 * into a short wait, which is the difference between a failed sign-in and a
 * slightly slow one.
 *
 * The rates are deliberately set *below* Bastion's defaults (auth 5/s burst 5,
 * global 20/s burst 40) so this bucket empties first.
 */

class TokenBucket {
  private tokens: number;
  private lastRefill = Date.now();

  constructor(
    private readonly ratePerSecond: number,
    private readonly capacity: number,
  ) {
    this.tokens = capacity;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1_000;
    this.lastRefill = now;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.ratePerSecond);
  }

  /** Resolves once a token is available. Never rejects. */
  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const deficit = 1 - this.tokens;
      const waitMs = Math.ceil((deficit / this.ratePerSecond) * 1_000);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
}

/** `/auth/*` unauthenticated routes: register, login, refresh, logout. */
const authBucket = new TokenBucket(4, 4);

/** Everything else behind the bearer token. */
const globalBucket = new TokenBucket(16, 32);

export type Tier = "auth" | "global";

export function acquire(tier: Tier): Promise<void> {
  return (tier === "auth" ? authBucket : globalBucket).take();
}

/**
 * Full jitter, so two processes that hit the same 429 do not retry in lockstep.
 * Deterministic backoff is what turns one limiter rejection into a thundering herd.
 */
export function jitteredDelay(baseMs: number, attempt: number): number {
  const ceiling = Math.min(baseMs * 2 ** attempt, 5_000);
  return Math.floor(Math.random() * ceiling);
}
