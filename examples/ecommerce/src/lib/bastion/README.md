# `bastion/` — drop-in BetterAuth ↔ Bastion integration

Copy this whole directory into any Next.js app that wants
[Bastion](../../../../../README.md) to be its credential authority while
BetterAuth handles the browser session.

## What it does

| Concern | Owner |
|---|---|
| Passwords, account records, refresh-token rotation | **Bastion** |
| Browser session cookie, CSRF, route handlers | **BetterAuth** |
| Everything else in your app | **You** |

Bastion tokens never leave the server. The browser only ever holds BetterAuth's
own session cookie — which is what makes Bastion's `allow_credentials(false)`
and its lack of cookie auth a non-issue rather than an obstacle.

## Install

```bash
pnpm add better-auth zod
```

Three edits:

1. **`store.ts` line 12** — `import { sqlite } from "@/db"` is the only line
   that knows where your database lives. Point it at your own `better-sqlite3`
   handle.
2. **Your BetterAuth config** — add the plugin and, importantly, leave
   `emailAndPassword` off:

   ```ts
   import { betterAuth } from "better-auth";
   import { bastion } from "@/lib/bastion";

   export const auth = betterAuth({
     database: /* your adapter */,
     emailAndPassword: { enabled: false }, // Bastion owns passwords
     plugins: [bastion()],
   });
   ```

3. **Your auth client**:

   ```ts
   import { createAuthClient } from "better-auth/react";
   import { bastionClient } from "@/lib/bastion/client";

   export const authClient = createAuthClient({ plugins: [bastionClient()] });
   ```

Then generate the tables — `bastionSchema` adds `bastionCredential` plus two
`input: false` columns on `user`:

```bash
pnpm dlx @better-auth/cli generate
```

## Environment

| Variable | Default | Notes |
|---|---|---|
| `BASTION_URL` | `http://127.0.0.1:8080` | No trailing slash |
| `BASTION_API_PREFIX` | `/api/v1` | |
| `BASTION_TOKEN_SECRET` | **required** | 32 bytes base64: `openssl rand -base64 32` |
| `BASTION_TIMEOUT_MS` | `8000` | |
| `BASTION_REFRESH_SKEW_SECONDS` | `30` | Raise it to force refresh on every call when testing |
| `BASTION_REFRESH_LEASE_MS` | `15000` | How long one refresh may hold the lock |
| `BASTION_FORWARD_CLIENT_IP` | `false` | See *Rate limits* below |

Config is parsed at module load and throws on anything invalid, so a bad secret
stops the process at boot instead of failing somebody's first sign-in.

## Endpoints it adds

- `POST /api/auth/sign-in/bastion` — `{ email, password }`, one Bastion call
- `POST /api/auth/sign-up/bastion` — `{ email, password }`, two calls (register
  returns no tokens, so a login follows)
- `POST /api/auth/change-password/bastion` — `{ currentPassword, newPassword }`;
  Bastion revokes all sessions on success, so this re-logs in and swaps the
  stored credential in place
- `POST /api/auth/sign-out` — unchanged, but a `before` hook revokes the Bastion
  refresh family first

## Using a token in your own code

```ts
import { withAccessToken, CredentialRevoked } from "@/lib/bastion";

try {
  await withAccessToken(session.id, (token) =>
    fetch(`${base}/api/v1/notes`, { headers: { authorization: `Bearer ${token}` } }),
  );
} catch (error) {
  if (error instanceof CredentialRevoked) {
    // sign the user out; do not surface this as a 500
  }
}
```

`withAccessToken` refreshes if needed and retries once on an unexpected 401.

## Three things worth understanding before you change anything

**1. Refresh is lazy, and that is load-bearing.** Every call to Bastion leaves
from one IP, so the whole app shares one rate-limit bucket. Because the session
carries `bastionUserId`, `email` and `role`, rendering a page needs no Bastion
call at all — the only traffic is auth *transitions*. Adding a proactive
background refresh would multiply that traffic by your user count.

**2. Refresh is serialised through the database, not a mutex.** Bastion's
refresh tokens are single-use and *losing* the rotation race revokes the whole
family — two concurrent refreshes sign the user out everywhere. The lock is a
compare-and-swap on `bastionCredential.generation` (`store.ts:acquireLease`),
which holds across `next dev` workers and multiple instances. The in-process
promise map in `tokens.ts` is an optimisation on top; deleting it would be
slower but still correct, and deleting the lease would not.

**3. A 429 and a timeout are not the same failure.** A 429 is rejected by the
limiter before the handler, so the refresh token is unspent and the lease can be
released. A timeout or 5xx is ambiguous — the token may have been consumed with
the response lost — so the credential is marked `poisoned` and never retried.
Retrying it would look like replay to Bastion and take down every session in the
family.

## Rate limits

Bastion's `/auth/*` bucket defaults to 5/s burst 5. `throttle.ts` paces this app
at 4/s so the client bucket empties first and a burst becomes a short wait
rather than a 429. If you need per-end-user buckets instead of one shared one,
set `BASTION_FORWARD_CLIENT_IP=true` — but only when Bastion runs behind a proxy
you control with `APP_TRUST_PROXY_HEADERS=true`, otherwise the header is either
ignored or spoofable.

## Credentials are per session, not per user

`bastionCredential` has one row per BetterAuth *session*. BetterAuth's own
`account` table would be the obvious home, but it is keyed by (user, provider) —
and Bastion mints a separate refresh family per login. Two devices sharing one
row would rotate each other's token away, which Bastion reads as replay and
punishes by revoking the family. One row per session gives each device its own.

Tokens are AES-256-GCM sealed at rest; BetterAuth's `encryptOAuthTokens` only
covers the `account` table, so this is ours to do.
