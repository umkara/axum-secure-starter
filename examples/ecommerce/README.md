# Bastion Provisions — a Next.js storefront on Bastion

A small ecommerce app where **Bastion is the credential authority** and
everything commerce-shaped — catalogue, carts, orders — lives locally in
SQLite. The integration is packaged as a drop-in directory,
[`src/lib/bastion/`](src/lib/bastion/README.md), which is as much the point of
this example as the shop is.

- Next.js 16 (App Router, server actions) · Tailwind 4 · Drizzle + better-sqlite3
- BetterAuth for the browser session, extended by a custom server plugin
- Bastion for accounts, passwords and refresh-token rotation

## Run it

Two processes. Bastion first, from the repository root:

```bash
APP_ENV=development \
APP_BIND_ADDR=127.0.0.1:8080 \
APP_JWT_SECRET="$(openssl rand -base64 48)" \
APP_DATABASE_URL="sqlite://data/app.db?mode=rwc" \
APP_BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
APP_BOOTSTRAP_ADMIN_PASSWORD=bootstrap-admin-password-1 \
cargo run
```

`APP_CORS_ALLOWED_ORIGINS` can stay empty — every call to Bastion is
server-to-server, so CORS never enters the picture.

Then the shop:

```bash
cd examples/ecommerce && pnpm install && cp .env.example .env.local
```

Fill in the two secrets in `.env.local`:

```bash
openssl rand -base64 32   # BETTER_AUTH_SECRET
openssl rand -base64 32   # BASTION_TOKEN_SECRET
```

```bash
pnpm db:push && pnpm db:seed && pnpm dev
```

Open http://localhost:3000. Sign in as `admin@example.com` to see `/admin`.

## How the two halves divide

| | Bastion | This app |
|---|---|---|
| Passwords, account records | ✅ | — |
| Refresh-token rotation, revocation | ✅ | — |
| Browser session cookie | — | ✅ (BetterAuth) |
| Catalogue, carts, orders | — | ✅ (Drizzle) |

Three properties of Bastion decided the architecture, and each is worth knowing
before changing anything:

**1. The page CSP is `script-src 'self'` with no `unsafe-inline`**
(`src/security/headers.rs`). A Next static export emits an inline bootstrap
script and would not hydrate — so this example runs as **its own Node process**
and is never served through `APP_STATIC_DIR`.

**2. Bastion sets `allow_credentials(false)` and has no cookie auth**
(`src/api/mod.rs`). Putting tokens in the browser would mean a refresh token in
`localStorage`, so **all Bastion tokens stay server-side**. The browser holds
one BetterAuth cookie and nothing else.

**3. Refresh tokens are single-use, and losing the rotation race revokes the
whole family** (`src/service/session_service.rs`). Two simultaneous refreshes
would sign the user out everywhere — so refresh is *prevented* from running
concurrently, via a database lease with a compare-and-swap on a `generation`
column. See [the plugin README](src/lib/bastion/README.md) for the details.

A consequence worth stating plainly: because the session carries
`bastionUserId`, `email` and `role`, **rendering a page makes zero Bastion
calls**. Only two actions in the whole app need a live access token — changing a
password, and revoking another user's sessions from `/admin`. That is what keeps
the shared-IP rate limit (all traffic leaves from one address) a non-issue.

## What is in scope

**In:** seeded catalogue, product pages, a guest cart that merges into the user's
cart on sign-in, checkout that writes an order, order history, sign-up / sign-in
/ sign-out, password change, and an `/admin` page gated on the JWT `role` claim.

**Out:** payments — checkout writes an order and stops. Also no inventory,
search, real images, or i18n.

## Layout

```
src/
  lib/bastion/     the drop-in integration — read its README
  lib/auth.ts      BetterAuth config (emailAndPassword deliberately disabled)
  lib/session.ts   requireUser / requireAdmin; imports nothing from bastion/api
  lib/cart.ts      guest-cookie carts and the sign-in merge
  db/              Drizzle schema for both halves, plus the seed
  app/             routes
```

`lib/session.ts` importing nothing from `lib/bastion/api.ts` is a structural
guard rather than a tidiness preference: if reading the session could reach
Bastion, every render would become an outbound call.

## Things that will bite you

**Password change signs out your other devices.** Bastion revokes every session
on the account. The plugin re-establishes *this* session automatically by
signing back in with the new password; everything else stays signed out, which
is the intended behaviour of `revoke_all`.

**A 401 from `/auth/password` may mean "wrong current password", not "stale
token".** Bastion returns 401 for both. That is why the change-password path
opts out of the reactive token retry — otherwise a typo would spend a refresh
rotation to rediscover the same 401.

**The session cookie is not readable inside the action that creates it.**
`auth.api.signInBastion` writes the cookie to the *response*; calling
`getSession` afterwards in the same server action still sees an anonymous
visitor. Take the user id from the endpoint's return value — `src/app/(auth)/actions.ts`
does, and the cart merge depends on it.

**Production Bastion is stricter than the repo suggests.** The live deployment
restricts inbound 443 to Cloudflare ranges with `iptables` on the host, which is
not visible in the repository — so reading the repo alone makes
`APP_TRUST_PROXY_HEADERS=true` look forgeable. It is not, there.
`BASTION_FORWARD_CLIENT_IP` is only meaningful when that is true.
