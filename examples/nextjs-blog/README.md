# A blog on Bastion

A Next.js 16 blog that keeps no passwords. Accounts, password hashing and
refresh-token rotation are Bastion's; posts, authors and sessions are this
app's.

**This example uses no auth library.** The whole integration is two files —
[`src/lib/bastion.ts`](src/lib/bastion.ts), the six HTTP calls, and
[`src/lib/session.ts`](src/lib/session.ts), the cookie and the refresh lease.
That is the difference from [`examples/nextjs`](../nextjs), which does the same
job through a BetterAuth plugin. Same server, two integration styles: read this
one if you want to see what the work actually is, and that one if you are
already using a session library.

## Run it

Two processes. Bastion first, from the repository root:

```bash
APP_ENV=development \
APP_BIND_ADDR=127.0.0.1:8088 \
APP_JWT_SECRET="$(openssl rand -base64 48)" \
APP_DATABASE_URL="sqlite://data/app.db?mode=rwc" \
cargo run
```

`APP_CORS_ALLOWED_ORIGINS` can stay empty — every call to Bastion is
server-to-server, so CORS never enters the picture.

Then the blog:

```bash
cd examples/nextjs-blog && pnpm install && cp .env.example .env.local
```

Fill in the one secret, which encrypts the Bastion token pair at rest:

```bash
openssl rand -base64 32   # BASTION_TOKEN_SECRET
```

```bash
pnpm db:push && pnpm db:seed && pnpm dev
```

Open <http://localhost:3000>, sign up, and write something.

## How the two halves divide

| | Bastion | This app |
|---|---|---|
| Passwords, account records | ✅ | — |
| Refresh-token rotation, revocation | ✅ | — |
| Who is signed in right now | — | ✅ (`session` row) |
| Posts, drafts, author profiles | — | ✅ (Drizzle) |

## What the browser holds

One cookie, `blog_session`, containing 32 random bytes. That is the entire
client-side footprint of being signed in.

Bastion's access and refresh tokens never leave the server: they live in the
`session` row, AES-256-GCM sealed, and are read only when something genuinely
needs one. Bastion sets `allow_credentials(false)` and has no cookie auth, so
tokens in a browser would buy nothing and cost a refresh token sitting in a jar.

**Rendering a page makes zero Bastion calls.** The session row already carries
the user id, email and role, so every public page — the feed, a permalink, an
author page — is one local `SELECT`. Exactly one screen in the whole app needs a
live access token: changing a password. That is what keeps Bastion's per-IP rate
limit a non-issue when every request from this app leaves from one address.

## The two things worth reading the code for

**The refresh lease.** Bastion's refresh tokens are single-use, and *losing* the
rotation race revokes the entire family — so two concurrent refreshes do not
waste a call, they sign the user out everywhere. Deduplicating is not enough;
concurrency has to be prevented. `session.ts` does it with a compare-and-swap on
a `generation` column, written as raw SQL so the mechanism is legible: a process
wins iff its `UPDATE` reports exactly one changed row. Losers poll for the
winner's rotation, bounded by the lease so a crashed winner strands nobody.

**Owner scoping lives in the `where` clause.** Every author-facing query in
[`src/lib/posts.ts`](src/lib/posts.ts) takes the author id and puts it in the
query — not as a filter on results, and not only as a check in the page.
Knowing a post id is not permission to edit it, and knowing a slug is not
permission to read a draft.

## Verified, not assumed

Run against a live Bastion, driving the real UI:

- Sign-up is register-then-login, because Bastion issues no tokens on register.
- A draft is invisible to everyone but its author: another signed-in user gets
  **404** from `/write/<id>` and from the public permalink, and the draft never
  appears in their list or on the feed.
- Publishing puts a post on the public feed; unpublishing takes it off.
- With a deliberately expired access token, a password-change attempt caused
  **exactly one** `/auth/refresh` — the lease committed the rotation and the
  generation moved `0 → 1`.
- A wrong *current password* returns 401 from Bastion, identical to a stale
  token. It produced **no second refresh**, which is the whole point of passing
  `retryOnUnauthorized: false` there — otherwise the app would spend a rotation
  to rediscover the same 401.
- Changing the password ends every session; the old password is then refused and
  the new one works.

**Not verified:** the lease under genuine concurrent contention. The
single-flight path was exercised, but not several requests racing for the same
lease at once. The sibling example's equivalent has been tested that way.

## Layout

```
src/
  lib/bastion.ts    the six Bastion calls, and nothing else
  lib/session.ts    the cookie, the session row, the refresh lease
  lib/seal.ts       AES-256-GCM for the token pair at rest
  lib/posts.ts      the blog's own queries — owner scoping lives here
  lib/actions.ts    every mutation, as Server Actions
  db/schema.ts      session, author, post
  app/              pages; the public ones make no Bastion call
  components/       form primitives
```

Forms post to Server Actions, so the blog works with JavaScript disabled. The
three client components exist only to render the error an action returned.
