# Bastion

A JSON API server in Rust, built to be secure by default rather than secure by
reminder. Registration, login, session rotation, and a small CRUD resource, with
the protections you would otherwise bolt on afterwards already wired in and
covered by tests.

Use it as the starting point for an API where accounts and sessions matter, or
read it as a worked example of what "hardened" means in practice.

```bash
git clone https://github.com/umkara/bastion.git
cd bastion
cp .env.example .env
sed -i '' "s|^APP_JWT_SECRET=.*|APP_JWT_SECRET=$(openssl rand -base64 48)|" .env
mkdir -p data && cargo run
```

The server comes up on `http://127.0.0.1:8443`. Skip to [Your first
request](#your-first-request) to try it.

---

## Contents

- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Getting started](#getting-started)
- [Your first request](#your-first-request)
- [How authentication works](#how-authentication-works)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Middleware plugins](#middleware-plugins)
- [Enabling TLS](#enabling-tls)
- [Creating an administrator](#creating-an-administrator)
- [Deploying](#deploying)
- [Adapting it to your project](#adapting-it-to-your-project)
- [Running the tests](#running-the-tests)
- [Examples](#examples)
- [Project layout](#project-layout)
- [Security design](#security-design)
- [Scope and limitations](#scope-and-limitations)
- [License](#license)

---

## What you get

**Accounts and sessions.** Registration, login, logout, password change, and an
admin endpoint that ends every session for a user. Passwords are hashed with
Argon2id at OWASP parameters. Sessions use short-lived access tokens plus
rotating, single-use refresh tokens.

**Protection you did not have to remember.** Per-IP rate limiting (stricter on
credential endpoints), per-account lockout, request and connection deadlines, a
cap on concurrent password hashing, body-size limits, and the full set of
response hardening headers on every response.

**A structure you can extend.** Layered like a Spring application — thin
handlers, services that own the rules, repositories behind traits — so swapping
SQLite for Postgres means replacing repository implementations and nothing else.

**Middleware you can add without touching the stack.** Rate limiting, CORS,
request logging and four pre-routing guards ship as [plugins](#middleware-plugins).
A plugin can only add; it cannot remove, replace or reorder a core protection,
and that is enforced by the types rather than by review.

**Tests that prove it.** 142 of them, including 31 that actively attack the
server — SQL injection, forged and downgraded JWTs, privilege escalation,
request smuggling, path confusion, timing-based account enumeration, login
floods — and 23 that attack the plugin system with plugins written to break it.

---

## Requirements

- **Rust 1.85 or newer** (2024 edition). Check with `rustc --version`; install
  from [rustup.rs](https://rustup.rs) if needed.
- **OpenSSL** for generating a signing key — preinstalled on macOS and most
  Linux distributions.
- No database server. Data lives in a local SQLite file the server creates on
  first run.

---

## Getting started

**1. Get the code and create your configuration.**

```bash
git clone https://github.com/umkara/bastion.git
cd bastion
cp .env.example .env
```

**2. Generate a signing key.** The server refuses to start without one, and
refuses anything shorter than 32 bytes.

```bash
openssl rand -base64 48
```

Paste the result into `.env` as `APP_JWT_SECRET=...`. On macOS you can do both
steps at once:

```bash
sed -i '' "s|^APP_JWT_SECRET=.*|APP_JWT_SECRET=$(openssl rand -base64 48)|" .env
```

On Linux, drop the `''` that follows `-i`.

**3. Run it.**

```bash
mkdir -p data && cargo run
```

The first build takes a few minutes; afterwards it is seconds. You should see:

```
WARN listening (http) — TLS is disabled; permitted outside production only addr=127.0.0.1:8443
```

That warning is expected in development. See [Enabling TLS](#enabling-tls)
before exposing the server to anything.

**4. Confirm it is alive.**

```bash
curl http://127.0.0.1:8443/health/ready
```

```json
{ "status": "ready", "version": "0.4.0" }
```

---

## Your first request

Create an account. Passwords must be at least 12 characters.

```bash
curl -X POST http://127.0.0.1:8443/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery-staple"}'
```

Log in. You get back an access token and a refresh token.

```bash
curl -X POST http://127.0.0.1:8443/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery-staple"}'
```

```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "pEn0HN3H-o_4jjva5Ekpwh3nvgeEC5hIrbECZfSmjOg",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Use the access token to create something:

```bash
TOKEN="paste-your-access-token-here"

curl -X POST http://127.0.0.1:8443/api/v1/notes \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"title":"first","body":"hello"}'
```

And read it back:

```bash
curl http://127.0.0.1:8443/api/v1/notes -H "authorization: Bearer $TOKEN"
```

```json
{ "items": [ { "id": "...", "title": "first", "body": "hello" } ],
  "total": 1, "limit": 20, "offset": 0 }
```

There is also a browser console at `tools/api-console.html` — a single page with
no dependencies that exercises every endpoint. Serve it and allow its origin:

```bash
python3 -m http.server 8080 --directory tools
```

```bash
APP_CORS_ALLOWED_ORIGINS=http://127.0.0.1:8080 cargo run
```

Then open <http://127.0.0.1:8080/api-console.html>. Opening the file directly
with `file://` will fail every request — that is the CORS policy working.

---

## How authentication works

Two tokens, with different jobs:

| | Access token | Refresh token |
| --- | --- | --- |
| Format | Signed JWT, or [another format](#access-token-formats) | Opaque random string |
| Lifetime | 15 minutes | 14 days |
| Sent with | Every API request | Only to `/auth/refresh` |
| Stored server-side | No | Yes, as a SHA-256 digest |

**What your client should do:**

1. Call `/auth/login` and keep both tokens.
2. Send `Authorization: Bearer <access_token>` on every request.
3. When a request returns `401`, call `/auth/refresh` with the refresh token.
   You get back a **new pair** — replace both.
4. On logout, call `/auth/logout` with the refresh token.

**Refresh tokens are single-use.** Each refresh returns a new one and retires
the old. If a retired token is ever presented again, the server assumes it was
stolen and revokes the entire chain — every session descended from that login
ends and the user must log in again. Store the newest refresh token, and never
retry a refresh with an old one, or you will log your own users out.

---

## API reference

Base URL: `http://127.0.0.1:8443`. Everything except the probes lives under
`/api/v1`.

### Public

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| `GET` | `/health/live` | — | `200` if the process is up |
| `GET` | `/health/ready` | — | `200` if the database is reachable, else `503` |
| `POST` | `/api/v1/auth/register` | `{email, password}` | `201` with the created user |
| `POST` | `/api/v1/auth/login` | `{email, password}` | `200` with a token pair |
| `POST` | `/api/v1/auth/refresh` | `{refresh_token}` | `200` with a new token pair |
| `POST` | `/api/v1/auth/logout` | `{refresh_token}` | `204` |

### Authenticated — send `Authorization: Bearer <access_token>`

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/password` | `{current_password, new_password}` | `204`, and every session ends |
| `GET` | `/api/v1/notes` | — | `200` with a page of notes |
| `POST` | `/api/v1/notes` | `{title, body}` | `201` with the created note |
| `GET` | `/api/v1/notes/{id}` | — | `200` with the note |
| `PUT` | `/api/v1/notes/{id}` | `{title, body}` | `200` with the updated note |
| `DELETE` | `/api/v1/notes/{id}` | — | `204` |

`GET /api/v1/notes` accepts `?limit=` (1–100, default 20) and `?offset=`.

### Admin — requires an account with the `admin` role

| Method | Path | Returns |
| --- | --- | --- |
| `DELETE` | `/api/v1/admin/users/{id}/sessions` | `204`, ending every session for that user |

### Input limits

| Field | Rule |
| --- | --- |
| `email` | Valid address, max 254 characters |
| `password` | 12–128 characters |
| `title` | 1–200 characters |
| `body` | Max 20,000 characters |
| Request body | 256 KB by default |

### Errors

Every error uses the same shape, so clients branch on `code` rather than prose:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "request validation failed",
    "details": [ { "field": "email", "message": "must be a valid email address" } ]
  }
}
```

| Status | `code` | Meaning |
| --- | --- | --- |
| `400` | `validation_failed`, `bad_request` | Input rejected; `details` lists the fields |
| `401` | `unauthorized` | Missing, invalid, or expired credentials |
| `403` | `forbidden` | Authenticated, but not permitted |
| `404` | `not_found` | No such route, or no such resource *for you* |
| `409` | `conflict` | Email already registered |
| `413` | `payload_too_large` | Body exceeded the limit |
| `429` | — | Rate limited; wait and retry |
| `503` | `service_unavailable` | Overloaded, or shedding load |

Two behaviours worth knowing, because they are deliberate:

- **Someone else's resource returns `404`, not `403`.** A `403` would confirm
  the id exists.
- **Every login failure returns the same `401`.** Wrong password, unknown
  address, and locked account are indistinguishable — by status, by body, and by
  timing.

---

## Configuration

Everything is read from the environment at start-up. `.env` is loaded
automatically when present; real deployments should inject variables directly.
Invalid configuration stops the server rather than failing open later.

**Required:**

| Variable | Notes |
| --- | --- |
| `APP_JWT_SECRET` | Minimum 32 bytes. Generate with `openssl rand -base64 48`. |

**Commonly changed:**

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_ENV` | `development` | `production` refuses to start without TLS |
| `APP_BIND_ADDR` | `127.0.0.1:8443` | Use `0.0.0.0:8443` to accept external traffic |
| `APP_DATABASE_URL` | `sqlite://data/app.db?mode=rwc` | SQLite file location |
| `APP_CORS_ALLOWED_ORIGINS` | empty | Comma-separated exact origins; `*` is rejected |
| `APP_ACCESS_TOKEN_TTL_SECS` | `900` | Access token lifetime |
| `APP_REFRESH_TOKEN_TTL_SECS` | `1209600` | Refresh token lifetime (14 days) |
| `APP_TOKEN_FORMAT` | `jwt` | How access tokens are written. See [Access token formats](#access-token-formats) |

**Rate limiting and lockout:**

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_RATE_LIMIT_PER_SECOND` | `1` | Seconds to replenish one request slot |
| `APP_RATE_LIMIT_BURST` | `60` | Requests available in hand |
| `APP_AUTH_RATE_LIMIT_PER_SECOND` | `5` | Same, for `/auth/*` |
| `APP_AUTH_RATE_LIMIT_BURST` | `5` | Same, for `/auth/*` |
| `APP_MAX_LOGIN_ATTEMPTS` | `5` | Failures before an account locks |
| `APP_LOCKOUT_SECS` | `900` | How long a lockout lasts |
| `APP_TRUST_PROXY_HEADERS` | `false` | Honour `X-Forwarded-For`. **Only enable behind a proxy you control** — otherwise clients forge their own rate-limit identity |

**Resource limits:**

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_BODY_LIMIT_BYTES` | `262144` | Maximum request body |
| `APP_REQUEST_TIMEOUT_SECS` | `15` | Whole-request deadline |
| `APP_MAX_CONCURRENCY` | `1024` | In-flight requests before shedding |
| `APP_MAX_CONNECTIONS` | `4096` | Open sockets before refusing |
| `APP_HEADER_READ_TIMEOUT_SECS` | `10` | Slowloris control |
| `APP_MAX_CONCURRENT_HASHES` | CPU count | Concurrent Argon2 hashes; each reserves 19 MiB |
| `APP_SHUTDOWN_GRACE_SECS` | `20` | Drain time on `SIGTERM` |

**Logging:** `APP_LOG` takes `tracing` filter syntax, for example
`info,bastion=debug`. Production emits JSON; development emits
human-readable output.

**Plugins:** every `APP_PLUGIN_*` variable is listed under
[Middleware plugins](#middleware-plugins).

The full list with comments is in [`.env.example`](.env.example).

### Access token formats

`APP_TOKEN_FORMAT` chooses how access tokens are written and read.

| Value | Format |
| --- | --- |
| `jwt` *(default)* | HS256 JWT, pinned to one algorithm, issuer and audience |
| `paseto-local` | PASETO v4.local — XChaCha20-Poly1305, encrypted payload |
| `paseto-public` | PASETO v4.public — Ed25519 signatures, readable payload |

An unknown value stops the server. A deployment that asked for one format and
silently got another is the mistake this setting exists to prevent.

**`paseto-local`** is worth choosing when you would rather remove a footgun than
guard it. A JWT names its own algorithm in a header the recipient must be careful
not to trust — `alg=none`, RS256 verified as HS256 against the public key — and
the JWT codec here closes that by pinning the accepted algorithm to one value.
PASETO deletes the choice instead: `v4.local` *is* XChaCha20-Poly1305 by
definition of the version, with no field an attacker can edit. The payload is
also encrypted rather than merely signed, so a user id and role are not legible
to anything that handles the token.

**`paseto-public`** signs instead of encrypting, which changes who can do what.
A shared secret lets every holder both mint and verify, so a service that only
needs to check tokens has to be trusted to issue them too. A key pair splits
that: the private key stays with this server, the public key goes to anything
that verifies, and a leak of the verifying half forges nothing. The payload is
readable, as in a JWT — a verifier that cannot read a token cannot act on it —
so choose `paseto-local` instead when the claims themselves are sensitive.

It needs an Ed25519 key pair. Generate one:

```bash
cargo run -- --generate-token-keypair
```

That prints the three lines to paste into `.env`. Keep the private key secret;
the public key is meant to be handed out. Both are base64, in either alphabet,
padded or not — the server refuses anything that is not exactly 64 and 32 bytes,
which is what catches a public key pasted into the private slot.

`jwt` and `paseto-local` use `APP_JWT_SECRET`. PASETO v4.local needs exactly 32
bytes, so its key is derived as `SHA-256(domain || secret)` with a domain string
that makes it unusable as any other key.

| Variable | Needed by |
| --- | --- |
| `APP_JWT_SECRET` | `jwt`, `paseto-local` |
| `APP_TOKEN_PRIVATE_KEY` | `paseto-public` — 64 bytes, base64 |
| `APP_TOKEN_PUBLIC_KEY` | `paseto-public` — 32 bytes, base64 |

**Switching format invalidates every access token in circulation.** They fail
closed — a token in the old format is refused, not half-accepted — and clients
recover on their next refresh, since refresh tokens are unaffected. A test pins
that in both directions.

The choice reaches the application through `TokenIssuer` in
[`src/security/token.rs`](src/security/token.rs), which is where a format is
turned into an implementation — once, at start-up. Nothing above that trait
knows what the string on the wire is, so a format is added by writing a module
beside it, not by touching the extractor, the session service, or any handler.

This affects **access tokens only**. Refresh tokens are opaque whatever this
says: 32 bytes of CSPRNG output, stored as a SHA-256 digest, single-use, and
revocable server-side.

---

## Middleware plugins

Rate limiting, CORS, request logging and four pre-routing guards are plugins
rather than lines in the middleware stack. Seven in total, registered in code and
tuned by environment, and all enabled by default. Two of them install nothing
until you configure them: CORS needs an origin list, and the host guard needs a
host list — in both cases the unconfigured state is the more restrictive one.

**A plugin can only add.** It contributes a layer at one of four stages, or a
pre-routing check, and nothing else. It cannot remove a hardening header, widen
what the router accepts, rewrite a URL, or move itself in the stack:

```
CatchPanic ─ request id ─ the seven hardening headers
  └── [Outer]
        └── HandleError ─ load shed ─ concurrency ─ timeout ─ body limits
              └── router ─ [Api] on /api/v1, [Credentials] on /auth, [Page] on files
```

Three things make that structural rather than conventional. The header layers
sit outside every stage and write with `overriding`, so a plugin that strips a
header has it written back on the way out. A plugin's layer is typed
`Error = Infallible`, so it cannot produce the error `HandleErrorLayer` exists to
catch and can never land between that and the load shedder. And a pre-routing
check receives the request head by shared reference and can only return `Err` —
a check that could rewrite a URL could undo the canonicalisation below it, which
is the one way a plugin could make this server *less* strict.

Health probes sit outside every stage, so nothing installed as a plugin can
starve an orchestrator's liveness check.

### What ships

| Plugin | Stage | Does |
| --- | --- | --- |
| `path-guard` | pre-routing | Refuses encoded separators, dot segments, control characters, backslashes, oversized paths and repeated query keys |
| `host-guard` | pre-routing | Refuses a `Host` outside your list. Off until you list hosts |
| `method-guard` | pre-routing | Refuses methods with no route — `TRACE` above all |
| `content-type-guard` | pre-routing | Requires JSON on API requests with a body. The CSRF guard for a token API |
| `rate-limit` | credentials + API | Per-client buckets, tighter on `/auth/*`. Cannot be disabled in production |
| `cors` | outer | The configured origin policy. With no origins listed it installs nothing, which is same-origin only |
| `request-log` | outer | One structured line per request: method, matched route, status, latency |

### Settings

Each plugin reads `APP_PLUGIN_<NAME>_*`, and every one takes `ENABLED`. A value
that does not parse stops the server; it is never a silent default.

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_PLUGIN_RATE_LIMIT_ENABLED` | `true` | Refused in production — the buckets themselves are `APP_RATE_LIMIT_*` |
| `APP_PLUGIN_CORS_ENABLED` | `true` | Origins come from `APP_CORS_ALLOWED_ORIGINS` |
| `APP_PLUGIN_CORS_MAX_AGE_SECS` | `600` | Preflight cache, maximum `86400` |
| `APP_PLUGIN_REQUEST_LOG_ENABLED` | `true` | |
| `APP_PLUGIN_REQUEST_LOG_SAMPLE` | `1` | Log one success in N. Failures are never sampled out |
| `APP_PLUGIN_REQUEST_LOG_HEADERS` | empty | Header allowlist. A credential header is refused at start-up |
| `APP_PLUGIN_REQUEST_LOG_CLIENT_IP` | `false` | Opt-in: an address is personal data |
| `APP_PLUGIN_PATH_GUARD_ENABLED` | `true` | |
| `APP_PLUGIN_PATH_GUARD_MAX_PATH_LEN` | `2048` | |
| `APP_PLUGIN_PATH_GUARD_MAX_QUERY_LEN` | `4096` | |
| `APP_PLUGIN_PATH_GUARD_MAX_QUERY_PAIRS` | `32` | |
| `APP_PLUGIN_PATH_GUARD_ALLOW_DUPLICATE_QUERY` | `false` | `?limit=1&limit=2` parses differently in different parsers |
| `APP_PLUGIN_HOST_GUARD_HOSTS` | empty | Exact hosts, comma-separated; `*` is rejected. Empty means the guard installs nothing |
| `APP_PLUGIN_METHOD_GUARD_ENABLED` | `true` | |
| `APP_PLUGIN_METHOD_GUARD_METHODS` | `GET,HEAD,POST,PUT,DELETE,OPTIONS` | |
| `APP_PLUGIN_CONTENT_TYPE_GUARD_ENABLED` | `true` | |
| `APP_PLUGIN_CONTENT_TYPE_GUARD_REQUIRE_JSON` | `true` | |

Settings are resolved once, before the listener accepts anything: a plugin that
refuses its configuration stops the server rather than failing on somebody's
first request. The names that contributed something are logged at start-up.

### Writing one

Implement `Plugin`, returning a layer, a pre-routing check, or both. `Ok(None)`
means configured off — the plugin then costs nothing at run time.

```rust
use bastion::plugin::{Plugin, PluginCx, PluginError, Plugins, RouteLayer, Stage};

struct ServerTiming;

impl Plugin for ServerTiming {
    fn name(&self) -> &'static str {
        "server-timing" // reads APP_PLUGIN_SERVER_TIMING_*
    }

    fn stage(&self) -> Stage {
        Stage::Api
    }

    fn layer(&self, cx: &PluginCx<'_>) -> Result<Option<RouteLayer>, PluginError> {
        if !cx.enabled(true)? {
            return Ok(None);
        }
        Ok(Some(Plugins::erase(your_layer())))
    }
}
```

Register it in `main.rs`, where the order is source order — a plugin registered
earlier wraps one registered later:

```rust
use bastion::plugin::Registry;

let plugins = Registry::builtin().with(ServerTiming);
server::serve(listener, state, plugins, handle).await?;
```

Configuration can switch a plugin off and tune it, but it cannot reorder the
stack: a reordering that boots is a reordering nobody reviewed.

`PluginCx` carries the validated `AppConfig` and the plugin's settings. It
deliberately does not carry `AppState` — middleware that can reach the services
is a route handler wearing a disguise.

---

## Enabling TLS

Point the server at a certificate and key. Both must be set together, and
`APP_ENV=production` refuses to start without them.

For local testing, a self-signed pair:

```bash
mkdir -p certs && openssl req -x509 -newkey rsa:4096 -nodes -days 365 -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost"
```

```bash
APP_TLS_CERT_PATH=certs/cert.pem APP_TLS_KEY_PATH=certs/key.pem cargo run
```

In production, use a real certificate. If you terminate TLS at a load balancer
or reverse proxy instead, leave these unset, keep the server bound to a private
interface, and set `APP_TRUST_PROXY_HEADERS=true` so rate limiting sees real
client addresses.

---

## Creating an administrator

Registration always creates ordinary users, so the first administrator is seeded
from the environment:

```bash
APP_BOOTSTRAP_ADMIN_EMAIL=admin@example.com APP_BOOTSTRAP_ADMIN_PASSWORD='a-long-bootstrap-password' cargo run
```

On start-up the account is created, or an existing account with that address is
promoted — its password is left untouched, so a stale bootstrap value can never
overwrite a real credential. The step is idempotent. Unset both variables once
the administrator exists.

---

## Deploying

Build an optimised binary:

```bash
cargo build --release
```

The result is `target/release/bastion`: a single executable with no
runtime dependencies beyond libc. Migrations are compiled into it and applied on
start-up, so the `migrations/` directory does not need to ship alongside.

A checklist before going live:

- [ ] `APP_ENV=production`, with TLS configured or terminated upstream
- [ ] `APP_JWT_SECRET` injected as a secret, never committed
- [ ] `APP_BIND_ADDR` reachable by your proxy only
- [ ] `APP_CORS_ALLOWED_ORIGINS` set to your exact frontend origins
- [ ] A backup schedule for the SQLite file (see [limitations](#scope-and-limitations))
- [ ] `SIGTERM` used for shutdown, so in-flight requests drain

The server logs structured JSON in production and echoes an `x-request-id`
header on every response for correlation.

---

## Adapting it to your project

**Replace the example resource.** `notes` is a placeholder. The files to copy
are `src/domain/note.rs`, `src/repository/note_repository.rs`,
`src/service/note_service.rs`, and `src/api/note_handler.rs`, plus a migration
in `migrations/`. Register the routes in `src/api/mod.rs`.

**Move to Postgres.** Every service depends on a repository trait, not on
SQLite. Add the `postgres` feature to `sqlx` in `Cargo.toml`, write new
implementations of the repository traits, and change the wiring in
`src/state.rs`. Nothing above the repository layer changes.

**Add a field to the API.** Request and response types live in
`src/api/dto.rs`, deliberately separate from the domain entities — so adding a
field to a domain struct never silently starts exposing it.

**Change a security parameter.** Argon2 cost is in `src/security/password.rs`,
token claims and validation in `src/security/jwt.rs`, response headers in
`src/security/headers.rs`, and the middleware stack in `src/api/mod.rs`.

**Add middleware.** Write a [plugin](#middleware-plugins) and register it in
`main.rs` rather than editing the stack. The stack is assembled once so a
protection cannot be forgotten on an individual route; plugins are the seam that
keeps that true while still letting you add to it.

---

## Running the tests

```bash
cargo test
```

142 tests across five groups:

- **Unit tests** run against in-memory fakes, so questions of policy — how many
  failures lock an account, whether a spent refresh token can be replayed —
  finish in under a millisecond.
- **`tests/security.rs`** boots the real server on an ephemeral port and asserts
  the controls hold: token rotation, cross-account isolation, lockout, body
  limits, connection limits, database file permissions, response headers, rate
  limiting.
- **`tests/attacks.rs`** attacks that same server: SQL injection through every
  string that reaches the database, `alg=none` and tampered JWTs, mass
  assignment, path traversal and confusion, request smuggling, CORS lookalike
  origins, login timing, concurrent token double-spend, and login floods.
- **`tests/plugins.rs`** registers plugins written to break the additive-only
  guarantee — strippers that delete the hardening headers from inside two
  different stages, a plugin that panics mid-request, a check that waves through
  a path the core refuses — and asserts the core wins each time.
- **`tests/tokens.rs`** runs the same session end to end through every
  [access token format](#access-token-formats), and proves a token written in
  one does not authenticate against a server running the other.

Also useful:

```bash
cargo clippy --all-targets
```

```bash
cargo audit
```

CI runs formatting, lints, the full suite, and a dependency advisory scan on
every push, plus the advisory scan weekly.

---

## Examples

**[`examples/nextjs`](examples/nextjs)** — a Next.js 16 app that uses this server
as its credential authority. The app's own data lives in its own SQLite
database; accounts, passwords and refresh-token rotation stay here.

The integration is a set of bricks rather than a framework:
[`src/lib/bastion/`](examples/nextjs/src/lib/bastion/README.md) is twelve files
that each do one job — the HTTP client, the rate-limit bucket, the token
sealing, the refresh lease — and only the last two know a session library
exists. Take the directory, or take the three files you need.

It is worth reading even if you do not use Next: it works through the three
constraints this server imposes on a browser-facing client — a page CSP with no
inline scripts, `allow_credentials(false)`, and single-use refresh tokens whose
lost rotation race revokes the whole family — and shows what each one costs.

---

## Project layout

```
src/
  api/          HTTP edge      — routing, DTOs, extractors, middleware
  service/      business rules — one service per responsibility
  repository/   persistence    — traits + SQLite implementations
  domain/       entities       — data and its own invariants
  security/     cross-cutting  — hashing, tokens, authn/authz, headers
  plugin/       middleware     — the plugin framework and seven built-ins
  net.rs        connection admission control
  server.rs     serving: the one path both the binary and the tests use
  config.rs     configuration, validated at start-up
  error.rs      one error type, one wire format
  state.rs      the wiring: concrete implementations chosen once
migrations/     schema
tests/          integration and adversarial suites
tools/          browser API console
bastion/        documentation site (served by the server itself)
examples/       runnable apps built on this server
```

Dependencies point inward. Nothing below `api` knows HTTP exists; nothing above
`repository` knows SQL exists. Concrete types — SQLite, JWT, Argon2 — are named
in exactly one file, `state.rs`, so substituting any of them is a local change.

---

## Serving a frontend

Point the server at a directory of built assets:

```bash
APP_STATIC_DIR=./bastion cargo run
```

Anything not matching an API route is served from there, with unknown paths
falling back to `index.html` so client-side routing works. Serving the frontend
from the same origin also means the browser never makes a cross-origin request,
so `APP_CORS_ALLOWED_ORIGINS` can stay empty.

Served pages get their own `Content-Security-Policy` — `default-src 'self'`
with no inline execution — and a cache lifetime, while the API keeps
`default-src 'none'; sandbox` and `no-store`. Keeping the two profiles separate
is what stops adding a frontend from quietly loosening the policy protecting the
API; a test asserts both.

The included docs site, **Bastion**, is served this way and documents the whole
API plus integration guides for vanilla JS, TypeScript, React, Vue, Svelte,
Next.js, Tailwind, and Sass. Next.js is the one that does *not* go behind
`APP_STATIC_DIR` — see [Examples](#examples).

## Performance

Measured on an Apple M2 (8 cores), release build, loopback, `ab -k -c 50
-n 20000`, median of three runs, with rate limits raised so the figures reflect
the server rather than the limiter:

| Endpoint | Work | req/s | p50 | p99 |
| --- | --- | --- | --- | --- |
| `GET /health/live` | routing + full middleware stack | 53,136 | 1 ms | 2 ms |
| `GET /api/v1/notes` | JWT verify + SQLite read | 30,409 | 2 ms | 3 ms |
| `GET /style.css` | 5.9 KB file from disk | 7,660 | 2 ms | 47 ms |
| `POST /api/v1/auth/login` | Argon2id | 73–187 | 193 ms | 311 ms |

Zero failed requests. The login figure is the hashing cost working as intended —
a single login is ~24 ms sequentially, and concurrent hashing is capped so a
flood sheds instead of exhausting memory. Static files are the slowest served
path because every request reads from disk; put a CDN or proxy in front if you
serve a large bundle under real traffic.

Numbers on a laptop move 10–20 % between runs and far more if the machine is
busy. The load generator is not the limit — two parallel `ab` instances sum to
the same total as one — but it shares the same cores as the server, so dedicated
hardware would go higher. Measure on your own before planning capacity.

## Security design

**Credentials.** Argon2id at OWASP parameters (19 MiB, t=2, p=1), on a blocking
thread so a login burst cannot stall the runtime, and bounded so a login flood
cannot exhaust memory. A login for an address that does not exist still performs
a full hash, so account existence cannot be timed.

**Sessions.** Access tokens are short-lived JWTs pinned to one algorithm,
issuer, and audience — no algorithm downgrade, and no replay of a token minted
for a different service. Refresh tokens are opaque, stored only as SHA-256
digests, and single-use; redeeming a spent one revokes the whole family.

**Authorisation.** Identity arrives through an extractor, so a handler cannot
compile without asking for one, and the admin role is checked during extraction.
Resource queries are scoped by owner in SQL *and* in the service layer.

**Input.** Bodies are capped twice, every request is validated before a handler
sees it, page sizes are clamped server-side, and all SQL is parameterised.

**Responses.** CSP, HSTS, `nosniff`, `DENY` framing, `no-referrer`, a
restrictive Permissions-Policy, cross-origin isolation, and `no-store` — on
every response, including the ones produced above the router: a guard's
rejection, a non-canonical path, and the 500 that replaces a panic. No plugin
can remove them. Internal errors log their cause and return a generic message —
no SQL, paths, or panic text reaches a client.

**Availability.** Request deadlines and a concurrency ceiling that sheds load,
with connection caps, header deadlines, and a TLS handshake deadline underneath
— because a client that stalls before sending a request is invisible to the
request-level limits.

---

## Scope and limitations

Worth knowing before you build on it:

- **Single node.** SQLite means one instance. Rate-limit and hashing budgets are
  per-process, so multiple replicas each get their own — move rate limiting to
  your ingress if you scale out, or switch to Postgres.
- **No email flows.** No verification, no password reset. A user who forgets
  their password cannot recover it without an administrator. This is the most
  likely first extension.
- **No MFA**, and password strength is length-only — no breach-list check.
- **`/auth/register` reveals whether an address is taken** by returning `409`.
  Closing that properly requires email verification.
- **Access tokens cannot be revoked individually** — the cost of keeping them
  stateless. The window is 15 minutes; `/auth/password` and the admin endpoint
  revoke refresh tokens immediately.
- **No response compression**, deliberately: compressing responses that contain
  tokens alongside attacker-influenced content is the BREACH setup.
- **Volumetric DDoS is out of scope.** Everything here bounds what one
  connection or one process spends; a flood that saturates your network link has
  to be absorbed upstream.
- **Data is not encrypted at rest.** Database files are owner-only (`0600`), and
  password hashes and token digests are individually safe, but resource content
  is stored in the clear.

---

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Umit Karasu.
