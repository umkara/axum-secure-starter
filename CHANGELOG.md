# Changelog

Notable changes to Bastion. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

This file starts at 0.4.0. Earlier versions were released before it existed;
their history is in the git log.

## Unreleased

### Added

- `APP_TOKEN_FORMAT` selects how access tokens are written, defaulting to `jwt`
  — what every earlier version issued. An unknown value stops the server rather
  than falling back.
- **PASETO v4.local** as a second format, `APP_TOKEN_FORMAT=paseto-local`.
  XChaCha20-Poly1305 with the version rather than a header deciding the
  cryptography, and an encrypted payload rather than readable base64 claims. The
  key is derived from `APP_JWT_SECRET` as `SHA-256(domain || secret)`, since
  v4.local needs exactly 32 bytes. Adds the `pasetors` dependency (v4 and std
  features only).
- **PASETO v4.public** as a third format, `APP_TOKEN_FORMAT=paseto-public`.
  Ed25519 signatures rather than a shared secret: the private key stays with the
  server, the public key can be handed to anything that verifies, and a leak of
  the verifying half forges nothing. The payload is signed rather than
  encrypted, so claims are readable — `paseto-local` remains the choice when
  that matters.
- `APP_TOKEN_PRIVATE_KEY` and `APP_TOKEN_PUBLIC_KEY`, base64 in either alphabet,
  padded or not, decoded and length-checked at start-up. Selecting
  `paseto-public` without both stops the server.
- `bastion --generate-token-keypair` prints a fresh pair as the environment
  lines that use it. Handled before configuration is loaded, since the usual
  reason to want a key is not having a configuration yet.
- **Opaque access tokens** as a fourth format, `APP_TOKEN_FORMAT=opaque`. The
  token is 32 bytes of CSPRNG output and the identity lives in a row, stored as
  a SHA-256 digest, so verification is a lookup and revocation takes effect on
  the next request. Logout ends that device's access token, a password change or
  an admin action ends all of them, and a role change applies without waiting
  for a refresh. Costs one indexed lookup per authenticated request — measured
  at 23,931 req/s against 30,227 for `jwt` on `GET /api/v1/notes` — and there is
  deliberately no cache, because a cached verification would reintroduce the
  window the format exists to close.
- Migration `0002_access_tokens.sql`, and an `AccessTokenRepository` port. The
  background janitor now sweeps every table with expiring rows rather than one.
- `tests/tokens.rs`: the same session driven end to end through every configured
  format, plus proof that a token written in one format does not authenticate
  against a server running the other — in both directions, with the same key,
  issuer and audience, so the format is the only difference.
- `security::token`, holding `TokenIssuer`, `TokenIdentity` and `issuer_for`:
  the one place a configured format becomes an implementation. Adding a format
  means adding a module beside it and an arm to that match, and touching nothing
  that uses tokens.

### Changed

- **Breaking:** `TokenIssuer` is now an async trait, because one implementation
  reaches storage to answer. `issue` also takes the session (refresh-token
  family) the access token belongs to, so a stored format can end one device's
  session without touching the others; stateless formats ignore it. Two default
  methods, `revoke_session` and `revoke_all_for_user`, do nothing unless a
  format can honour them — which is the honest answer for a stateless token.
- **Breaking:** `Repositories` gained `access_tokens`, and its `sweeper` field
  became `sweepers`, a list. `TokenJanitor::new` takes that list.
- `TokenIssuer` and `TokenIdentity` moved from `security::jwt` to
  `security::token`. Both are still re-exported from `security`, so
  `use bastion::security::TokenIssuer` is unaffected; a path naming `jwt`
  directly needs updating. `security::jwt` is now one implementation of the
  trait rather than its home.

## [0.4.0] — 2026-07-28

### Added

- **A middleware plugin system** (`src/plugin`). Middleware can now be added
  without editing the stack in `build_router`. A plugin contributes a layer at
  one of four stages — `Outer`, `Api`, `Credentials`, `Page` — or a pre-routing
  check, and nothing else. It cannot remove, replace or reorder a core control,
  which is enforced by the types: the hardening headers are written outside
  every stage with `overriding`, a plugin's layer is typed `Error = Infallible`
  so it can never sit between `HandleErrorLayer` and the load shedder, and a
  pre-routing check takes the request head by shared reference and can only
  return `Err`.
- **Four pre-routing guards**, all on by default. `path-guard` refuses encoded
  separators, dot segments, control characters, backslashes, oversized paths and
  repeated query keys. `host-guard` refuses a `Host` outside a configured list
  (off until you list one). `method-guard` refuses methods with no route,
  `TRACE` above all. `content-type-guard` requires JSON on API requests carrying
  a body, which is the CSRF guard for a token-authenticated API.
- `APP_PLUGIN_*` configuration for all of the above, resolved once at start-up.
  A plugin that refuses its settings stops the server rather than failing on the
  first request. See the README and `.env.example`.
- **`tests/plugins.rs`**: 23 tests that register plugins written to break the
  additive-only guarantee and assert the core wins.
- Rate limiting had shipped without a single test — the harness gave it an
  effectively unlimited bucket, so nothing ever provoked a 429. Five tests now
  pin it, including the fact that a 429 is the one response that is not the JSON
  envelope.

### Changed

- **Breaking:** `api::build_router` takes a `&Plugins`, and `server::serve` takes
  a `Registry`. Existing callers pass `Registry::builtin()` to keep what shipped,
  or `Registry::empty()` for none.
- **Breaking:** the seven single-header constructors on `SecurityHeaders`
  (`hsts`, `no_sniff`, `frame_options`, `referrer_policy`, `permissions_policy`,
  `cross_origin_resource_policy`, `cross_origin_opener_policy`) are replaced by
  `SecurityHeaders::hardening()`, one layer that writes all seven, and
  `SecurityHeaders::harden()`, the same set applied to a response directly. Two
  ways to spell one policy is how the two drift apart.
- CORS, rate limiting and request logging moved out of the hard-wired stack and
  ship as plugins. Behaviour is unchanged with the default registry. Request
  logging is now a hand-written layer rather than `TraceLayer`, with a header
  allowlist that refuses credential headers at start-up rather than filtering
  them at run time.
- Credential endpoints became their own stage. They already carried a tighter
  rate-limit bucket than the rest of the API; that is now a structural
  distinction a plugin can target.

### Fixed

- Responses produced *above* the router carried none of the hardening headers.
  Two cases: the 500 that `CatchPanicLayer` substitutes for a panicking stack,
  and every rejection made before routing — a guard's, and path
  canonicalisation's 404. The panic handler now sits below the headers, and the
  request id and hardening are applied above the pre-routing checks as well.
