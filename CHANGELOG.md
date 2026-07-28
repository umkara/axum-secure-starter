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
- `tests/tokens.rs`: the same session driven end to end through every configured
  format, plus proof that a token written in one format does not authenticate
  against a server running the other — in both directions, with the same key,
  issuer and audience, so the format is the only difference.
- `security::token`, holding `TokenIssuer`, `TokenIdentity` and `issuer_for`:
  the one place a configured format becomes an implementation. Adding a format
  means adding a module beside it and an arm to that match, and touching nothing
  that uses tokens.

### Changed

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
