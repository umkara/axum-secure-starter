# Security Policy

Bastion is a security-hardened API server, so a vulnerability in it is the whole
point of the project failing. Reports are welcome, and they will be read.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub: open the
[Security tab](https://github.com/umkara/bastion/security/advisories/new) and
file a draft advisory. If that is unavailable to you, email
**umkarasu@gmail.com** with `bastion security` in the subject.

A useful report includes:

- the version or commit you tested against, and the feature flags it was built
  with (`sqlite` by default; `postgres`, `mysql` and `mongodb` are opt-in);
- what an attacker gains — bypassed authentication, another account's data, a
  denied service, leaked secrets;
- the smallest reproduction you have: a request sequence, a `curl` invocation, a
  failing test, or a patch against `tests/`.

You will get an acknowledgement within **72 hours** and an assessment within
**7 days**. If a report is accepted, you will be credited in the advisory and
the changelog unless you ask otherwise. This is a personal project with no bug
bounty — the thanks are real, but they are not monetary.

Please give a reasonable window to ship a fix before publishing. Ninety days is
the usual expectation; if a fix is going to take longer than that, you will hear
why rather than hear nothing.

## Supported versions

Fixes land on `main` and ship in the next release. Older minor versions are not
backported.

| Version | Supported |
| ------- | --------- |
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Scope

In scope — anything that breaks a guarantee the README's
[Security design](README.md#security-design) section claims:

- authentication or authorisation bypass, privilege escalation to admin;
- session handling failures: refresh-token replay, families that survive
  revocation, tokens accepted across issuer/audience/algorithm boundaries;
- reading or writing another account's resources;
- injection of any kind, including through a storage backend other than SQLite;
- leaking secrets, password hashes, SQL, or panic text to a client;
- a remote unauthenticated request that takes the process down, other than the
  documented per-process limits below.

Out of scope — these are known and documented in
[Scope and limitations](README.md#scope-and-limitations), not defects:

- rate limits, account lockout, and the hashing budget are **per-process**;
  multiple replicas each get their own set, and shared enforcement belongs at
  your ingress;
- the default SQLite backend is single-writer and will serialise under load;
- resource exhaustion that requires valid credentials and a request volume
  already above the configured ceilings;
- findings from a scanner with no demonstrated impact, missing headers on a
  deployment you configured yourself, or issues in your own fork's changes;
- social engineering, physical access, and attacks on bastionrs.dev's hosting
  rather than on this code.

## Dependencies

CI runs `cargo audit` on every push and on a weekly schedule, so advisories
against unchanged dependencies still surface. Any accepted advisory waiver is
recorded in the audit configuration with the reasoning for it. If you find a
waiver you believe is wrong, that is a legitimate report — send it the same way.
