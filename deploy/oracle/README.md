# Deploying to Oracle Cloud Always Free

Runs the server on an Ampere A1 instance for $0/month: 2 OCPU, 12 GB of memory,
and 10 TB of egress, none of which expires.

## Why there is no reverse proxy here

The obvious shape for this — nginx or Caddy on :443, proxying to the app on
loopback — is the wrong one for *this* server. Its defences are connection-level:
`APP_MAX_CONNECTIONS`, `APP_HEADER_READ_TIMEOUT_SECS`,
`APP_TLS_HANDSHAKE_TIMEOUT_SECS` and `APP_MAX_CONCURRENT_STREAMS` all act on the
socket, before a request exists. Behind a proxy the app sees one trusted peer
that always speaks well-formed HTTP, so every one of those limits becomes dead
configuration and slowloris defence silently becomes the proxy's problem.

So the server terminates TLS itself on :443, and certbot answers ACME challenges
on :80 in standalone mode. This also keeps `APP_TRUST_PROXY_HEADERS=false`
honest: the peer address really is the client, so rate-limit identity cannot be
forged with `X-Forwarded-For`.

## Files

| File | Role |
| --- | --- |
| `cloud-init.yaml` | Instance first-boot: packages, service account, directories, host firewall, renewal hook |
| `Dockerfile.build` | Native `linux/arm64` build container |
| `build.sh` | Produces `dist/axum-secure-starter` |
| `issue-cert.sh` | First Let's Encrypt certificate |
| `deploy.sh` | Build, upload, restart, verify |
| `axum-secure-starter.service` | Hardened systemd unit |
| `env.production.example` | Template for `/etc/axum-secure-starter/env` |

## Before you start

**Upgrade the tenancy to Pay-As-You-Go.** A1 capacity is routinely refused for
non-upgraded Free Tier accounts — `Out of host capacity` on every launch attempt.
Upgrading adds a payment method but Always Free resources stay free, and it also
stops Oracle reclaiming an idle Always Free instance. This is the single change
that decides whether provisioning takes one attempt or fifty.

## 1. Launch the instance

Console → Compute → Instances → Create.

- **Image**: Canonical Ubuntu 24.04
- **Shape**: `VM.Standard.A1.Flex`, **2 OCPU / 12 GB** (the current Always Free
  ceiling — it was 4/24 until Oracle reduced it)
- **Boot volume**: 50 GB is plenty and stays inside the 200 GB free allowance
- **SSH key**: add yours
- **Advanced options → Management → Initialization script**: paste
  `cloud-init.yaml`

Note the public IP when it finishes.

## 2. Open :80 and :443

Two firewalls sit in the path, and both must be opened. `cloud-init.yaml`
handles the second one for you.

**VCN security list** — Networking → Virtual Cloud Networks → your VCN →
Security Lists → default → Add Ingress Rules. For each of 80 and 443:

| Field | Value |
| --- | --- |
| Source CIDR | `0.0.0.0/0` |
| IP Protocol | TCP |
| Destination Port Range | `80` (then a second rule for `443`) |

Or with the OCI CLI, appending to the existing rules rather than replacing them:

```bash
oci network security-list update --security-list-id <ocid> --force \
  --ingress-security-rules '[
    {"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},
    {"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":80,"max":80}}},
    {"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":443,"max":443}}}
  ]'
```

**Host firewall** — Oracle's Ubuntu images ship an iptables chain that REJECTs
everything but SSH. `cloud-init.yaml` inserts the ACCEPT rules and persists
them. Nothing to do unless you skipped cloud-init, in which case:

```bash
ssh ubuntu@<ip> sudo /usr/local/sbin/open-web-ports
```

A connection that hangs rather than refusing is almost always this chain.

## 3. Point DNS at it

An `A` record for your domain → the instance's public IP. Wait for it to
resolve; `issue-cert.sh` refuses to run before then, because a failed http-01
challenge counts against the Let's Encrypt rate limit.

## 4. Fill in the environment

```bash
cp deploy/oracle/env.production.example deploy/oracle/env.production
openssl rand -base64 48   # paste into APP_JWT_SECRET
```

Set `APP_BOOTSTRAP_ADMIN_EMAIL` and `APP_BOOTSTRAP_ADMIN_PASSWORD` for the first
deploy only. `deploy/oracle/env.production` is gitignored — keep it that way.

## 5. Certificate, then deploy

```bash
chmod +x deploy/oracle/*.sh

deploy/oracle/issue-cert.sh \
  --host ubuntu@<ip> --domain example.com --email you@example.com --staging
```

`--staging` uses the untrusted CA, which has no rate limit — worth one run to
prove the challenge path works. Then drop the flag and run it again for the real
certificate.

```bash
deploy/oracle/deploy.sh \
  --host ubuntu@<ip> \
  --env deploy/oracle/env.production \
  --domain example.com
```

That builds an aarch64 binary in a native arm64 container, uploads it with the
`bastion/` assets, installs the unit, restarts, and verifies
`https://example.com/health/live`.

No Docker? Add `--on-server` and it builds on the instance instead — slower, and
it leaves a Rust toolchain there.

## 6. Remove the bootstrap admin

Once the account exists, delete both `APP_BOOTSTRAP_ADMIN_*` lines and redeploy.
They are a standing credential otherwise.

```bash
deploy/oracle/deploy.sh --host ubuntu@<ip> --env deploy/oracle/env.production --skip-build
```

## Afterwards

```bash
# logs
ssh ubuntu@<ip> sudo journalctl -u axum-secure-starter -f

# ship a code change
deploy/oracle/deploy.sh --host ubuntu@<ip> --domain example.com

# back up the database (SQLite, so this must not be a plain file copy)
ssh ubuntu@<ip> "sudo -u axum sqlite3 /var/lib/axum-secure-starter/app.db \
  \".backup '/tmp/app-backup.db'\"" && scp ubuntu@<ip>:/tmp/app-backup.db .
```

Renewal is unattended: `certbot.timer` renews, the deploy hook copies the new
certificate into `/etc/axum-secure-starter/certs` and restarts the service,
which re-reads it at start-up.

## Known limits

- **SQLite on one box.** No replica, no failover. The instance's boot volume is
  the durability story, so take backups.
- **Restart on renewal.** The server loads its certificate once at start-up, so
  renewal costs a graceful restart every ~60 days.
- **Egress is free, capacity is not guaranteed.** Always Free instances can be
  reclaimed when idle unless the tenancy is upgraded to Pay-As-You-Go.
