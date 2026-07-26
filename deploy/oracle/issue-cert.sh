#!/usr/bin/env bash
#
# Obtains the first Let's Encrypt certificate for the instance and installs it
# where the service expects it. Renewal after this is unattended: certbot.timer
# runs the deploy hook that cloud-init wrote.
#
# The DNS A record for the domain must already point at the instance, and the
# VCN security list must allow :80 — the http-01 challenge is answered by
# certbot binding :80 directly.

set -euo pipefail

host=""
domain=""
email=""
staging=""
ssh_opts=()

usage() {
  cat >&2 <<'EOF'
usage: issue-cert.sh --host user@host --domain example.com --email you@example.com [--staging]

  --staging   use Let's Encrypt's staging CA (untrusted certificates, but no
              rate limit — worth one run before the real thing)
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)    host="${2:?}";   shift 2 ;;
    --domain)  domain="${2:?}"; shift 2 ;;
    --email)   email="${2:?}";  shift 2 ;;
    --staging) staging="--test-cert"; shift ;;
    --ssh-opt) ssh_opts+=("${2:?}"); shift 2 ;;
    -h|--help) usage ;;
    *) echo "issue-cert.sh: unknown argument '$1'" >&2; usage ;;
  esac
done

[[ -n "$host" && -n "$domain" && -n "$email" ]] || usage

ssh_args=("${ssh_opts[@]+"${ssh_opts[@]}"}")

echo "==> checking that $domain resolves to the instance"
resolved="$(dig +short "$domain" A | tail -1 || true)"
if [[ -z "$resolved" ]]; then
  echo "issue-cert.sh: $domain has no A record. Add one before issuing." >&2
  exit 1
fi
echo "    $domain -> $resolved"

ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" \
  DOMAIN="$domain" EMAIL="$email" STAGING="$staging" bash -seu <<'REMOTE'
# The server holds :443, certbot only wants :80, so nothing needs stopping.
sudo certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email "$EMAIL" \
  --domain "$DOMAIN" \
  --key-type ecdsa \
  --preferred-challenges http \
  ${STAGING:+$STAGING}

# certbot runs /etc/letsencrypt/renewal-hooks/deploy/* itself, but only when it
# actually issues. Running it here makes a no-op re-run still publish the files.
sudo env RENEWED_LINEAGE="/etc/letsencrypt/live/$DOMAIN" \
  /etc/letsencrypt/renewal-hooks/deploy/50-axum-secure-starter

sudo ls -l /etc/axum-secure-starter/certs
REMOTE

echo "==> certificate installed; run deploy.sh next"
