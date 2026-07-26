#!/usr/bin/env bash
#
# Builds, uploads and restarts. Safe to re-run: everything it writes is
# overwritten in place, and the database is never touched.
#
#   deploy.sh --host ubuntu@1.2.3.4 --env deploy/oracle/env.production --domain example.com

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

host=""
env_file=""
domain=""
skip_build=""
ssh_opts=()

usage() {
  cat >&2 <<'EOF'
usage: deploy.sh --host user@host [options]

  --host HOST     target instance, e.g. ubuntu@1.2.3.4        (required)
  --env FILE      environment file to install as /etc/axum-secure-starter/env
  --domain NAME   verify https://NAME/health/live after restart
  --skip-build    reuse the existing dist/axum-secure-starter
  --on-server     build on the instance instead of in a container
  --ssh-opt OPT   extra option passed to ssh/scp/rsync (repeatable)
EOF
  exit 2
}

build_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)       host="${2:?}"; shift 2 ;;
    --env)        env_file="${2:?}"; shift 2 ;;
    --domain)     domain="${2:?}"; shift 2 ;;
    --skip-build) skip_build=1; shift ;;
    --on-server)  build_args+=(--on-server); shift ;;
    --ssh-opt)    ssh_opts+=("${2:?}"); shift 2 ;;
    -h|--help)    usage ;;
    *) echo "deploy.sh: unknown argument '$1'" >&2; usage ;;
  esac
done

[[ -n "$host" ]] || usage
ssh_args=("${ssh_opts[@]+"${ssh_opts[@]}"}")

if [[ -n "$env_file" && ! -f "$env_file" ]]; then
  echo "deploy.sh: no such environment file: $env_file" >&2
  exit 1
fi

if [[ -z "$skip_build" ]]; then
  # --on-server needs the host, which build.sh takes as the flag's argument.
  if [[ ${#build_args[@]} -gt 0 ]]; then
    build_args+=("$host")
  fi
  for opt in "${ssh_args[@]+"${ssh_args[@]}"}"; do
    build_args+=(--ssh-opt "$opt")
  done
  deploy/oracle/build.sh "${build_args[@]+"${build_args[@]}"}"
fi

[[ -f dist/axum-secure-starter ]] || {
  echo "deploy.sh: dist/axum-secure-starter is missing; drop --skip-build" >&2
  exit 1
}

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

mkdir -p "$staging/payload"
cp dist/axum-secure-starter "$staging/payload/"
cp deploy/oracle/axum-secure-starter.service "$staging/payload/"
cp -R bastion "$staging/payload/bastion"
[[ -n "$env_file" ]] && cp "$env_file" "$staging/payload/env"

echo "==> uploading to $host"
tar -C "$staging" -czf "$staging/payload.tgz" payload
scp "${ssh_args[@]+"${ssh_args[@]}"}" "$staging/payload.tgz" "$host:/tmp/axum-deploy.tgz"

echo "==> installing"
ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" HAS_ENV="${env_file:+1}" bash -seu <<'REMOTE'
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work" /tmp/axum-deploy.tgz' EXIT
tar -C "$work" -xzf /tmp/axum-deploy.tgz
cd "$work/payload"

sudo install -d -o root -g root -m 0755 /opt/axum-secure-starter/bin
sudo install -d -o axum -g axum -m 0750 /var/lib/axum-secure-starter
sudo install -d -o root -g axum -m 0750 /etc/axum-secure-starter
sudo install -d -o root -g axum -m 0750 /etc/axum-secure-starter/certs

# Replacing a running executable in place would fail with ETXTBSY; installing
# alongside and renaming is atomic and avoids it.
sudo install -o root -g root -m 0755 axum-secure-starter /opt/axum-secure-starter/bin/.axum-secure-starter.new
sudo mv /opt/axum-secure-starter/bin/.axum-secure-starter.new /opt/axum-secure-starter/bin/axum-secure-starter

sudo rm -rf /opt/axum-secure-starter/bastion
sudo cp -R bastion /opt/axum-secure-starter/bastion
sudo chown -R root:root /opt/axum-secure-starter/bastion
sudo chmod -R a=rX /opt/axum-secure-starter/bastion

if [ -n "${HAS_ENV:-}" ]; then
  # Readable by the service account, by nobody else: it holds the signing key.
  sudo install -o root -g axum -m 0640 env /etc/axum-secure-starter/env
fi

if [ ! -f /etc/axum-secure-starter/env ]; then
  echo "no /etc/axum-secure-starter/env on the host; pass --env FILE" >&2
  exit 1
fi
if [ ! -s /etc/axum-secure-starter/certs/fullchain.pem ]; then
  echo "no certificate installed; run issue-cert.sh first (production refuses to start without TLS)" >&2
  exit 1
fi

sudo install -o root -g root -m 0644 axum-secure-starter.service \
  /etc/systemd/system/axum-secure-starter.service
sudo systemctl daemon-reload
sudo systemctl enable axum-secure-starter.service
sudo systemctl restart axum-secure-starter.service

# `restart` returns once the process is spawned, not once it has bound a port;
# a configuration error surfaces a moment later.
sleep 3
sudo systemctl is-active --quiet axum-secure-starter.service || {
  echo "--- service failed to start ---" >&2
  sudo journalctl -u axum-secure-starter.service -n 40 --no-pager >&2
  exit 1
}
sudo systemctl --no-pager --lines=0 status axum-secure-starter.service || true
REMOTE

if [[ -n "$domain" ]]; then
  echo "==> checking https://$domain/health/live"
  for attempt in 1 2 3 4 5; do
    if curl -fsS --max-time 10 "https://$domain/health/live"; then
      echo
      echo "==> live"
      exit 0
    fi
    sleep 2
  done
  echo "deploy.sh: the service is running but https://$domain/health/live did not answer." >&2
  echo "  Check the VCN security list (ingress 443) and the host firewall:" >&2
  echo "    ssh $host sudo iptables -L INPUT -n --line-numbers" >&2
  exit 1
fi

echo "==> deployed"
