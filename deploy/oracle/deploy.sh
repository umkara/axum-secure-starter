#!/usr/bin/env bash
#
# Builds, uploads and restarts. Safe to re-run: everything it writes is
# overwritten in place, and the database is never touched.
#
#   deploy.sh --host ubuntu@1.2.3.4 --env deploy/oracle/env.production --domain example.com

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# What this tree expects to be deploying. Checked against what the service
# reports once it is back up, which is the only way to notice that --skip-build
# just shipped a stale dist/ binary.
version="$(awk -F'"' '/^\[package\]/{p=1} p && /^version *=/{print $2; exit}' Cargo.toml)"
[[ -n "$version" ]] || {
  echo "deploy.sh: could not read the package version from Cargo.toml" >&2
  exit 1
}

host=""
env_file=""
domain=""
skip_build=""
ssh_opts=()

usage() {
  cat >&2 <<'EOF'
usage: deploy.sh --host user@host [options]

  --host HOST     target instance, e.g. ubuntu@1.2.3.4        (required)
  --env FILE      environment file to install as /etc/bastion/env
  --domain NAME   verify https://NAME/health/live after restart
  --skip-build    reuse the existing dist/bastion
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

[[ -f dist/bastion ]] || {
  echo "deploy.sh: dist/bastion is missing; drop --skip-build" >&2
  exit 1
}

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

mkdir -p "$staging/payload"
cp dist/bastion "$staging/payload/"
cp deploy/oracle/bastion.service "$staging/payload/"
# Staged as docs/: the payload already has a file called bastion, the binary.
cp -R bastion "$staging/payload/docs"
[[ -n "$env_file" ]] && cp "$env_file" "$staging/payload/env"

echo "==> uploading to $host"
# --disable-copyfile or macOS writes AppleDouble ._* siblings, which would be
# unpacked straight into the served directory.
tar --disable-copyfile -C "$staging" -czf "$staging/payload.tgz" payload 2>/dev/null ||
  tar -C "$staging" -czf "$staging/payload.tgz" payload
scp "${ssh_args[@]+"${ssh_args[@]}"}" "$staging/payload.tgz" "$host:/tmp/bastion-deploy.tgz"

echo "==> installing"
ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" \
  HAS_ENV="${env_file:+1}" VERSION="$version" bash -seu <<'REMOTE'
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work" /tmp/bastion-deploy.tgz' EXIT
tar -C "$work" -xzf /tmp/bastion-deploy.tgz
cd "$work/payload"

sudo install -d -o root -g root -m 0755 /opt/bastion/bin
sudo install -d -o axum -g axum -m 0750 /var/lib/bastion
sudo install -d -o root -g axum -m 0750 /etc/bastion
sudo install -d -o root -g axum -m 0750 /etc/bastion/certs

# Replacing a running executable in place would fail with ETXTBSY; installing
# alongside and renaming is atomic and avoids it.
sudo install -o root -g root -m 0755 bastion /opt/bastion/bin/.bastion.new
sudo mv /opt/bastion/bin/.bastion.new /opt/bastion/bin/bastion

# The repository keeps the site in bastion/; here and on the box it is docs,
# because /opt/bastion/bastion would read like a mistake.
sudo rm -rf /opt/bastion/docs
sudo cp -R docs /opt/bastion/docs
sudo chown -R root:root /opt/bastion/docs
sudo chmod -R a=rX /opt/bastion/docs

if [ -n "${HAS_ENV:-}" ]; then
  # Readable by the service account, by nobody else: it holds the signing key.
  sudo install -o root -g axum -m 0640 env /etc/bastion/env
fi

# These live in a 0750 root:axum directory that the deploying user cannot
# traverse, so the tests have to run as root or they always report "missing".
if ! sudo test -f /etc/bastion/env; then
  echo "no /etc/bastion/env on the host; pass --env FILE" >&2
  exit 1
fi
if ! sudo test -s /etc/bastion/certs/fullchain.pem; then
  echo "no certificate installed; run issue-cert.sh first (production refuses to start without TLS)" >&2
  exit 1
fi

sudo install -o root -g root -m 0644 bastion.service \
  /etc/systemd/system/bastion.service
sudo systemctl daemon-reload
sudo systemctl enable bastion.service
sudo systemctl restart bastion.service

# `restart` returns once the process is spawned, not once it has bound a port;
# a configuration error surfaces a moment later.
sleep 3
sudo systemctl is-active --quiet bastion.service || {
  echo "--- service failed to start ---" >&2
  sudo journalctl -u bastion.service -n 40 --no-pager >&2
  exit 1
}
sudo systemctl --no-pager --lines=0 status bastion.service || true

# The binary is built for this instance's architecture, so the deploying machine
# cannot execute it to ask its version. Ask the running service instead: that
# answers "is the new code actually serving?", which is the question, and covers
# a restart that silently came back on the old executable.
#
# -k because the certificate is issued for the public hostname, not localhost.
port="$(sudo sed -n 's/^APP_BIND_ADDR=.*:\([0-9]*\)$/\1/p' /etc/bastion/env | tail -1)"
port="${port:-443}"

reported=""
for _ in 1 2 3 4 5; do
  reported="$(curl -k -fsS --max-time 5 "https://localhost:$port/health/live" 2>/dev/null |
    sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
  [ -n "$reported" ] && break
  sleep 1
done

if [ -z "$reported" ]; then
  echo "the service is active but /health/live did not answer on port $port" >&2
  exit 1
fi

if [ "$reported" != "$VERSION" ]; then
  echo "version mismatch: the service reports $reported, this tree is $VERSION" >&2
  echo "  dist/bastion is stale; rebuild it (drop --skip-build)" >&2
  exit 1
fi

echo "verified: serving $reported"
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
