#!/usr/bin/env bash
#
# Produces dist/bastion, an aarch64 Linux binary for the Oracle A1
# shape.
#
# Default is a native arm64 container build (an Apple Silicon Mac and an Ampere
# instance share an architecture, so nothing is emulated). `--on-server` builds
# on the instance instead, for when Docker is unavailable — it is slower and
# leaves a Rust toolchain on the host.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mode=container
host=""
ssh_opts=()

usage() {
  cat >&2 <<'EOF'
usage: build.sh [--on-server user@host] [--ssh-opt OPT]...

  --on-server HOST   build on the instance over SSH instead of in a container
  --ssh-opt OPT      extra option passed to ssh/rsync (repeatable)
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --on-server) mode=on-server; host="${2:?--on-server needs user@host}"; shift 2 ;;
    --ssh-opt)   ssh_opts+=("${2:?--ssh-opt needs a value}"); shift 2 ;;
    -h|--help)   usage ;;
    *)           echo "build.sh: unknown argument '$1'" >&2; usage ;;
  esac
done

mkdir -p dist

if [[ "$mode" == container ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "build.sh: docker not found. Start Docker Desktop, or use --on-server user@host." >&2
    exit 1
  fi
  if ! docker version >/dev/null 2>&1; then
    echo "build.sh: the Docker daemon is not responding. Start Docker Desktop, or use --on-server user@host." >&2
    exit 1
  fi

  echo "==> building for linux/arm64 in a container"
  docker buildx build \
    --platform linux/arm64 \
    --file deploy/oracle/Dockerfile.build \
    --target artifact \
    --output "type=local,dest=dist" \
    .
else
  echo "==> building on $host"
  # macOS ships bash 3.2, where an empty array expands unset under `set -u`.
  ssh_args=("${ssh_opts[@]+"${ssh_opts[@]}"}")
  ssh_cmd="ssh${ssh_args[@]+ ${ssh_args[*]}}"

  # --locked needs Cargo.lock, and the build needs the migrations directory
  # because sqlx::migrate! embeds it at compile time.
  #
  # Secrets must not ride along. cargo needs none of them, and anything sent
  # here lands in the login user's home directory — outside the 0640 root:axum
  # that /etc/bastion/env gets, and readable by anyone who reaches that account.
  # env.production holds the signing key; deploy.sh installs it over its own
  # connection, so the build has no reason to see it. `/.env` was anchored at
  # the root and so never covered examples/nextjs/.env.local; `.env*` unanchored
  # does, and the --include ahead of it keeps the committed .env.example files.
  #
  # node_modules is excluded because it is most of the bytes and none of the
  # build: the Rust compile does not read it.
  #
  # --delete does not remove a file that is excluded, so a copy left behind by
  # an older revision of this script has to be deleted by hand.
  rsync -az --delete \
    --exclude '/target' --exclude '/dist' --exclude '/data' \
    --exclude '/.git' \
    --include '.env.example' --exclude '.env*' \
    --exclude 'node_modules/' \
    --exclude '/deploy/oracle/env.production' \
    -e "$ssh_cmd" \
    ./ "$host:bastion-src/"

  ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" bash -seu <<'REMOTE'
if ! command -v cargo >/dev/null 2>&1; then
  echo "==> installing the Rust toolchain"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends build-essential cmake clang curl pkg-config
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env"
cd ~/bastion-src
cargo build --release --locked
REMOTE

  scp "${ssh_args[@]+"${ssh_args[@]}"}" \
    "$host:bastion-src/target/release/bastion" \
    dist/bastion
fi

chmod +x dist/bastion
echo "==> dist/bastion"
file dist/bastion 2>/dev/null || ls -l dist/bastion
