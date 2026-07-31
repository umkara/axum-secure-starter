#!/usr/bin/env bash
#
# Produces dist/bastion, an aarch64 Linux binary for the Oracle A1
# shape.
#
# Default is a native arm64 container build (an Apple Silicon Mac and an Ampere
# instance share an architecture, so nothing is emulated). `--on-server` builds
# on the instance instead, for when Docker is unavailable — it is slower and
# leaves a Rust toolchain on the host.
#
# Cargo features pass through, which is how a non-SQLite backend gets built:
#
#   build.sh --no-default-features --features postgres
#
# Both modes honour them, and the container build applies them to its
# dependency-cache layer too — otherwise that layer would be compiled with a
# different feature set from the crate and rebuilt from scratch every time.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mode=container
host=""
ssh_opts=()
features=""
no_default_features=0

usage() {
  cat >&2 <<'EOF'
usage: build.sh [--on-server user@host] [--ssh-opt OPT]...
                [--no-default-features] [--features LIST]

  --on-server HOST        build on the instance over SSH instead of in a container
  --ssh-opt OPT           extra option passed to ssh/rsync (repeatable)
  --features LIST         cargo features, comma-separated
  --no-default-features   drop the default feature set (which is `sqlite`)

The storage backend is a compile-time choice, so a PostgreSQL deployment is:

  build.sh --no-default-features --features postgres

Leaving both off builds exactly what it always did: the default features.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --on-server)           mode=on-server; host="${2:?--on-server needs user@host}"; shift 2 ;;
    --ssh-opt)             ssh_opts+=("${2:?--ssh-opt needs a value}"); shift 2 ;;
    --features)            features="${2:?--features needs a value}"; shift 2 ;;
    --no-default-features) no_default_features=1; shift ;;
    -h|--help)             usage ;;
    *)                     echo "build.sh: unknown argument '$1'" >&2; usage ;;
  esac
done

# The flags cargo will receive, as an array so an empty one stays empty rather
# than becoming an argument that is the empty string.
cargo_flags=()
(( no_default_features )) && cargo_flags+=(--no-default-features)
[[ -n "$features" ]] && cargo_flags+=(--features "$features")

# A build with no backend compiles and then refuses every APP_DATABASE_URL at
# start-up, which is a long way to travel to discover a typo. Catch it here.
if (( no_default_features )) && ! [[ ",$features," == *,sqlite,* || ",$features," == *,postgres,* \
   || ",$features," == *,mysql,* || ",$features," == *,mongodb,* || ",$features," == *,all-backends,* ]]; then
  echo "build.sh: --no-default-features drops the sqlite backend, and --features names no replacement." >&2
  echo "          The binary would refuse every database url at start-up. Add one of:" >&2
  echo "          sqlite, postgres, mysql, mongodb" >&2
  exit 2
fi

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

  echo "==> building for linux/arm64 in a container${cargo_flags[*]+ (${cargo_flags[*]})}"
  docker buildx build \
    --platform linux/arm64 \
    --file deploy/oracle/Dockerfile.build \
    --target artifact \
    --build-arg "CARGO_FEATURES=${cargo_flags[*]-}" \
    --output "type=local,dest=dist" \
    .
else
  echo "==> building on $host${cargo_flags[*]+ (${cargo_flags[*]})}"
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

  # The heredoc stays quoted so nothing expands locally; the feature flags reach
  # the remote shell as positional arguments instead, which keeps them intact
  # without a round of quoting nobody wants to reason about.
  ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" bash -seu -s -- \
    ${cargo_flags[@]+"${cargo_flags[@]}"} <<'REMOTE'
if ! command -v cargo >/dev/null 2>&1; then
  echo "==> installing the Rust toolchain"
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends build-essential cmake clang curl pkg-config
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env"
cd ~/bastion-src
cargo build --release --locked "$@"
REMOTE

  scp "${ssh_args[@]+"${ssh_args[@]}"}" \
    "$host:bastion-src/target/release/bastion" \
    dist/bastion
fi

chmod +x dist/bastion
echo "==> dist/bastion"
file dist/bastion 2>/dev/null || ls -l dist/bastion
