#!/usr/bin/env bash
#
# Produces dist/bastion, a Linux binary for the Oracle instance.
#
# The default target is **linux/amd64**, because the instance is an x86_64
# `VM.Standard.E2.1.Micro` — the A1 Ampere shapes this script was originally
# written for were refused with `Out of host capacity`. Pass `--platform` if
# that ever changes; a binary built for the wrong architecture installs happily
# and then fails to exec.
#
# On an Apple Silicon Mac an amd64 container build is emulated through qemu, so
# it is slow and memory-hungry. `--on-server` builds on the instance instead:
# natively correct by construction, and the path deploy.sh is usually driven
# with. It leaves a Rust toolchain on the host.
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
# The instance is x86_64. See the header before changing this.
platform=linux/amd64
# Empty means "size it against the builder's RAM"; see pick_jobs.
jobs=""

usage() {
  cat >&2 <<'EOF'
usage: build.sh [--on-server user@host] [--ssh-opt OPT]...
                [--no-default-features] [--features LIST] [--platform PLATFORM]

  --on-server HOST        build on the instance over SSH instead of in a container
  --ssh-opt OPT           extra option passed to ssh/rsync (repeatable)
  --features LIST         cargo features, comma-separated
  --no-default-features   drop the default feature set (which is `sqlite`)
  --platform PLATFORM     container build target, default linux/amd64
                          (the instance is x86_64); ignored by --on-server,
                          which builds natively on whatever the host is
  --jobs N                concurrent compiler jobs. The default is derived from
                          the builder's RAM, roughly one job per 2 GiB and never
                          fewer than 2, because a job per core is what exhausts
                          a small builder

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
    --platform)            platform="${2:?--platform needs a value}"; shift 2 ;;
    --jobs)                jobs="${2:?--jobs needs a value}"; shift 2 ;;
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

if [[ -n "$jobs" ]] && ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
  echo "build.sh: --jobs '$jobs' is not a positive integer." >&2
  exit 2
fi

# rustc is memory-hungry, and cargo's default of one job per core assumes a
# machine sized to its core count. A Docker VM rarely is: this one is given 8
# cores and 5.75 GiB, and eight concurrent rustc processes exhausted the host
# badly enough that macOS SIGKILLed the whole VM mid-build — twice — taking
# every other running container with it. The guest logs no OOM because nothing
# in the guest failed; it was killed from outside.
#
# So budget by memory rather than cores: ~2 GiB per concurrent job, never more
# jobs than cores. On a builder with RAM to match its cores this changes nothing.
#
# The floor is 2 rather than 1, which is worth justifying, because the arithmetic
# alone would pick 1 on the very VM this was written for. Two things make that
# safe now. The VM's memory is a hard ceiling — it cannot take the host down
# again however many jobs run inside it — so what this figure now protects
# against is a *guest* OOM, which kills one rustc with a legible error rather
# than the machine. And two jobs is the only concurrency this crate has ever
# been built at successfully. One is slower and has never been shown to be
# safer. The cap by core count still applies, so a single-core builder gets 1.
pick_jobs() {
  local mem_bytes ncpu n
  mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  ncpu="$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 1)"
  [[ "$mem_bytes" =~ ^[0-9]+$ ]] || mem_bytes=0
  [[ "$ncpu" =~ ^[1-9][0-9]*$ ]] || ncpu=1

  n=$(( mem_bytes / (2 * 1024 * 1024 * 1024) ))
  (( n < 2 )) && n=2
  (( n > ncpu )) && n=$ncpu
  echo "$n"
}

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

  # The wrong architecture is not a build failure — it produces a binary that
  # installs and then dies with "cannot execute binary file", which is a long
  # way from the cause. Only the two shapes Oracle actually offers are accepted.
  case "$platform" in
    linux/amd64|linux/arm64) ;;
    *)
      echo "build.sh: --platform '$platform' is not one of linux/amd64, linux/arm64." >&2
      echo "          The instance is x86_64, so linux/amd64 is almost certainly right." >&2
      exit 2 ;;
  esac

  [[ -n "$jobs" ]] || jobs="$(pick_jobs)"

  echo "==> building for $platform in a container, $jobs job(s)${cargo_flags[*]+ (${cargo_flags[*]})}"
  docker buildx build \
    --platform "$platform" \
    --file deploy/oracle/Dockerfile.build \
    --target artifact \
    --build-arg "CARGO_FEATURES=${cargo_flags[*]-}" \
    --build-arg "CARGO_JOBS=--jobs $jobs" \
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
  # No memory-derived default here: the instance has one core, so cargo already
  # runs a single job. An explicit --jobs still forwards, for a bigger shape.
  remote_flags=("${cargo_flags[@]+"${cargo_flags[@]}"}")
  [[ -n "$jobs" ]] && remote_flags+=(--jobs "$jobs")

  ssh "${ssh_args[@]+"${ssh_args[@]}"}" "$host" bash -seu -s -- \
    ${remote_flags[@]+"${remote_flags[@]}"} <<'REMOTE'
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
