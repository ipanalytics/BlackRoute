#!/usr/bin/env bash
# Build and run Blackroute from the project checkout.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

section() {
  printf '\n'
  printf '================================================================\n'
  printf '  %s\n' "$1"
  printf '================================================================\n'
}

if ! command -v go >/dev/null; then
  echo "Go is not installed. Run scripts/setup-server.sh first." >&2
  exit 1
fi

CACHE_DIR="${BLACKROUTE_CACHE_DIR:-${TMPDIR:-/tmp}/blackroute-go}"
export GOPATH="${GOPATH:-$CACHE_DIR/go}"
export GOMODCACHE="${GOMODCACHE:-$CACHE_DIR/pkg/mod}"
export GOCACHE="${GOCACHE:-$CACHE_DIR/build}"
export HOME="${HOME:-$ROOT}"

mkdir -p release bin "$GOMODCACHE" "$GOCACHE"

section "Build"
go build -o ./bin/blackroute ./cmd/collector

section "Run"
./bin/blackroute \
  --feeds=configs/feeds.yaml \
  --output=release \
  "$@"

section "Outputs"
ls -lh release/blackroute.* release/run_stats.json 2>/dev/null || true
