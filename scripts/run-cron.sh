#!/usr/bin/env bash
# Cron-safe Blackroute wrapper with a local lock and stable cache paths.

set -euo pipefail

if [[ -z "${APP_DIR:-}" ]]; then
  APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
fi

RUN_DIR="$APP_DIR/var/run"
LOG_DIR="$APP_DIR/var/log"
RELEASE_DIR="$APP_DIR/release"
LOCK_FILE="$RUN_DIR/blackroute.lock"
CACHE_DIR="${BLACKROUTE_CACHE_DIR:-${TMPDIR:-/tmp}/blackroute-go}"

export GOPATH="${GOPATH:-$CACHE_DIR/go}"
export GOMODCACHE="${GOMODCACHE:-$CACHE_DIR/pkg/mod}"
export GOCACHE="${GOCACHE:-$CACHE_DIR/build}"
export HOME="${HOME:-$APP_DIR}"

section() {
  printf '%s\n' "[$(date -Is)] ------------------------------------------------------------"
  printf '%s\n' "[$(date -Is)] $1"
}

mkdir -p "$RUN_DIR" "$LOG_DIR" "$RELEASE_DIR" "$APP_DIR/bin" "$GOMODCACHE" "$GOCACHE"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "$(date -Is) Blackroute is already running"
  exit 0
fi

cd "$APP_DIR"
if [[ ! -x ./bin/blackroute ]]; then
  section "Building Blackroute"
  go build -o ./bin/blackroute ./cmd/collector
fi

section "Starting Blackroute"
./bin/blackroute \
  --feeds="$APP_DIR/configs/feeds.yaml" \
  --output="$RELEASE_DIR" \
  "$@"
section "Finished Blackroute"
