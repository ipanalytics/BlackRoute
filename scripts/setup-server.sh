#!/usr/bin/env bash
# Prepare a Linux host for building and running Blackroute.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

section() {
  printf '\n'
  printf '================================================================\n'
  printf '  %s\n' "$1"
  printf '================================================================\n'
}

section "Project"
printf 'Root: %s\n' "$ROOT"

section "System Packages"
if command -v apt-get >/dev/null; then
  sudo apt-get update -qq
  sudo apt-get install -y --no-install-recommends \
    golang-go curl unzip jq file ca-certificates
elif command -v dnf >/dev/null; then
  sudo dnf install -y golang curl unzip jq file ca-certificates
else
  echo "No apt or dnf detected. Install Go, curl, unzip, jq, file, and CA certificates manually."
fi

section "Go Modules"
CACHE_DIR="${BLACKROUTE_CACHE_DIR:-${TMPDIR:-/tmp}/blackroute-go}"
export GOPATH="${GOPATH:-$CACHE_DIR/go}"
export GOMODCACHE="${GOMODCACHE:-$CACHE_DIR/pkg/mod}"
export GOCACHE="${GOCACHE:-$CACHE_DIR/build}"
mkdir -p "$GOMODCACHE" "$GOCACHE"
go mod download

section "Ready"
echo "Run ./run.sh to build the database."
