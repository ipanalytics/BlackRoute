#!/usr/bin/env bash
# Build local/feeds/threatfox_ips.txt from the public ThreatFox IP:port export.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/local/feeds/threatfox_ips.txt}"
EXPORT_URL="${THREATFOX_EXPORT_URL:-https://threatfox.abuse.ch/export/csv/ip-port/full}"

if ! command -v curl >/dev/null; then
  echo "curl is required" >&2
  exit 2
fi
if ! command -v unzip >/dev/null; then
  echo "unzip is required" >&2
  exit 2
fi

tmp_zip="$(mktemp)"
tmp_csv="$(mktemp)"
tmp_out="$(mktemp)"
trap 'rm -f "$tmp_zip" "$tmp_csv" "$tmp_out"' EXIT

mkdir -p "$(dirname "$OUT")"

curl -fsSL \
  --connect-timeout 15 \
  --max-time 120 \
  --retry 2 \
  --retry-delay 2 \
  -A "blackroute-threatfox-export/1.0" \
  "$EXPORT_URL" \
  -o "$tmp_zip"

unzip -p "$tmp_zip" > "$tmp_csv"

awk -F',' '
  /^[[:space:]]*#/ { next }
  NF >= 3 {
    value=$3
    gsub(/"/, "", value)
    split(value, parts, ":")
    ip=parts[1]
    if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
      print ip
    }
  }
' "$tmp_csv" | sort -u > "$tmp_out"

count="$(wc -l < "$tmp_out" | tr -d ' ')"
if [[ "$count" -eq 0 ]]; then
  echo "ThreatFox export returned no IP indicators" >&2
  exit 1
fi

mv "$tmp_out" "$OUT"
echo "Wrote $OUT ($count IPs)"
