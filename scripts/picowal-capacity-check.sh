#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://wavefunctionlabs.com}"
WARN_PCT="${WARN_PCT:-70}"
CRIT_PCT="${CRIT_PCT:-85}"
TMPDIR="${TMPDIR:-/tmp}"
BODY="$TMPDIR/wfl-picowal-capacity.$$"
trap 'rm -f "$BODY"' EXIT

curl -fsS --max-time "${CURL_MAX_TIME:-10}" "${BASE_URL%/}/metricsz" -o "$BODY"

used=$(awk '$1 == "picowal_used_bytes" { print int($2); found=1 } END { if (!found) exit 1 }' "$BODY")
free=$(awk '$1 == "picowal_free_bytes" { print int($2); found=1 } END { if (!found) exit 1 }' "$BODY")
total=$((used + free))
if [ "$total" -le 0 ]; then
    echo "picowal capacity unavailable: used=$used free=$free" >&2
    exit 2
fi

pct=$((used * 100 / total))
echo "picowal capacity: used=${used}B free=${free}B total=${total}B used_pct=${pct}%"

if [ "$pct" -ge "$CRIT_PCT" ]; then
    echo "critical: picowal usage ${pct}% >= ${CRIT_PCT}%" >&2
    exit 2
fi
if [ "$pct" -ge "$WARN_PCT" ]; then
    echo "warning: picowal usage ${pct}% >= ${WARN_PCT}%" >&2
    exit 1
fi
