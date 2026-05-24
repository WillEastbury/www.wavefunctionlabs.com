#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://wavefunctionlabs.com}"
HOST="${HOST:-wavefunctionlabs.com}"
TMPDIR="${TMPDIR:-/tmp}"
BODY="$TMPDIR/wfl-release-smoke-body.$$"
HEADERS="$TMPDIR/wfl-release-smoke-headers.$$"
TOKEN_BODY="$TMPDIR/wfl-release-smoke-token.$$"
trap 'rm -f "$BODY" "$HEADERS" "$TOKEN_BODY"' EXIT

curl_common=(--silent --show-error --fail --max-time "${CURL_MAX_TIME:-10}" --resolve "$HOST:443:${RESOLVE_IP:-}")
if [ -z "${RESOLVE_IP:-}" ]; then
    curl_common=(--silent --show-error --fail --max-time "${CURL_MAX_TIME:-10}")
fi

url() {
    printf '%s%s' "${BASE_URL%/}" "$1"
}

expect_code() {
    local expected="$1"; shift
    local got
    got=$(curl --silent --show-error --max-time "${CURL_MAX_TIME:-10}" \
        -o "$BODY" -w '%{http_code}' "$@")
    if [ "$got" != "$expected" ]; then
        echo "expected HTTP $expected, got $got for $*" >&2
        head -c 500 "$BODY" >&2 || true
        echo >&2
        exit 1
    fi
}

curl "${curl_common[@]}" -D "$HEADERS" -o "$BODY" "$(url /)"
grep -qi '^HTTP/.* 200' "$HEADERS"
grep -qi 'WaveFunctionLabs' "$BODY"

curl "${curl_common[@]}" -o "$BODY" "$(url /readyz)"
grep -q '"status":"ready"' "$BODY"
grep -q '"picowal":"ready"' "$BODY"

curl "${curl_common[@]}" -o "$BODY" "$(url /metricsz)"
grep -q '^picoweb_requests_total' "$BODY"
grep -q '^picowal_recovery_status ' "$BODY"

expect_code 404 "$(url /wal/42)"

curl "${curl_common[@]}" -X POST -o "$TOKEN_BODY" "$(url /api/scores/start)"
token=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$TOKEN_BODY")
if [ -z "$token" ]; then
    echo "score token missing from /api/scores/start response" >&2
    cat "$TOKEN_BODY" >&2
    exit 1
fi

name="${SCORE_SMOKE_NAME:-smoke}"
score="${SCORE_SMOKE_SCORE:-1}"
expect_code 201 \
    -H 'Content-Type: application/json' \
    -H "X-Score-Token: $token" \
    -d "{\"name\":\"$name\",\"score\":$score}" \
    "$(url /api/scores)"

curl "${curl_common[@]}" -o "$BODY" "$(url /api/scores)"
grep -q "\"name\":\"$name\"" "$BODY"
grep -q "\"score\":$score" "$BODY"

echo "release smoke ok: $BASE_URL"
