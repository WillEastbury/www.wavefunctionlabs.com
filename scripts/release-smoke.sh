#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://wavefunctionlabs.com}"
HOST="${HOST:-wavefunctionlabs.com}"
TMPDIR="${TMPDIR:-/tmp}"
BODY="$TMPDIR/wfl-release-smoke-body.$$"
HEADERS="$TMPDIR/wfl-release-smoke-headers.$$"
TOKEN_BODY="$TMPDIR/wfl-release-smoke-token.$$"
LIVE_CERT="$TMPDIR/wfl-release-smoke-live-cert.$$"
SECRET_CERT="$TMPDIR/wfl-release-smoke-secret-cert.$$"
trap 'rm -f "$BODY" "$HEADERS" "$TOKEN_BODY" "$LIVE_CERT" "$SECRET_CERT"' EXIT

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
grep -qi '^Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "$HEADERS"
grep -qi "^Content-Security-Policy: default-src 'self'" "$HEADERS"
grep -qi '^Referrer-Policy: strict-origin-when-cross-origin' "$HEADERS"
grep -qi '^Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()' "$HEADERS"
grep -qi 'WaveFunctionLabs' "$BODY"

if [ "${CHECK_CERT_SECRET:-1}" != "0" ] && command -v openssl >/dev/null 2>&1 && command -v kubectl >/dev/null 2>&1; then
    cert_ns="${CERT_NAMESPACE:-wfl-www}"
    cert_secret="${CERT_SECRET_NAME:-wfl-www-tls}"
    connect_host="${RESOLVE_IP:-$HOST}"
    if kubectl get secret "$cert_secret" -n "$cert_ns" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d > "$SECRET_CERT"; then
        echo | openssl s_client -servername "$HOST" -connect "$connect_host:443" -showcerts 2>/dev/null |
            sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$LIVE_CERT"
        live_fp=$(openssl x509 -in "$LIVE_CERT" -noout -fingerprint -sha256 | sed 's/^.*=//')
        secret_fp=$(openssl x509 -in "$SECRET_CERT" -noout -fingerprint -sha256 | sed 's/^.*=//')
        if [ "$live_fp" != "$secret_fp" ]; then
            echo "live TLS certificate does not match Kubernetes secret $cert_ns/$cert_secret" >&2
            echo "live:   $live_fp" >&2
            echo "secret: $secret_fp" >&2
            exit 1
        fi
        openssl x509 -in "$LIVE_CERT" -noout -checkend "${CERT_MIN_VALID_SECONDS:-1209600}" >/dev/null
    fi
fi

curl "${curl_common[@]}" -o "$BODY" "$(url /readyz)"
grep -q '"status":"ready"' "$BODY"
grep -q '"picowal":"ready"' "$BODY"

curl "${curl_common[@]}" -o "$BODY" "$(url /metricsz)"
grep -q '^picoweb_requests_total' "$BODY"
grep -q '^picowal_recovery_status ' "$BODY"
grep -q '^picowal_used_bytes ' "$BODY"
grep -q '^picowal_free_bytes ' "$BODY"

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
