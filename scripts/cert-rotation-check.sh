#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---check}"
HOST="${HOST:-wavefunctionlabs.com}"
NAMESPACE="${CERT_NAMESPACE:-wfl-www}"
SECRET="${CERT_SECRET_NAME:-wfl-www-tls}"
DEPLOYMENT="${DEPLOYMENT:-wfl-www}"
TMPDIR="${TMPDIR:-/tmp}"
LIVE_CERT="$TMPDIR/wfl-live-cert.$$"
SECRET_CERT="$TMPDIR/wfl-secret-cert.$$"
trap 'rm -f "$LIVE_CERT" "$SECRET_CERT"' EXIT

usage() {
    cat >&2 <<EOF
usage: $0 [--check|--restart-if-needed]

Compares the live picoweb TLS certificate with the cert-manager Secret.
--check exits non-zero on mismatch. --restart-if-needed performs a controlled
Deployment restart, waits for rollout, then verifies the live certificate.
EOF
}

case "$MODE" in
    --check|--restart-if-needed) ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
esac

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 2
    }
}

require kubectl
require openssl
require base64

connect_host="${RESOLVE_IP:-$HOST}"

fetch_secret_cert() {
    kubectl get secret "$SECRET" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' |
        base64 -d > "$SECRET_CERT"
}

fetch_live_cert() {
    echo | openssl s_client -servername "$HOST" -connect "$connect_host:443" -showcerts 2>/dev/null |
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$LIVE_CERT"
}

fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/^.*=//'
}

matches_secret() {
    fetch_secret_cert
    fetch_live_cert
    live_fp="$(fingerprint "$LIVE_CERT")"
    secret_fp="$(fingerprint "$SECRET_CERT")"
    [ "$live_fp" = "$secret_fp" ]
}

if matches_secret; then
    echo "certificate ok: live $HOST matches $NAMESPACE/$SECRET"
    openssl x509 -in "$LIVE_CERT" -noout -subject -issuer -dates
    exit 0
fi

echo "certificate mismatch: live $HOST does not match $NAMESPACE/$SECRET" >&2
echo "live:   $live_fp" >&2
echo "secret: $secret_fp" >&2

if [ "$MODE" = "--check" ]; then
    exit 1
fi

kubectl rollout restart "deployment/$DEPLOYMENT" -n "$NAMESPACE"
kubectl rollout status "deployment/$DEPLOYMENT" -n "$NAMESPACE" --timeout="${ROLLOUT_TIMEOUT:-120s}"

if ! matches_secret; then
    echo "certificate still mismatched after rollout" >&2
    echo "live:   $live_fp" >&2
    echo "secret: $secret_fp" >&2
    exit 1
fi

"$(dirname "$0")/release-smoke.sh"
echo "certificate rotation complete: live $HOST now matches $NAMESPACE/$SECRET"
