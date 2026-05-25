#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/scripts"

NAMESPACE="${NAMESPACE:-wfl-www}"
DEPLOYMENT="${DEPLOYMENT:-wfl-www}"
CONTAINER="${CONTAINER:-wfl-www}"
MANIFEST="${MANIFEST:-$ROOT/k8s/wfl-www.yaml}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"
GATE_SAMPLE_SECONDS="${GATE_SAMPLE_SECONDS:-${SAMPLE_SECONDS:-60}}"

usage() {
    cat >&2 <<EOF
usage: $0 [--skip-provenance] [--skip-cert] [--skip-slo]

Runs the production release gate for the live wfl-www deployment:
  1. rollout status and manifest/live image consistency
  2. image provenance for the live deployment
  3. TLS certificate Secret/live certificate match
  4. release smoke
  5. picowal capacity check
  6. alerting/SLO sample

Environment:
  NAMESPACE=$NAMESPACE
  DEPLOYMENT=$DEPLOYMENT
  CONTAINER=$CONTAINER
  MANIFEST=$MANIFEST
  ROLLOUT_TIMEOUT=$ROLLOUT_TIMEOUT
  GATE_SAMPLE_SECONDS=$GATE_SAMPLE_SECONDS
EOF
}

skip_provenance=0
skip_cert=0
skip_slo=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-provenance) skip_provenance=1 ;;
        --skip-cert) skip_cert=1 ;;
        --skip-slo) skip_slo=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
    shift
done

step() {
    echo
    echo "==> $*"
}

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 2
    }
}

manifest_image() {
    awk '$1 == "image:" && $2 ~ /^tileforgeacr\.azurecr\.io\/wfl-www:/ { print $2; exit }' "$MANIFEST"
}

live_image() {
    kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
        -o "jsonpath={.spec.template.spec.containers[?(@.name=='$CONTAINER')].image}"
}

require kubectl
require curl

step "checking rollout"
kubectl rollout status "deployment/$DEPLOYMENT" -n "$NAMESPACE" --timeout="$ROLLOUT_TIMEOUT"

step "checking deployment image"
expected_image="$(manifest_image)"
actual_image="$(live_image)"
if [ -z "$expected_image" ]; then
    echo "could not find wfl-www image in $MANIFEST" >&2
    exit 1
fi
if [ "$actual_image" != "$expected_image" ]; then
    echo "live image does not match manifest" >&2
    echo "manifest: $expected_image" >&2
    echo "live:     $actual_image" >&2
    exit 1
fi
echo "image ok: $actual_image"

if [ "$skip_provenance" -eq 0 ]; then
    step "recording image provenance"
    "$SCRIPTS/image-provenance.sh" --live
fi

if [ "$skip_cert" -eq 0 ]; then
    step "checking TLS certificate"
    "$SCRIPTS/cert-rotation-check.sh" --check
fi

step "running release smoke"
"$SCRIPTS/release-smoke.sh"

step "checking picowal capacity"
"$SCRIPTS/picowal-capacity-check.sh"

if [ "$skip_slo" -eq 0 ]; then
    step "sampling alerting/SLO signals"
    SAMPLE_SECONDS="$GATE_SAMPLE_SECONDS" "$SCRIPTS/alerting-slo-check.sh"
fi

echo
echo "release gate ok: $actual_image"
