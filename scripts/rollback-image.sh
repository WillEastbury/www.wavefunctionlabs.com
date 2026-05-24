#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 tileforgeacr.azurecr.io/wfl-www:<known-good-tag>" >&2
    exit 2
fi

image="$1"
case "$image" in
    tileforgeacr.azurecr.io/wfl-www:*) ;;
    *)
        echo "rollback image must be a wfl-www image in tileforgeacr.azurecr.io" >&2
        exit 2
        ;;
esac

kubectl set image deployment/wfl-www -n wfl-www "wfl-www=$image"
kubectl rollout status deployment/wfl-www -n wfl-www --timeout="${ROLLOUT_TIMEOUT:-180s}"

BASE_URL="${BASE_URL:-https://wavefunctionlabs.com}" "$(dirname "$0")/release-smoke.sh"
