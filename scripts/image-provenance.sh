#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${REGISTRY:-tileforgeacr}"
REGISTRY_HOST="${REGISTRY_HOST:-tileforgeacr.azurecr.io}"
NAMESPACE="${NAMESPACE:-wfl-www}"
DEPLOYMENT="${DEPLOYMENT:-wfl-www}"
CONTAINER="${CONTAINER:-wfl-www}"
BASE_REPOSITORY="${BASE_REPOSITORY:-alpine}"
BASE_TAG="${BASE_TAG:-3.19}"

usage() {
    cat >&2 <<USAGE
usage:
  $0 --image tileforgeacr.azurecr.io/wfl-www:<tag>
  $0 --live

Print release provenance for the runtime image, current base image tag, and
the live Kubernetes deployment. Requires az and, for --live, kubectl.
USAGE
}

image=""
if [ "$#" -eq 1 ] && [ "$1" = "--live" ]; then
    image=$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
        -o "jsonpath={.spec.template.spec.containers[?(@.name=='$CONTAINER')].image}")
elif [ "$#" -eq 2 ] && [ "$1" = "--image" ]; then
    image="$2"
else
    usage
    exit 2
fi

case "$image" in
    "$REGISTRY_HOST"/wfl-www:*) ;;
    *)
        echo "image must be $REGISTRY_HOST/wfl-www:<tag>, got: $image" >&2
        exit 2
        ;;
esac

repo_tag="${image#"$REGISTRY_HOST"/}"
repository="${repo_tag%%:*}"
tag="${repo_tag##*:}"

digest_for_tag() {
    local repository="$1"
    local tag="$2"
    az acr manifest list-metadata \
        --registry "$REGISTRY" \
        --name "$repository" \
        --query "[?tags[?@=='$tag']].digest | [0]" \
        -o tsv
}

runtime_digest=$(digest_for_tag "$repository" "$tag")
base_digest=$(digest_for_tag "$BASE_REPOSITORY" "$BASE_TAG")

if [ -z "$runtime_digest" ]; then
    echo "runtime digest not found for $repository:$tag in $REGISTRY" >&2
    exit 1
fi
if [ -z "$base_digest" ]; then
    echo "base digest not found for $BASE_REPOSITORY:$BASE_TAG in $REGISTRY" >&2
    exit 1
fi

cat <<EOF
image=$image
image_digest=$REGISTRY_HOST/$repository@$runtime_digest
base_image=$REGISTRY_HOST/$BASE_REPOSITORY:$BASE_TAG
base_digest=$REGISTRY_HOST/$BASE_REPOSITORY@$base_digest
git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
