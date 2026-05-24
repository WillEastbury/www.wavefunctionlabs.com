# Release runbook

Production runs picoweb directly on `:443` with embedded picowal storage. Do not
insert a reverse proxy or TLS terminator as a release workaround.

## Build

Use a unique image tag for every release. The Kubernetes manifest uses
`imagePullPolicy: IfNotPresent`, so reusing a tag can keep the old digest on a
node.

```sh
TAG="pNN-short-name-$(date +%H%M)"
az acr build --registry tileforgeacr \
  --image "wfl-www:${TAG}" \
  --platform linux/arm64 \
  --file Dockerfile .
```

Update `k8s/wfl-www.yaml` to `tileforgeacr.azurecr.io/wfl-www:${TAG}` and apply
it:

```sh
kubectl apply -f k8s/wfl-www.yaml
kubectl rollout status deployment/wfl-www -n wfl-www --timeout=180s
```

## Post-rollout smoke

Run the release smoke after every rollout:

```sh
scripts/release-smoke.sh
```

The smoke checks TLS/static content, `/readyz`, `/metricsz`, picowal capacity
metrics, score token issue/write/readback, and that raw `/wal/*` remains
non-public.

## Picowal capacity

Check WAL headroom before storage-sensitive work:

```sh
scripts/picowal-capacity-check.sh
```

If usage is above the warning threshold, follow `k8s/picowal-capacity.md`
before the bounded WAL reaches `507 Insufficient Storage`.

## Rollback

Roll back by setting the deployment image to the last known-good unique tag,
then run the same smoke:

```sh
scripts/rollback-image.sh tileforgeacr.azurecr.io/wfl-www:<known-good-tag>
```

Do not scale beyond the two-node cost limit or add a proxy to mask picoweb
release failures. If picoweb is bad, fix picoweb or roll the image back.
