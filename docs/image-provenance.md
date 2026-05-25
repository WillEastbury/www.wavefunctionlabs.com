# Image provenance and dependency updates

Production images are built by Azure Container Registry Tasks from this
repository. Docker is not required locally.

## Build provenance

Use a unique runtime tag for every release:

```sh
TAG="pNN-short-name-$(date +%H%M)"
az acr build --registry tileforgeacr \
  --image "wfl-www:${TAG}" \
  --platform linux/arm64 \
  --file Dockerfile .
```

Record the immutable digests after the build:

```sh
scripts/image-provenance.sh --image "tileforgeacr.azurecr.io/wfl-www:${TAG}"
```

The output captures:

- the mutable release tag,
- the immutable runtime image digest,
- the current private ACR Alpine base image digest,
- the git commit used by the operator checkout,
- the UTC generation time.

Keep the digest output with the release notes or PR description. Kubernetes
continues to deploy the unique tag because `imagePullPolicy: IfNotPresent`
requires a new tag to force pulls reliably on the node.

## Live verification

After rollout, confirm the live deployment still points at the expected tag and
record its digest:

```sh
scripts/image-provenance.sh --live
kubectl get pods -n wfl-www -l app=wfl-www \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.name}{"\t"}{.image}{"\t"}{.imageID}{"\n"}{end}{end}'
```

If the tag and pulled digest disagree with the release notes, stop and resolve
the image mismatch before continuing.

## Dependency update cadence

- Review `tileforgeacr.azurecr.io/alpine:3.19` at least monthly and whenever
  Alpine publishes a security advisory relevant to musl, OpenSSL-compatible TLS
  dependencies, brotli, gcc runtime, or iproute2.
- Refresh the private ACR base tag deliberately; do not silently switch the
  Dockerfile to Docker Hub images.
- For base-image refreshes, build a new unique `wfl-www` tag, run
  `scripts/release-smoke.sh`, `scripts/alerting-slo-check.sh`, and retain the
  provenance output in the PR.
- Picoweb, picowal, and BareMetalJsTools updates should be reviewed as source
  changes in this repository or upstream PRs, not pulled implicitly at image
  build time.
