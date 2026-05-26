# Copilot Instructions — www.wavefunctionlabs.com

## Production architecture invariants (READ FIRST)

These are non-negotiable design rules. Do not violate them silently to keep
the site up; if they conflict with reality, stop and ask the user.

1. **picoweb owns :443 inline.** The production listener is picoweb itself,
   serving TLS in-process via a byte-driven TLS engine over a kernel TCP
   socket. The connection is a single hop from `accept()` through the HTTP
   response — no reverse proxy, no TLS terminator, no service mesh sidecar
   in front. "Fewest hops possible" is the explicit product requirement.

2. **Never swap picoweb out for an nginx (or other) TLS terminator without
   explicit user approval — even temporarily, even to keep the site up.**
   If picoweb is failing, the correct response is to diagnose and fix
   picoweb (or roll the picoweb image back to a known-good tag). Putting
   an nginx terminator in front silently changes the product architecture
   and hides the bug. Past sessions have done this and it was wrong.

3. **AF_PACKET, AF_XDP, io_uring zero-copy, DPDK, etc. are *optional*
   optimisations layered on top of the kernel-socket baseline.** They
   must be CLI/build-flag gated and must not be the only path. The
   kernel-socket TLS path must always remain functional in the same
   image. Do not reintroduce userspace TCP/IP on AKS — kernel conntrack
   and Azure LB reverse-NAT are incompatible with AF_PACKET-emitted
   SYN-ACKs (documented failure mode).

4. **TLS certs come from the `wfl-www-tls` Kubernetes secret** (managed by
   cert-manager with the `letsencrypt-prod` ClusterIssuer) and are
   mounted into the picoweb pod at `/certs/tls.crt` and `/certs/tls.key`.

## Architecture

Static marketing site for WaveFunctionLabs, served by picoweb in a Docker container and deployed to Kubernetes on Azure (ACR: `tileforgeacr.azurecr.io`).

- `wwwroot/wavefunctionlabs.com/` — Main static site tree served by picoweb.
- `wwwroot/wavefunctionlabs.com/_pages/` — Clean URL page content wrapped with shared chrome.
- `wwwroot/wavefunctionlabs.com/wavefunction.html` — Interactive canvas game with high scores.
- `Dockerfile` — Builds picoweb from the vendored `picoweb/` source and packages `wwwroot/`.
- `k8s/wfl-www.yaml` — Deployment, Service, Certificate, and picowal PVC for the main site (`wavefunctionlabs.com` + `www.`).
- `k8s/games.yaml` — Deployment, Service, and Ingress for game subdomains (`bedlam.`, `hambargness.`). These are separate container images, not part of this site's build.

## Build & Deploy

The cluster runs **arm64** nodes. Docker is not available in the dev environment — use `az acr build` to build remotely via ACR Tasks.

```sh
# Build arm64 image via ACR Tasks (no local Docker needed)
az acr build --registry tileforgeacr --image wfl-www:v1arm --platform linux/arm64 --file Dockerfile .

# Roll out to the cluster
kubectl rollout restart deployment/wfl-www -n wfl-www
kubectl rollout status deployment/wfl-www -n wfl-www --timeout=90s

# Verify
kubectl get pods -n wfl-www
```

If you need to run locally for testing, `podman` is available but may not work in all environments:

```sh
podman build -t tileforgeacr.azurecr.io/wfl-www:v1arm .
podman run -p 8080:80 tileforgeacr.azurecr.io/wfl-www:v1arm
```

To apply manifest changes (only needed if `k8s/*.yaml` files change):

```sh
kubectl apply -f k8s/wfl-www.yaml
```

## Browser smoke / staging gate

Playwright browser smoke tests live under `tests/site-smoke.spec.js`.

```sh
npm install
npm run smoke:playwright
```

The suite targets `https://wavefunctionlabs.com` by default. Use `BASE_URL` to gate staging before promotion:

```sh
kubectl rollout status deployment/wfl-www -n wfl-www-staging --timeout=180s
BASE_URL=https://staging.wavefunctionlabs.com npm run smoke:playwright
```

This is a browser-behaviour gate for the home page, top-level pages, clean deep routes, and wavefunction game/high-score UI. It complements, but does not replace, the production release gate (`scripts/release-gate.sh`) for image provenance, cert parity, picowal capacity, smoke, and SLO checks.

## Conventions

- **No app build tooling**: The site is static HTML/CSS/JS served directly by picoweb. npm is present only for Playwright smoke tests.
- **Private ACR base image**: The Dockerfile pulls from `tileforgeacr.azurecr.io/alpine:3.19`, not Docker Hub. Keep this when modifying the Dockerfile.
- **TLS via cert-manager**: Ingress resources use `cert-manager.io/cluster-issuer: letsencrypt-prod` for automatic certificate management.
- **New pages**: Add a `COPY` line to the Dockerfile and ensure `nginx.conf` routing covers the new path. No routing framework exists — Nginx `try_files` handles fallback.
