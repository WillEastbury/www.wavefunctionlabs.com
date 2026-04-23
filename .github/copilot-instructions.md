# Copilot Instructions — www.wavefunctionlabs.com

## Architecture

Static marketing site for WaveFunctionLabs, served via Nginx in a Docker container and deployed to Kubernetes on Azure (ACR: `tileforgeacr.azurecr.io`).

- `index.html` — Main landing page. Single self-contained HTML file with inline CSS/JS. Uses [BareMetalJsTools](https://github.com/WillEastbury/BareMetalJsTools) for base styling via CDN.
- `phi.html` — Interactive canvas-based easter egg (wavefunction collapse animation). Standalone, no shared dependencies with `index.html`.
- `nginx.conf` — Nginx server config with SPA-style fallback (`try_files`), gzip, and 1-hour cache on static assets.
- `Dockerfile` — Builds from `tileforgeacr.azurecr.io/nginx:alpine` (private base image, not Docker Hub).
- `k8s/wfl-www.yaml` — Deployment, Service, and Ingress for the main site (`wavefunctionlabs.com` + `www.`).
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

There are no build steps, test suites, or linters — the site is raw HTML/CSS/JS served as static files.

## Conventions

- **No build tooling**: All pages are self-contained HTML files with inline styles and scripts. No bundler, no npm, no framework.
- **Private ACR base image**: The Dockerfile pulls from `tileforgeacr.azurecr.io/nginx:alpine`, not `nginx:alpine`. Keep this when modifying the Dockerfile.
- **TLS via cert-manager**: Ingress resources use `cert-manager.io/cluster-issuer: letsencrypt-prod` for automatic certificate management.
- **New pages**: Add a `COPY` line to the Dockerfile and ensure `nginx.conf` routing covers the new path. No routing framework exists — Nginx `try_files` handles fallback.
