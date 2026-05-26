# Agent notes

## Staging browser gate

Use the Playwright smoke suite as the browser-level gate for staging before
promoting a deployment:

```sh
kubectl rollout status deployment/wfl-www -n wfl-www-staging --timeout=180s
BASE_URL=https://staging.wavefunctionlabs.com npm run smoke:playwright
```

The suite covers the home page, top-level pages, clean deep article routes, and
the wavefunction game/high-score UI. It complements the production release gate;
do not treat it as a replacement for Kubernetes/image/cert/picowal/SLO checks.

