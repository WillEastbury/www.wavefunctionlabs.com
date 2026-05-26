# Repository instructions

## Staging browser gate

After a staging rollout completes, gate the deployment with the Playwright smoke
suite:

```sh
kubectl rollout status deployment/wfl-www -n wfl-www-staging --timeout=180s
BASE_URL=https://staging.wavefunctionlabs.com npm run smoke:playwright
```

The test suite is browser-level coverage for the home page, top-level pages,
clean deep article routing, and the wavefunction game/high-score UI. It
complements the production release gate rather than replacing image provenance,
certificate, picowal capacity, or SLO checks.

