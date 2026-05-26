# www.wavefunctionlabs.com

Static WaveFunctionLabs site served by picoweb.

## Browser smoke tests

Install dependencies once:

```sh
npm install
```

Run the browser smoke suite against production:

```sh
npm run smoke:playwright
```

Gate a staging deployment by pointing the same suite at staging:

```sh
kubectl rollout status deployment/wfl-www -n wfl-www-staging --timeout=180s
BASE_URL=https://staging.wavefunctionlabs.com npm run smoke:playwright
```

The Playwright suite checks the home page, top-level navigation pages, a clean
deep article route, and the wavefunction game/high-score UI.

