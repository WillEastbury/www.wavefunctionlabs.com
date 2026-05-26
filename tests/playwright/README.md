# Playwright smoke tests

The active Playwright suite is at `../site-smoke.spec.js` and runs from the
repository root.

```sh
npm install
npm run smoke:playwright
BASE_URL=https://staging.wavefunctionlabs.com npm run smoke:playwright
```

Use the `BASE_URL` form as the browser-level staging deployment gate after the
staging rollout has completed.
