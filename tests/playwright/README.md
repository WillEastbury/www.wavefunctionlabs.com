# Playwright smoke test

Validates www.wavefunctionlabs.com renders a 200, has the right title,
and has non-empty body content.

```sh
cd tests/playwright
npm init -y
npm install @playwright/test
npx playwright install chromium --with-deps
npx playwright test                                  # default: https://legacy.wavefunctionlabs.com/
SITE_URL=https://www.wavefunctionlabs.com/ npx playwright test
```
