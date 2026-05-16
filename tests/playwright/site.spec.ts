import { test, expect } from '@playwright/test';

const URL = process.env.SITE_URL || 'https://legacy.wavefunctionlabs.com/';

test('site loads, has expected title and content', async ({ page }) => {
  const resp = await page.goto(URL, { waitUntil: 'domcontentloaded', timeout: 15000 });
  expect(resp, 'response object').not.toBeNull();
  expect(resp!.status(), 'http status').toBe(200);
  await expect(page).toHaveTitle(/WaveFunctionLabs/i);
  const body = await page.locator('body').innerText();
  expect(body.length, 'body innerText length').toBeGreaterThan(50);
});
