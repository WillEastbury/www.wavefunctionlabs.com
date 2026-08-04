const { test, expect } = require('@playwright/test');

const topLevelRoutes = [
  ['/cognition', 'Cognition'],
  ['/ai', 'How AI Actually Works'],
  ['/transformers', 'How a Transformer Produces One Token'],
  ['/ducks', 'Ducks All the Way Down'],
  ['/forge', 'Forge'],
  ['/swarm', 'Swarm'],
  ['/metal', 'Metal'],
  ['/play', 'Play'],
  ['/collapse', 'Metaphor'],
  ['/broadcast', 'Broadcast'],
  ['/me', 'Will Eastbury'],
  ['/signal', 'Signal (CV)'],
];

async function gotoOk(page, path) {
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));

  const response = await page.goto(path, { waitUntil: 'domcontentloaded' });
  expect(response, `${path} response`).not.toBeNull();
  expect(response.status(), `${path} status`).toBeLessThan(400);

  return pageErrors;
}

test('home page shell renders core content', async ({ page }) => {
  const pageErrors = await gotoOk(page, '/');

  await expect(page).toHaveTitle(/WaveFunctionLabs/);
  await expect(page.locator('nav.wf-nav')).toBeVisible();
  await expect(page.locator('.wf-section')).toBeVisible();
  await expect(page.getByText('Be the full wave function.')).toBeVisible();
  await expect(page.getByText('When imagination meets physics')).toBeVisible();
  await expect(page.locator('#waveCanvas')).toBeAttached();
  await expect(page.locator('footer.wf-footer')).toContainText('wavefunctionlabs');
  expect(pageErrors, 'page JavaScript errors').toEqual([]);
});

test('top-level pages render with the matching active nav item', async ({ page }) => {
  for (const [path, heading] of topLevelRoutes) {
    const pageErrors = await gotoOk(page, path);
    const navPath = `/${path.split('/')[1]}`;

    await expect(page.locator('nav.wf-nav')).toBeVisible();
    await expect(page.locator(`.wf-nav-links a[href="${navPath}"]`)).toHaveClass(/active/);
    await expect(page.locator('h1.wf-section-hdr')).toContainText(heading);
    await expect(page.locator('footer.wf-footer')).toContainText('wavefunctionlabs');
    expect(pageErrors, `${path} page JavaScript errors`).toEqual([]);
  }
});

test('deep article routes render directly from clean URLs', async ({ page }) => {
  const pageErrors = await gotoOk(page, '/metal/picowal');

  await expect(page.locator('.wf-nav-links a[href="/metal"]')).toHaveClass(/active/);
  await expect(page.locator('h1.wf-section-hdr')).toContainText('PicoWAL');
  await expect(page.locator('main, .wf-section').first()).toContainText('write-ahead log');
  expect(pageErrors, 'page JavaScript errors').toEqual([]);
});

test('Transformer technical book and chapters render from clean URLs', async ({ page }) => {
  let pageErrors = await gotoOk(page, '/transformers');

  await expect(page.locator('.wf-nav-links a[href="/transformers"]')).toHaveClass(/active/);
  await expect(page.locator('h1.wf-section-hdr')).toContainText('How a Transformer Produces One Token');
  await expect(page.locator('a[href="/transformers/ch1"]').first()).toBeVisible();
  expect(pageErrors, 'Transformer landing page JavaScript errors').toEqual([]);

  pageErrors = await gotoOk(page, '/transformers/ch1');
  await expect(page.locator('h1.wf-section-hdr')).toContainText("A Single Token's Journey");
  await expect(page.locator('.wf-article-body')).toContainText('Five integers');
  expect(pageErrors, 'Transformer chapter JavaScript errors').toEqual([]);
});

test('wavefunction game page loads, starts, and shows high scores', async ({ page }) => {
  const pageErrors = await gotoOk(page, '/wavefunction.html');

  await expect(page).toHaveTitle(/WaveFunctionLabs|Be The Wavefunction/);
  await expect(page.locator('#screen-title')).toHaveClass(/active/);
  await expect(page.getByRole('heading', { name: 'Be The Wavefunction' })).toBeVisible();

  await page.locator('#screen-title').getByRole('button', { name: 'HIGH SCORES' }).click();
  await expect(page.locator('#screen-scores')).toHaveClass(/active/);
  await expect(page.locator('#scores-alltime li').first()).toBeVisible();
  await expect(page.locator('#scores-today li').first()).toBeVisible();

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.locator('#screen-title')).toHaveClass(/active/);
  await page.locator('#screen-title').getByRole('button', { name: 'COLLAPSE INTO REALITY' }).click({ force: true });
  await expect(page.locator('#hud')).toBeVisible();
  expect(pageErrors, 'page JavaScript errors').toEqual([]);
});
