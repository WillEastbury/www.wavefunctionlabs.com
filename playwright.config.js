const { defineConfig, devices } = require('@playwright/test');

const baseURL = process.env.BASE_URL || 'https://wavefunctionlabs.com';

module.exports = defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: {
    timeout: 7_500,
  },
  reporter: process.env.CI ? 'github' : [['list']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

