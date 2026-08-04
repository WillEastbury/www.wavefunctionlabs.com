const { defineConfig, devices } = require('@playwright/test');

const baseURL = process.env.BASE_URL || 'https://wavefunctionlabs.com';
const hostResolverRules = process.env.HOST_RESOLVER_RULES;

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
    launchOptions: hostResolverRules
      ? { args: [`--host-resolver-rules=${hostResolverRules}`] }
      : undefined,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
