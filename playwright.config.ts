import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/desktop/e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:1420',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'desktop-chromium',
      use: {
        ...devices['Desktop Chrome'],
        screen: undefined,
        ...(process.env.RUNNE_PLAYWRIGHT_BROWSER_CHANNEL
          ? { channel: process.env.RUNNE_PLAYWRIGHT_BROWSER_CHANNEL } : {}),
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
  webServer: {
    command: process.env.RUNNE_PLAYWRIGHT_WEB_SERVER_COMMAND ?? 'pnpm dev',
    url: 'http://127.0.0.1:1420',
    reuseExistingServer: !process.env.CI,
  },
})
