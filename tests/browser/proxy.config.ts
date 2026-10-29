import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/proxy',
  timeout: 45000,
  workers: 1,
  retries: 0,
  use: {
    trace: 'retain-on-failure', screenshot: 'only-on-failure',
    browserName: 'chromium', headless: true, ignoreHTTPSErrors: true,
    launchOptions: { args: ['--host-resolver-rules=MAP *.test 127.0.0.1', '--no-proxy-server'] },
  },
});
