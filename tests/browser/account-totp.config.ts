import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// This suite owns its server, temporary configuration and database.
export default defineConfig({
  testDir: './tests/account-totp',
  outputDir: join(tmpdir(), 'autentico-account-totp-playwright'),
  timeout: 90000,
  workers: 1,
  retries: 0,
  use: {
    browserName: 'chromium', headless: true,
    screenshot: 'only-on-failure', trace: 'retain-on-failure',
  },
});
