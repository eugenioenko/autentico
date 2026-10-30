import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// This suite owns an isolated temporary database, configuration, and server.
export default defineConfig({
  testDir: './tests/claims',
  outputDir: join(tmpdir(), 'autentico-group-claims-playwright'),
  timeout: 45000,
  workers: 1,
  retries: 0,
  use: {
    browserName: 'chromium', headless: true,
    screenshot: 'only-on-failure', trace: 'retain-on-failure',
  },
});
