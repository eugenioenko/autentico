import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: ['./setup.ts'],
    setupFiles: ['./setup-per-file.ts'],
    testTimeout: 15000,
    hookTimeout: 60000,
    fileParallelism: false,
  },
});
