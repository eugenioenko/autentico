import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globalSetup: ['./setup.ts'],
    testTimeout: 15000,
    hookTimeout: 60000,
    fileParallelism: false,
  },
});
