import { beforeAll, afterAll } from 'vitest';
import { startServer, stopServer } from './server-manager';
import { resetState } from './helpers';

beforeAll(async () => {
  resetState();
  await startServer();
}, 30000);

afterAll(() => {
  stopServer();
});
