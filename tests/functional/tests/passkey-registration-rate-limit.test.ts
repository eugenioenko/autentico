import { afterAll, beforeAll, expect, it } from 'vitest';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const binary = join(import.meta.dirname, '../../../autentico');
const baseURL = 'http://localhost:19996';
let server: ChildProcess | undefined;
let directory: string | undefined;

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), 'autentico-passkey-rate-'));
  const env = { ...process.env, AUTENTICO_DB_FILE_PATH: join(directory, 'auth.db') };
  execFileSync(binary, ['init', '--url', baseURL], { cwd: directory, env });
  server = spawn(binary, ['start'], {
    cwd: directory,
    env: {
      ...env,
      AUTENTICO_RATE_LIMIT_RPS: '1',
      AUTENTICO_RATE_LIMIT_BURST: '1',
      AUTENTICO_RATE_LIMIT_RPM: '0',
      AUTENTICO_CSRF_SECURE_COOKIE: 'false',
    },
    stdio: 'ignore',
  });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${baseURL}/healthz`)).ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Rate-limited test server failed to start');
});

afterAll(async () => {
  if (server && server.exitCode === null) {
    await new Promise<void>((resolve) => {
      server!.once('exit', () => resolve());
      server!.kill('SIGTERM');
    });
  }
  if (directory) rmSync(directory, { recursive: true, force: true });
});

it('rate-limits registration begin and finish on the production router', async () => {
  for (const [method, path] of [
    ['GET', '/oauth2/passkey/register/begin'],
    ['POST', '/oauth2/passkey/register/finish'],
  ]) {
    // Both routes share the authentication bucket; let one token replenish.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const allowed = await fetch(baseURL + path, { method });
    expect(allowed.status).toBe(400); // Missing fields reach the handler once.
    const blocked = await fetch(baseURL + path, { method });
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('Retry-After')).toBe('1');
    expect((await blocked.json()).error).toBe('too_many_requests');
  }
});
