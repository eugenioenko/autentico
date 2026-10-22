import { afterAll, beforeAll, expect, it } from 'vitest';
import { execFileSync, spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const binary = join(import.meta.dirname, '../../../autentico');
const base = 'http://127.0.0.1:19994';
let directory: string;
let server: ChildProcess | undefined;
let env: NodeJS.ProcessEnv;
let caller: string;
let logs = '';

/** Stop the isolated binary before restarting with the authentication limiter enabled. */
async function stop() {
  if (server && server.exitCode === null) {
    await new Promise<void>(resolve => { server!.once('exit', () => resolve()); server!.kill('SIGTERM'); });
  }
  server = undefined;
}

/** Start the production route configuration and wait through an unthrottled health endpoint. */
async function start(limited: boolean) {
  logs = '';
  server = spawn(binary, ['start'], { cwd: directory,
    env: { ...env, AUTENTICO_RATE_LIMIT_RPS: limited ? '0.001' : '0', AUTENTICO_RATE_LIMIT_BURST: '1', AUTENTICO_RATE_LIMIT_RPM: '0' },
    stdio: 'pipe' });
  server.stdout?.on('data', data => { logs += data.toString(); });
  server.stderr?.on('data', data => { logs += data.toString(); });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try { if ((await fetch(`${base}/healthz`)).ok) return; } catch {}
    if (server.exitCode !== null) throw new Error(`Deletion test server exited: ${logs}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Deletion test server did not start: ${logs}`);
}

/** Obtain credentials while throttling is disabled, keeping the test bucket unused. */
async function token(username: string) {
  const response = await fetch(`${base}/oauth2/token`, { method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'autentico-admin',
      username, password: 'Password123!', scope: 'openid profile email' }) });
  expect(response.status).toBe(200);
  return (await response.json()).access_token as string;
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), 'autentico-deletion-throttle-'));
  env = { ...process.env, AUTENTICO_DB_FILE_PATH: join(directory, 'auth.db'), AUTENTICO_TRUSTED_PROXIES: '',
    AUTENTICO_CSRF_SECURE_COOKIE: 'false', AUTENTICO_IDP_SESSION_SECURE: 'false' };
  execFileSync(binary, ['init', '--url', base], { cwd: directory, env });
  execFileSync(binary, ['onboard', '--username', 'admin', '--password', 'Password123!', '--email', 'admin@test.com', '--enable-admin-password-grant'], { cwd: directory, env });
  await start(false);
  const admin = await token('admin');
  const headers = { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' };
  expect((await fetch(`${base}/admin/api/settings`, { method: 'PUT', headers,
    body: JSON.stringify({ allow_self_service_deletion: 'true', account_lockout_max_attempts: '0' }) })).status).toBe(204);
  expect((await fetch(`${base}/admin/api/users`, { method: 'POST', headers,
    body: JSON.stringify({ username: 'delete-rate-limit', password: 'Password123!', email: 'delete-rate-limit@test.com' }) })).status).toBe(201);
  caller = await token('delete-rate-limit');
  await stop();
  await start(true);
});

afterAll(async () => {
  await stop();
  if (directory) rmSync(directory, { recursive: true, force: true });
});

it('throttles the production deletion POST before repeated password verification', async () => {
  for (let attempt = 0; attempt < 4; attempt++) {
    const response = await fetch(`${base}/account/api/deletion-request`, { method: 'POST',
      headers: { Authorization: `Bearer ${caller}`, 'Content-Type': 'application/json', 'X-Forwarded-For': `203.0.113.${attempt + 1}` },
      body: JSON.stringify({ current_password: 'wrong' }) });
    if (attempt === 0) expect(response.status).toBe(403);
    else {
      expect(response.status).toBe(429);
      expect(response.headers.get('retry-after')).toBe('1');
      expect(await response.json()).toMatchObject({ error: 'too_many_requests' });
    }
  }
  expect((await fetch(`${base}/account/api/profile`, { headers: { Authorization: `Bearer ${caller}` } })).status).toBe(200);
});
