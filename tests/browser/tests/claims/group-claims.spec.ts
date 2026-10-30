import { test, expect } from '@playwright/test';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';

let base: string;
let directory: string;
let server: ChildProcess;
let token: string;
let groupID: string;

async function api(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') {
  return fetch(base + path, {
    method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test.beforeAll(async () => {
  const listener = createServer();
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  base = `http://localhost:${port}`;
  directory = mkdtempSync(join(tmpdir(), 'autentico-group-claims-browser-'));
  const binary = resolve(process.env.AUTENTICO_TEST_BINARY ?? '../../autentico');
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('AUTENTICO_')) delete env[key];
  Object.assign(env, {
    AUTENTICO_CSRF_SECURE_COOKIE: 'false', AUTENTICO_IDP_SESSION_SECURE: 'false',
    AUTENTICO_RATE_LIMIT_RPS: '0', AUTENTICO_RATE_LIMIT_RPM: '0',
  });
  execFileSync(binary, ['init', '--url', base], { cwd: directory, env, stdio: 'pipe' });
  execFileSync(binary, ['onboard', '--username', 'admin', '--password', 'Password123!', '--email', 'admin@test.com', '--enable-admin-password-grant'], { cwd: directory, env, stdio: 'pipe' });
  server = spawn(binary, ['start'], { cwd: directory, env, stdio: 'ignore' });
  await expect.poll(async () => {
    try { return (await fetch(base + '/.well-known/openid-configuration')).status; }
    catch { return 0; }
  }, { timeout: 15000 }).toBe(200);
  const response = await fetch(base + '/oauth2/token', { method: 'POST', body: new URLSearchParams({
    grant_type: 'password', client_id: 'autentico-admin', username: 'admin', password: 'Password123!', scope: 'openid profile email',
  }) });
  expect(response.status).toBe(200);
  token = (await response.json()).access_token;
  const group = await api('/admin/api/groups', { name: 'app1' });
  expect(group.status).toBe(201);
  groupID = (await group.json()).data.id;
});

test.afterAll(async () => {
  if (server && server.exitCode === null) {
    const exited = new Promise<void>(resolve => server.once('exit', () => resolve()));
    server.kill('SIGTERM');
    await exited;
  }
  if (directory) rmSync(directory, { recursive: true, force: true });
});

test('admin manages group claims and individual overrides through the shared editor', async ({ page }) => {
  await page.goto(base + '/admin/groups');
  await page.locator('#username').fill('admin');
  await page.locator('#password').fill('Password123!');
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/admin/groups');
  const row = page.getByRole('row').filter({ hasText: 'app1' });
  await row.getByRole('button', { name: 'Manage group claims' }).click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('Individual claims with the same full name override group values');
  await drawer.getByRole('textbox', { name: 'Claim name' }).fill('role');
  await drawer.getByRole('textbox', { name: 'Claim value' }).fill('viewer');
  await expect(drawer).toContainText('Emitted name: app1.role');
  await drawer.getByRole('button', { name: /Add$/ }).click();
  await expect(drawer.getByRole('row').filter({ hasText: 'app1.role' })).toContainText('viewer');
  await drawer.getByRole('textbox', { name: 'Claim name' }).fill('role');
  await drawer.getByRole('textbox', { name: 'Claim value' }).fill('editor');
  await drawer.getByRole('button', { name: /Add$/ }).click();
  await expect(drawer.getByRole('row').filter({ hasText: 'app1.role' })).toContainText('editor');
  // Malformed drafts stay visible and do not mutate stored claims.
  await drawer.getByRole('textbox', { name: 'Claim name' }).fill('bad name');
  await drawer.getByRole('button', { name: /Add$/ }).click();
  await expect(page.getByText(/name is invalid:/).first()).toBeVisible();
  expect((await (await api(`/admin/api/groups/${groupID}/claims`)).json()).data).toHaveLength(1);
  await drawer.getByRole('button', { name: 'Close', exact: true }).click();
  // Existing user editor accepts a namespaced override, including without membership.
  await page.goto(base + '/admin/users');
  const admin = page.getByRole('row').filter({ hasText: 'admin@test.com' });
  await admin.getByRole('button', { name: 'Custom claims for admin', exact: true }).click();
  await drawer.getByRole('textbox', { name: 'Claim name' }).fill('app1.role');
  await drawer.getByRole('textbox', { name: 'Claim value' }).fill('owner');
  await drawer.getByRole('button', { name: /Add$/ }).click();
  await expect(drawer.getByRole('row').filter({ hasText: 'app1.role' })).toContainText('owner');
  await drawer.getByRole('button', { name: 'Close', exact: true }).click();
  await page.goto(base + '/admin/groups');
  await row.getByRole('button', { name: 'Edit group', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Renaming the group changes the prefix');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await row.getByRole('button', { name: 'Manage group claims' }).click();
  await drawer.getByRole('button', { name: 'Remove claim role' }).click();
  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(drawer).toContainText('No custom claims');
  expect((await (await api(`/admin/api/groups/${groupID}/claims`)).json()).data).toEqual([]);
});
