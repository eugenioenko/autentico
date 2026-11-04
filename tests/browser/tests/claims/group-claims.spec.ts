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
  await row.getByRole('button', { name: 'More actions for app1' }).click();
  await page.getByRole('menuitem', { name: 'Manage claims', exact: true }).click();
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
  await admin.getByRole('button', { name: 'More actions for admin', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Custom claims', exact: true }).click();
  await drawer.getByRole('textbox', { name: 'Claim name' }).fill('app1.role');
  await drawer.getByRole('textbox', { name: 'Claim value' }).fill('owner');
  await drawer.getByRole('button', { name: /Add$/ }).click();
  await expect(drawer.getByRole('row').filter({ hasText: 'app1.role' })).toContainText('owner');
  await drawer.getByRole('button', { name: 'Close', exact: true }).click();
  await page.goto(base + '/admin/groups');
  await row.getByRole('button', { name: 'Edit group', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Renaming the group changes the prefix');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await row.getByRole('button', { name: 'More actions for app1' }).click();
  await page.getByRole('menuitem', { name: 'Manage claims', exact: true }).click();
  await drawer.getByRole('button', { name: 'Remove claim role' }).click();
  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(drawer).toContainText('No custom claims');
  expect((await (await api(`/admin/api/groups/${groupID}/claims`)).json()).data).toEqual([]);
});

test('user search debounces typing, applies Enter and clear immediately, and survives tab changes', async ({ page }) => {
  await page.goto(base + '/admin/users');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'Password123!');
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/admin/users');
  const admin = page.getByRole('row').filter({ hasText: 'admin@test.com' });
  await expect(admin).toBeVisible();

  await page.clock.install();
  await page.clock.pauseAt(await page.evaluate(() => Date.now() + 1000));
  const search = page.getByRole('searchbox', { name: 'Search users...' });
  const searches: string[] = [];
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.pathname === '/admin/api/users') searches.push(url.searchParams.get('search') ?? '');
  });

  await search.fill('ad');
  await page.clock.runFor(200);
  await search.fill('admin');
  await page.clock.runFor(349);
  expect(searches).toEqual([]);
  const searched = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/admin/api/users' && url.searchParams.get('search') === 'admin';
  });
  await page.clock.runFor(1);
  expect((await searched).status()).toBe(200);
  // Let React Query's notification timers render the response.
  await page.clock.resume();
  await expect(admin).toBeVisible();
  expect(searches).toEqual(['admin']);

  await search.fill('no-matching-user-enter');
  await search.press('Enter');
  await expect(page.getByText('No users found', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Clear search', exact: true }).click();
  await expect(search).toHaveValue('');
  await expect(admin).toBeVisible();
  await page.clock.runFor(350);
  await expect(admin).toBeVisible();

  // Keep time paused so switching tabs always happens before the debounce fires.
  await page.clock.pauseAt(await page.evaluate(() => Date.now() + 1000));
  await search.fill('no-matching-user-tab');
  await page.getByRole('tab', { name: 'Deletion Requests' }).click();
  await page.getByRole('tab', { name: 'Users', exact: true }).click();
  await page.clock.resume();
  await expect(search).toHaveValue('no-matching-user-tab');
  await expect(page.getByText('No users found', { exact: true })).toBeVisible();
  expect(searches).toContain('no-matching-user-tab');
  await page.getByRole('button', { name: 'Clear search', exact: true }).click();
  await expect(admin).toBeVisible();
});

test('row menus retain primary actions and confirm destructive actions before changing data', async ({ page }) => {
  await page.goto(base + '/admin/users');
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'Password123!');
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/admin/users');

  const user = page.getByRole('row').filter({ hasText: 'admin@test.com' });
  await expect(user.getByRole('button', { name: 'Edit user', exact: true })).toBeVisible();
  const userMenu = user.getByRole('button', { name: 'More actions for admin', exact: true });
  await userMenu.click();
  await expect(page.getByRole('menuitem')).toHaveText(['Manage groups', 'Custom claims', 'View sessions', 'Deactivate user']);
  await page.getByRole('menuitem', { name: 'Manage groups', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Groups for admin');
  await page.getByRole('button', { name: 'Close', exact: true }).click();
  await userMenu.click();
  await page.getByRole('menuitem', { name: 'Deactivate user', exact: true }).click();
  const confirmation = page.getByRole('dialog');
  await expect(confirmation).toContainText('Deactivate this user?');
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect((await (await api('/admin/api/users')).json()).data.total).toBe(1);

  await page.goto(base + '/admin/groups');
  const group = page.getByRole('row').filter({ hasText: 'app1' });
  await expect(group.getByRole('button', { name: 'Edit group', exact: true })).toBeVisible();
  await group.getByRole('button', { name: 'More actions for app1', exact: true }).click();
  await expect(page.getByRole('menuitem')).toHaveText(['Manage members', 'Manage claims', 'Delete group']);
  await page.getByRole('menuitem', { name: 'Delete group', exact: true }).click();
  await expect(confirmation).toContainText('Delete this group?');
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect((await api(`/admin/api/groups/${groupID}`)).status).toBe(200);

  await page.goto(base + '/admin/sessions');
  const device = page.getByRole('row').filter({ hasText: 'admin@test.com' }).first();
  await expect(device.getByRole('button', { name: 'View device details', exact: true })).toBeVisible();
  await device.getByRole('button', { name: /^More actions for device / }).click();
  await expect(page.getByRole('menuitem')).toHaveText(['View OAuth sessions', 'Force sign out']);
  await page.getByRole('menuitem', { name: 'Force sign out', exact: true }).click();
  await expect(confirmation).toContainText('Force sign out this device?');
  await confirmation.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(device).toBeVisible();
});

test('member and device-session views have direct routes that survive refresh and browser navigation', async ({ page }) => {
  await page.goto(base + '/admin/groups');
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', 'admin');
  await page.fill('#password', 'Password123!');
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/admin/groups');

  const membersURL = `${base}/admin/groups/${groupID}/members`;
  await page.getByRole('row').filter({ hasText: 'app1' })
    .getByRole('button', { name: 'More actions for app1', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Manage members', exact: true }).click();
  await expect(page).toHaveURL(membersURL);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Members of app1');
  await expect(page.getByRole('table', { name: 'Members of app1', exact: true })).toBeVisible();
  // Check router history separately from reload's fresh OIDC sign-in round trip.
  await page.goBack();
  await expect(page).toHaveURL(base + '/admin/groups');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Groups');
  await page.goForward();
  await expect(page).toHaveURL(membersURL);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Members of app1');
  await page.reload();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Members of app1');
  await expect(page.getByRole('table', { name: 'Members of app1', exact: true })).toBeVisible();

  await page.goto(base + '/admin/sessions');
  const device = page.getByRole('row').filter({ hasText: 'admin@test.com' }).first();
  await device.getByRole('button', { name: /^More actions for device / }).click();
  await page.getByRole('menuitem', { name: 'View OAuth sessions', exact: true }).click();
  await expect(page).toHaveURL(/\/admin\/sessions\/[^/]+\/devices\/[^/]+$/);
  const deviceURL = page.url();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('OAuth Sessions for admin');
  await expect(page.getByRole('table', { name: 'OAuth sessions', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(base + '/admin/sessions');
  await page.goForward();
  await expect(page).toHaveURL(deviceURL);
  await page.reload();
  await expect(page).toHaveURL(deviceURL);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('OAuth Sessions for admin');
  await expect(page.getByRole('table', { name: 'OAuth sessions', exact: true })).toBeVisible();

  await page.goto(base + '/admin/groups/missing/members');
  await expect(page.getByText('Group not found or unavailable', { exact: true })).toBeVisible();
  await page.goto(deviceURL.replace(/\/devices\/[^/]+$/, '/devices/missing'));
  await expect(page.getByText('Device session not found', { exact: true })).toBeVisible();
});
