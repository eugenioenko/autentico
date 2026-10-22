import { test, expect, type Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import { join } from 'path';
import { startServer, stopServer, getAdminToken, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';

let admin: string;
const secrets = new Map<string, string>();
const legacy = [
  { id: 'legacy-auth-confidential', type: 'confidential', method: 'none', effective: 'client_secret_basic' },
  { id: 'legacy-auth-public', type: 'public', method: 'client_secret_basic', effective: 'none' },
];

const legacyFixtures = [...legacy, { id: 'legacy-auth-disabled', type: 'confidential', method: 'none', effective: 'client_secret_basic', disabled: true }];

test.beforeAll(async () => {
  await startServer();
  admin = await getAdminToken();
  for (const client of legacyFixtures) {
    const response = await fetch(`${BASE_URL}/admin/api/clients`, { method: 'POST',
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: client.id, client_name: client.id, client_type: client.type,
        redirect_uris: [`${BASE_URL}/callback`], grant_types: ['password'], scopes: 'openid' }),
    });
    expect(response.status).toBe(201);
    secrets.set(client.id, (await response.json()).client_secret);
  }
  // Existing databases may contain combinations current registration rejects.
  execFileSync('python3', ['-c', `import json, sqlite3, sys
with sqlite3.connect(sys.argv[1]) as database:
    for client in json.loads(sys.argv[2]):
        database.execute('UPDATE clients SET token_endpoint_auth_method=?, is_active=? WHERE client_id=?', (client['method'], not client.get('disabled', False), client['id']))
`, join(__dirname, '../../../autentico.db'), JSON.stringify(legacyFixtures)]);
});
test.afterAll(() => stopServer());

async function openClients(page: Page) {
  await page.goto(`${BASE_URL}/admin/clients`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${BASE_URL}/admin/clients`);
}

async function choose(page: Page, label: string, option: string) {
  await page.getByLabel(label, { exact: true }).click();
  await page.locator('.ant-select-dropdown:visible').getByText(option, { exact: true }).click();
}

test('legacy read and list responses report effective authentication before repair, including disabled clients', async () => {
  const listed = await fetch(`${BASE_URL}/admin/api/clients`, { headers: { Authorization: `Bearer ${admin}` } });
  expect(listed.status).toBe(200);
  const items = (await listed.json()).data.items;
  for (const client of legacyFixtures) {
    const expected = { client_id: client.id, client_type: client.type, token_endpoint_auth_method: client.effective,
      is_active: client.id !== 'legacy-auth-disabled' };
    expect(items.find((item: { client_id: string }) => item.client_id === client.id)).toMatchObject(expected);
    for (const route of ['/admin/api/clients', '/oauth2/register']) {
      const read = await fetch(`${BASE_URL}${route}/${client.id}`, { headers: { Authorization: `Bearer ${admin}` } });
      expect(read.status).toBe(200);
      const metadata = await read.json();
      expect(metadata).toMatchObject(expected);
      expect(metadata).not.toHaveProperty('client_secret');
    }
  }
});

for (const clientType of ['public', 'confidential']) {
  test(`admin creates a consistent ${clientType} client and type changes reset authentication`, async ({ page }) => {
    await openClients(page);
    await page.getByRole('button', { name: /Create Client/ }).click();
    const drawer = page.locator('.ant-drawer-open');
    const method = drawer.locator('.ant-form-item:has(label[for="token_endpoint_auth_method"])');
    await expect(method.locator('.ant-select')).toHaveText('None');
    await choose(page, 'Client Type', 'Confidential');
    await expect(method.locator('.ant-select')).toHaveText('Client Secret Basic');
    await drawer.getByLabel('Client Secret', { exact: true }).fill('temporary-secret');
    if (clientType === 'public') {
      await choose(page, 'Client Type', 'Public');
      await expect(method.locator('.ant-select')).toHaveText('None');
    } else await choose(page, 'Token Endpoint Auth Method', 'Client Secret Post');
    await drawer.getByLabel('Token Endpoint Auth Method', { exact: true }).click();
    const options = page.locator('.ant-select-dropdown:visible .ant-select-item-option-content');
    await expect(options).toHaveText(clientType === 'public' ? ['None'] : ['Client Secret Basic', 'Client Secret Post']);
    await page.keyboard.press('Escape');
    const id = `browser-auth-${clientType}`;
    await drawer.getByLabel('Client Name', { exact: true }).fill(id);
    await drawer.getByLabel('Client ID', { exact: true }).fill(id);
    await drawer.getByPlaceholder('https://example.com/callback', { exact: true }).fill(`${BASE_URL}/callback`);
    const submitted = page.waitForResponse(response => response.request().method() === 'POST' && response.url().endsWith('/admin/api/clients'));
    await drawer.getByRole('button', { name: 'Create', exact: true }).click();
    const response = await submitted;
    expect(response.status(), await response.text()).toBe(201);
    const expectedMethod = clientType === 'public' ? 'none' : 'client_secret_post';
    const metadata = await response.json();
    expect(metadata).toMatchObject({ client_type: clientType, token_endpoint_auth_method: expectedMethod });
    expect(response.request().postDataJSON()).toMatchObject({ client_type: clientType, token_endpoint_auth_method: expectedMethod });
    if (clientType === 'public') {
      expect(metadata).not.toHaveProperty('client_secret');
      expect(response.request().postDataJSON()).not.toHaveProperty('client_secret');
    } else expect(metadata.client_secret).toBe('temporary-secret');
  });
}

for (const client of legacy) {
  test(`legacy ${client.type} client can be edited without changing its secret requirements`, async ({ page }) => {
    await openClients(page);
    const row = page.getByRole('row').filter({ hasText: client.id });
    await row.getByRole('button', { name: 'Edit client', exact: true }).click();
    const drawer = page.locator('.ant-drawer-open');
    await expect(drawer.locator('.ant-form-item:has(label[for="token_endpoint_auth_method"]) .ant-select'))
      .toHaveText(client.type === 'public' ? 'None' : 'Client Secret Basic');
    await drawer.getByLabel('Token Endpoint Auth Method', { exact: true }).click();
    await expect(page.locator('.ant-select-dropdown:visible .ant-select-item-option-content'))
      .toHaveText(client.type === 'public' ? ['None'] : ['Client Secret Basic', 'Client Secret Post']);
    await page.keyboard.press('Escape');
    await drawer.getByLabel('Client Name', { exact: true }).fill(`${client.id} repaired`);
    const saved = page.waitForResponse(response => response.request().method() === 'PUT' && response.url().endsWith(`/admin/api/clients/${client.id}`));
    await drawer.getByRole('button', { name: 'Save', exact: true }).click();
    const response = await saved;
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({ client_type: client.type, token_endpoint_auth_method: client.effective });
    const fields = { grant_type: 'password', client_id: client.id, username: ADMIN_USERNAME, password: ADMIN_PASSWORD, scope: 'openid' };
    const noSecret = await fetch(`${BASE_URL}/oauth2/token`, { method: 'POST', body: new URLSearchParams(fields) });
    expect(noSecret.status).toBe(client.type === 'public' ? 200 : 401);
    if (client.type === 'confidential') {
      const withSecret = await fetch(`${BASE_URL}/oauth2/token`, { method: 'POST', body: new URLSearchParams({ ...fields, client_secret: secrets.get(client.id)! }) });
      expect(withSecret.status).toBe(200);
    }
  });
}
