import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';
import { join } from 'path';
import { startServer, stopServer, getAdminToken, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';

let admin: string;
const legacyClients = [
  { id: 'legacy-mixed-responses', types: ['code', 'token'] },
  { id: 'legacy-token-response', types: ['id_token'] },
];

test.beforeAll(async () => {
  await startServer(); admin = await getAdminToken();
  for (const client of legacyClients) {
    const response = await fetch(`${BASE_URL}/admin/api/clients`, { method: 'POST',
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' }, body: JSON.stringify({
        client_id: client.id, client_name: client.id, client_type: 'public', token_endpoint_auth_method: 'none',
        redirect_uris: [`${BASE_URL}/legacy-callback`], grant_types: ['authorization_code'], response_types: ['code'], scopes: 'openid',
      }) });
    expect(response.status, await response.text()).toBe(201);
  }
  // Seed historical registrations that the current public API correctly rejects.
  execFileSync('python3', ['-c', `import json, sqlite3, sys
with sqlite3.connect(sys.argv[1]) as database:
    for client in json.loads(sys.argv[2]):
        database.execute('UPDATE clients SET response_types=? WHERE client_id=?', (json.dumps(client['types']), client['id']))
`, join(__dirname, '../../../autentico.db'), JSON.stringify(legacyClients)]);
});
test.afterAll(() => stopServer());

for (const client of legacyClients) {
  test(`legacy ${client.types.join('/')} metadata has an explicit repair path`, async ({ page }) => {
    let updates = 0;
    page.on('request', request => {
      if (request.method() === 'PUT' && request.url().endsWith(`/admin/api/clients/${client.id}`)) updates++;
    });
    await page.goto(`${BASE_URL}/admin/clients`);
    await page.waitForURL('**/oauth2/authorize**');
    await page.fill('#username', ADMIN_USERNAME); await page.fill('#password', ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL('**/admin/**');
    await page.goto(`${BASE_URL}/admin/clients`);
    const row = page.getByRole('row').filter({ hasText: client.id });
    await row.getByRole('button', { name: 'Edit client', exact: true }).click();
    const drawer = page.locator('.ant-drawer-open');
    await expect(drawer.getByText(/This client has unsupported response types/)).toBeVisible();
    await drawer.getByLabel('Client Name', { exact: true }).fill(`${client.id} repaired`);
    await drawer.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(drawer.getByText('Only Code is supported. Remove unsupported response types before saving.')).toBeVisible();
    expect(updates).toBe(0);
    const field = drawer.locator('.ant-form-item:has(label[for="response_types"])');
    for (const unsupported of client.types.filter(value => value !== 'code')) {
      await field.locator('.ant-select-selection-item').filter({ hasText: unsupported }).locator('.ant-select-selection-item-remove').click();
    }
    if (!client.types.includes('code')) {
      await drawer.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(drawer.getByText('Select Code explicitly to replace the legacy response types.')).toBeVisible();
      expect(updates).toBe(0);
      await field.locator('.ant-select-selector').click();
      await page.locator('.ant-select-dropdown:visible').getByText('Code', { exact: true }).click();
    }
    const saved = page.waitForResponse(response => response.request().method() === 'PUT' && response.url().endsWith(`/admin/api/clients/${client.id}`));
    await drawer.getByRole('button', { name: 'Save', exact: true }).click();
    expect((await saved).status()).toBe(200);
    const stored = await fetch(`${BASE_URL}/admin/api/clients/${client.id}`, { headers: { Authorization: `Bearer ${admin}` } });
    expect(stored.status).toBe(200);
    const metadata = await stored.json();
    expect(metadata.response_types).toEqual(['code']);
    expect(metadata.client_name).toBe(`${client.id} repaired`);
  });
}
