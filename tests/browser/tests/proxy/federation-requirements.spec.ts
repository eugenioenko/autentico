import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Real production binary behind TLS Caddy. The matcher never contacts this issuer.
const fixture = JSON.parse(readFileSync(process.env.AUTENTICO_PROXY_FIXTURE!, 'utf8'));
const base = '/admin/api/federation';
const tester = `${base}/test-claim-requirements`;
const auth = { Authorization: `Bearer ${fixture.token}`, 'Content-Type': 'application/json' };
async function api(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') {
  return fetch(fixture.admin + path, { method, headers: auth, body: body === undefined ? undefined : JSON.stringify(body) });
}
async function select(page: Page, label: string, option: string) {
  await page.getByRole('combobox', { name: label, exact: true }).click();
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option-content').getByText(option, { exact: true }).click();
}

test('production tester enforces authentication, strict types and bounded unambiguous JSON without saving', async () => {
  expect((await fetch(fixture.admin + tester, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status).toBe(401);
  expect((await fetch(fixture.admin + tester, { method: 'POST', headers: { ...auth, Authorization: 'Bearer invalid' }, body: '{}' })).status).toBe(401);
  const login = await fetch(fixture.admin + '/oauth2/token', { method: 'POST', body: new URLSearchParams({
    grant_type: 'password', client_id: 'autentico-admin', username: 'proxy-user', password: 'Password123!', scope: 'openid profile email',
  }) });
  expect(login.status).toBe(200);
  const regular = (await login.json()).access_token;
  expect((await fetch(fixture.admin + tester, { method: 'POST', headers: { ...auth, Authorization: `Bearer ${regular}` }, body: '{"claim_requirements":[],"claims":{}}' })).status).toBe(403);
  const before = await (await api(base)).json();
  for (const [match, value, claims, passed] of [
    ['equals', true, { email_verified: true }, true], ['equals', false, { email_verified: false }, true],
    ['equals', true, { email_verified: 'true' }, false], ['not_equals', false, { email_verified: true }, true],
    ['not_equals', false, {}, false], ['not_equals', false, { email_verified: null }, false],
    ['not_regex', 'bad', { email_verified: 123 }, false], ['regex', '^good$', { email_verified: 'good' }, true],
    ['regex', '^good$', { email_verified: 'prefixgood' }, false], ['not_regex', 'bad', { email_verified: 'good' }, true],
  ] as const) {
    const response = await api(tester, { claim_requirements: [{ claim: 'email_verified', match, value }], claims });
    expect(response.status).toBe(200); expect((await response.json()).passed).toBe(passed);
    expect(response.headers.getSetCookie()).toEqual([]);
  }
  const invalid = await api(tester, { claim_requirements: [{ claim: 'email', match: 'regex', value: '[' }], claims: {} });
  expect(invalid.status).toBe(200); expect((await invalid.json()).results[0].reason).toBe('invalid_pattern');
  for (const body of [
    '{', '{"claim_requirements":[],"claims":null}', '{"claim_requirements":null,"claims":{}}',
    '{"claim_requirements":[],"claims":{"hd":"a","hd":"b"}}',
    JSON.stringify({ claim_requirements: [], claims: { huge: 'x'.repeat(65536) } }),
  ]) {
    const response = await fetch(fixture.admin + tester, { method: 'POST', headers: auth, body });
    expect(response.status).toBe(400);
  }
  expect(await (await api(base)).json()).toEqual(before);
});

test('admin builds, tests and persists typed requirements; invalid drafts cannot be saved', async ({ page }) => {
  const id = 'requirements-browser';
  await api(`${base}/${id}`, undefined, 'DELETE');
  try {
    await page.goto(fixture.auth + '/admin/federation');
    await page.locator('#username').fill('admin'); await page.locator('#password').fill('Password123!');
    await page.locator('button[type=submit]').click();
    await page.waitForURL(fixture.auth + '/admin/federation');
    await page.getByRole('button', { name: /Add Provider/ }).click();
    await page.getByLabel('Provider ID', { exact: true }).fill(id);
    await page.getByLabel('Display Name', { exact: true }).fill('Requirements browser');
    await page.getByLabel('Issuer URL', { exact: true }).fill('https://issuer.example.invalid');
    await page.locator('input#client_id').fill('browser-client');
    await page.getByLabel('Client Secret', { exact: true }).fill('private-secret');
    await page.getByRole('switch').uncheck();
    await page.getByRole('button', { name: 'Add requirement', exact: true }).click();
    await page.getByLabel('Rule 1 claim', { exact: true }).fill('email_verified');
    await select(page, 'Rule 1 type', 'Boolean'); await select(page, 'Rule 1 value', 'false');
    await page.getByRole('button', { name: 'Add requirement', exact: true }).click();
    await page.getByLabel('Rule 2 claim', { exact: true }).fill('hd');
    await select(page, 'Rule 2 operator', 'regex');
    await page.getByLabel('Rule 2 value', { exact: true }).fill('[');
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(page.getByText('Row 2: invalid pattern', { exact: true })).toBeVisible();
    expect((await api(`${base}/${id}`)).status).toBe(404);
    await page.getByRole('button', { name: 'Test rules', exact: true }).click();
    await page.getByLabel('Sample claims JSON', { exact: true }).fill('{');
    await page.getByRole('button', { name: 'Run test', exact: true }).click();
    await expect(page.getByText('Sample claims must be valid JSON.', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Run test', exact: true })).toBeEnabled();
    await page.getByLabel('Sample claims JSON', { exact: true }).fill('{"email_verified":false,"hd":"mycompany.com"}');
    await page.getByRole('button', { name: 'Run test', exact: true }).click();
    await expect(page.getByText('Row 2 (hd): invalid pattern', { exact: true })).toBeVisible();
    await page.getByRole('dialog', { name: 'Test claim requirements', exact: true }).getByRole('button', { name: 'Close', exact: true }).click();
    await page.getByLabel('Rule 2 value', { exact: true }).fill('^mycompany\\.com$');
    await page.getByRole('button', { name: 'Test rules', exact: true }).click();
    await page.getByRole('button', { name: 'Run test', exact: true }).click();
    await expect(page.getByText('All requirements pass', { exact: true })).toBeVisible();
    expect((await api(`${base}/${id}`)).status).toBe(404);
    await page.getByLabel('Sample claims JSON', { exact: true }).fill('{"email_verified":"false","hd":"mycompany.com"}');
    await page.getByRole('button', { name: 'Run test', exact: true }).click();
    await expect(page.getByText('Row 1 (email_verified): wrong type', { exact: true })).toBeVisible();
    await page.getByRole('dialog', { name: 'Test claim requirements', exact: true }).getByRole('button', { name: 'Close', exact: true }).click();
    await page.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(page.getByText('Federation provider created', { exact: true })).toBeVisible();
    const expected = [{ claim: 'email_verified', match: 'equals', value: false }, { claim: 'hd', match: 'regex', value: '^mycompany\\.com$' }];
    expect((await (await api(`${base}/${id}`)).json()).claim_requirements).toEqual(expected);
    await page.reload();
    const row = page.getByRole('row').filter({ hasText: 'Requirements browser' });
    await row.getByRole('button', { name: 'Edit provider', exact: true }).click();
    await expect(page.getByRole('combobox', { name: 'Rule 1 value', exact: true }).locator('..')).toContainText('false');
    await page.getByRole('button', { name: 'Remove rule 2', exact: true }).click();
    await page.getByRole('button', { name: 'Remove rule 1', exact: true }).click();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.getByText('Federation provider updated', { exact: true })).toBeVisible();
    expect((await (await api(`${base}/${id}`)).json()).claim_requirements).toEqual([]);
  } finally { await api(`${base}/${id}`, undefined, 'DELETE'); }
});
