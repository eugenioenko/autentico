import { test, expect, type Page } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_PASSWORD } from '../server-manager';

let admin: string;
const client = 'consent-browser';
const callback = `${BASE_URL}/consent-browser-callback`;
function authorize(extra: Record<string, string> = {}) {
  return `${BASE_URL}/oauth2/authorize?${new URLSearchParams({ client_id: client, redirect_uri: callback,
    response_type: 'code', scope: 'openid', state: 'consent & browser', prompt: 'consent',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', ...extra })}`;
}
async function changeClient(changes: Record<string, unknown>) {
  const response = await fetch(`${BASE_URL}/admin/api/clients/${client}`, { method: 'PUT',
    headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' }, body: JSON.stringify(changes) });
  expect(response.status, await response.text()).toBe(200);
}
async function login(page: Page, extra: Record<string, string> = {}) {
  await page.goto(authorize(extra));
  await page.fill('#username', 'admin'); await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/oauth2/consent?**');
  await expect(page.locator('[name="consent_flow"]')).toHaveValue(/.+/);
}

test.beforeAll(async () => {
  await startServer(); admin = await getAdminToken();
  const response = await fetch(`${BASE_URL}/admin/api/clients`, { method: 'POST',
    headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' }, body: JSON.stringify({
      client_id: client, client_name: 'Browser consent', redirect_uris: [callback],
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scopes: 'openid',
      client_type: 'public', token_endpoint_auth_method: 'none', consent_required: false,
    }) });
  expect(response.status, await response.text()).toBe(201);
});
test.beforeEach(async () => {
  await updateSettings(admin, { sso_enabled: 'true', sso_session_max_age: '720h', require_mfa: 'false' });
  await changeClient({ consent_required: false, sso_session_idle_timeout: '1h' });
});
test.afterAll(() => stopServer());

test('explicit consent and max_age=0 survive a fresh login with SSO disabled', async ({ page }) => {
  await updateSettings(admin, { sso_enabled: 'false' });
  await login(page, { max_age: '0' });
  await expect(page.locator('[name="max_age"]')).toHaveValue('0');
  await expect(page.locator('[name="prompt"]')).toHaveValue('consent');
  await page.locator('button[value="allow"]').click();
  await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
  expect(new URL(page.url()).searchParams.get('state')).toBe('consent & browser');
});

test('an open consent form cannot outlive the current client idle timeout', async ({ page }) => {
  await login(page);
  await changeClient({ sso_session_idle_timeout: '1s' });
  await page.waitForTimeout(1200);
  const response = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/oauth2/consent'));
  await page.locator('button[value="allow"]').click();
  expect((await response).status()).toBe(401);
  expect(new URL(page.url()).searchParams.get('code')).toBeNull();
});

test('changing a hidden freshness control invalidates consent', async ({ page }) => {
  await login(page, { max_age: '60' });
  await page.locator('[name="max_age"]').evaluate((input: HTMLInputElement) => { input.value = ''; });
  const response = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/oauth2/consent'));
  await page.locator('button[value="allow"]').click();
  expect((await response).status()).toBe(400);
  expect(new URL(page.url()).searchParams.get('code')).toBeNull();
});
