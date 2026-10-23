import { test, expect, type Cookie, type Page } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_PASSWORD } from '../server-manager';
import { clearEmails, waitForNewEmail, extractMagicLinkCode } from '../smtp-helper';

test.describe.configure({ mode: 'serial' });

let admin: string;
let trusted: Cookie;
let sso: Cookie;
const callback = `${BASE_URL}/client-override-callback`;
function authorize(client: string, prompt = 'login') {
  return `${BASE_URL}/oauth2/authorize?${new URLSearchParams({ client_id: client, redirect_uri: callback,
    response_type: 'code', scope: 'openid', state: 'override-test', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', prompt })}`;
}
async function changeClient(client: string, changes: Record<string, unknown>) {
  const response = await fetch(`${BASE_URL}/admin/api/clients/${client}`, { method: 'PUT',
    headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' }, body: JSON.stringify(changes) });
  expect(response.status, await response.text()).toBe(200);
}
async function login(page: Page, client: string) {
  await page.goto(authorize(client));
  await page.fill('#username', 'admin');
  await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
}

test.beforeAll(async () => {
  await startServer(); admin = await getAdminToken();
  await updateSettings(admin, { auth_mode: 'password', require_mfa: 'false', require_email_verification: 'false', profile_field_email: 'required',
    smtp_host: 'localhost', smtp_port: '2525', smtp_from: 'auth@test.com' });
  for (const [client, overrides] of Object.entries({
    'signup-denied': { allow_self_signup: false }, 'signup-allowed': { allow_self_signup: true },
    'trust-allowed': { trust_device_enabled: true, trust_device_expiration: '48h' },
    'trust-denied': { trust_device_enabled: false },
    'sso-strict': { sso_session_idle_timeout: '1s' }, 'sso-infinite': { sso_session_idle_timeout: '0' },
  })) {
    const response = await fetch(`${BASE_URL}/admin/api/clients`, { method: 'POST',
      headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' }, body: JSON.stringify({
        client_id: client, client_name: client, redirect_uris: [callback], grant_types: ['authorization_code'],
        response_types: ['code'], scopes: 'openid', client_type: 'public', token_endpoint_auth_method: 'none', ...overrides,
      }) });
    expect(response.status, await response.text()).toBe(201);
  }
});
test.afterAll(() => stopServer());

test('client can disable global signup in the UI and direct signed POST', async ({ page }) => {
  await updateSettings(admin, { allow_self_signup: 'true' });
  await page.goto(authorize('signup-denied'));
  await expect(page.getByText('Create account', { exact: true })).toHaveCount(0);
  const fields = await page.locator('form').first().evaluate(form => Object.fromEntries(new FormData(form as HTMLFormElement)));
  const response = await page.request.post(`${BASE_URL}/oauth2/signup`, { form: {
    ...fields, username: 'forbidden-override', password: ADMIN_PASSWORD, confirm_password: ADMIN_PASSWORD, email: 'forbidden@test.com',
  }, headers: { Origin: BASE_URL, Referer: page.url() }, maxRedirects: 0 });
  expect(response.status(), await response.text()).toBe(405);
  await page.goto(authorize('signup-denied', 'create'));
  await expect(page.locator('#confirm_password')).toHaveCount(0);
  const users = await (await fetch(`${BASE_URL}/admin/api/users`, { headers: { Authorization: `Bearer ${admin}` } })).json();
  expect(users.data.items.some((u: { username: string }) => u.username === 'forbidden-override')).toBe(false);
});

test('client can enable signup while globally disabled', async ({ page }) => {
  await updateSettings(admin, { allow_self_signup: 'false' });
  await page.goto(authorize('signup-allowed'));
  await page.getByText('Create account', { exact: true }).click();
  await page.fill('#username', 'allowed-override');
  await page.fill('#email', 'allowed-override@test.com');
  await page.fill('#password', ADMIN_PASSWORD);
  await page.fill('#confirm_password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
});

test('client enables trusted-device UI, current expiry, and password bypass', async ({ page }) => {
  await updateSettings(admin, { require_mfa: 'true', mfa_method: 'email', trust_device_enabled: 'false', trust_device_expiration: '720h' });
  await clearEmails(); await login(page, 'trust-allowed');
  await page.waitForURL('**/oauth2/mfa?**');
  await expect(page.locator('label[for="trust_device"]')).toHaveText('Trust this device for 2 days');
  const otp = extractMagicLinkCode(await waitForNewEmail()); expect(otp).toBeTruthy();
  await changeClient('trust-allowed', { trust_device_enabled: true, trust_device_expiration: '72h' });
  await page.fill('#code', otp!); await page.check('#trust_device'); await page.click('button[type="submit"]');
  await page.waitForURL(`${callback}?**`);
  trusted = (await page.context().cookies()).find(c => c.name === 'autentico_trusted_device')!;
  expect(trusted).toBeTruthy();
  const devicesResponse = await fetch(`${BASE_URL}/account/api/trusted-devices`, { headers: { Authorization: `Bearer ${admin}` } });
  expect(devicesResponse.status).toBe(200);
  const exportedDevices = await devicesResponse.text();
  expect(exportedDevices).not.toContain(trusted.value);
  const devices = JSON.parse(exportedDevices).data;
  expect(devices).toHaveLength(1);
  expect(devices[0].id).not.toBe(trusted.value);
  expect(devices[0]).not.toHaveProperty('token_hash');
  expect(Math.abs(trusted.expires - Date.now() / 1000 - 72 * 3600)).toBeLessThan(5);
  await clearEmails(); await login(page, 'trust-allowed');
  await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
  sso = (await page.context().cookies()).find(c => c.name === 'autentico_idp_session')!;
  expect(sso).toBeTruthy();
});

test('client disables global trusted-device bypass and forged opt-in', async ({ page }) => {
  await updateSettings(admin, { trust_device_enabled: 'true' });
  await page.context().addCookies([trusted]); await clearEmails(); await login(page, 'trust-denied');
  await page.waitForURL('**/oauth2/mfa?**'); await expect(page.locator('#trust_device')).toHaveCount(0);
  const otp = extractMagicLinkCode(await waitForNewEmail()); expect(otp).toBeTruthy();
  await page.locator('form').first().evaluate(form => {
    for (const [name, value] of [['trust_device', 'on'], ['client_id', 'trust-allowed']]) {
      const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.appendChild(input);
    }
  });
  await page.fill('#code', otp!);
  const posted = page.waitForResponse(r => r.url().includes('/oauth2/mfa') && r.request().method() === 'POST');
  await page.click('button[type="submit"]'); const response = await posted;
  expect(response.status()).toBe(302);
  expect((await response.headersArray()).filter(h => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('autentico_trusted_device='))).toHaveLength(0);
  await page.waitForURL(`${callback}?**`);
  expect((await page.context().cookies()).find(c => c.name === trusted.name)?.value).toBe(trusted.value);
});

test('SSO uses strict client timeout and explicit zero override', async ({ page }) => {
  await updateSettings(admin, { sso_session_idle_timeout: '30m' }); await page.context().addCookies([sso]);
  // Shared authenticated SSO is reused even when this client's direct device bypass is disabled.
  await page.goto(authorize('trust-denied', 'none')); await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
  await new Promise(resolve => setTimeout(resolve, 1200));
  await page.goto(authorize('sso-strict', 'none')); await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('error')).toBe('login_required');
  await page.goto(authorize('sso-infinite', 'none')); await page.waitForURL(`${callback}?**`);
  expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();
});
