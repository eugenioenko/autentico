import { test, expect } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_PASSWORD } from '../server-manager';

test.describe.configure({ mode: 'serial' });
let admin: string;
/** Inspect isolated test accounts and their audit trail through the admin API. */
async function adminRequest(path: string, method = 'GET', body?: unknown) {
  return fetch(`${BASE_URL}/admin/api/${path}`, { method,
    headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
test.beforeAll(async () => {
  await startServer(); admin = await getAdminToken();
  await updateSettings(admin, { allow_self_service_deletion: 'true', require_email_verification: 'false',
    require_mfa: 'false', profile_field_email: 'required', audit_log_retention: '720h' });
});
test.afterAll(() => stopServer());

test('password deletion requires confirmation and records the deleted actor', async ({ page }) => {
  await updateSettings(admin, { auth_mode: 'password' });
  const username = 'delete-browser-password';
  const created = await adminRequest('users', 'POST', { username, password: ADMIN_PASSWORD, email: `${username}@test.com` });
  expect(created.status).toBe(201);
  const id = (await created.json()).data.id;
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', username); await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await expect(page.getByTestId('account-dashboard')).toBeVisible();
  await page.goto(`${BASE_URL}/account/security`);
  await page.getByRole('button', { name: 'Delete Account', exact: true }).click();
  const form = page.getByTestId('account-deletion-form');
  await form.locator('#deletion-confirm-username').fill(username);
  const submit = form.getByRole('button', { name: 'Delete Account', exact: true });
  await expect(submit).toBeDisabled();
  await form.getByLabel('Current Password').fill('wrong');
  const failed = page.waitForResponse(r => r.url().endsWith('/account/api/deletion-request') && r.request().method() === 'POST');
  await submit.click(); expect((await failed).status()).toBe(403);
  await expect(form.getByText('Current password does not match')).toBeVisible();
  expect((await adminRequest(`users/${id}`)).status).toBe(200);
  await form.getByLabel('Current Password').fill(ADMIN_PASSWORD);
  const deleted = page.waitForResponse(r => r.url().endsWith('/account/api/deletion-request') && r.request().method() === 'POST');
  await submit.click(); expect((await deleted).status()).toBe(204);
  expect((await adminRequest(`users/${id}`)).status).toBe(404);
  const audit = await adminRequest('audit-logs?event=user_deleted');
  expect(audit.status).toBe(200);
  const record = (await audit.json()).data.items.find((entry: { target_id: string }) => entry.target_id === id);
  expect(record).toMatchObject({ actor_id: id, actor_username: username, event: 'user_deleted' });
});

test('passwordless accounts request review and can cancel even with self-service enabled', async ({ page }) => {
  await updateSettings(admin, { auth_mode: 'passkey_only', allow_self_signup: 'true' });
  const username = 'delete-browser-passkey';
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.getByText('Create account', { exact: true }).click();
  await page.fill('#username', username); await page.fill('#email', `${username}@test.com`);
  await page.click('button[type="submit"]');
  await expect(page.getByTestId('account-dashboard')).toBeVisible({ timeout: 15000 });
  await page.goto(`${BASE_URL}/account/security`);
  await page.getByRole('button', { name: 'Delete Account', exact: true }).click();
  const form = page.getByTestId('account-deletion-form');
  await expect(page.getByRole('heading', { name: 'Request Account Deletion', exact: true })).toBeVisible();
  await expect(form.getByLabel('Current Password')).toHaveCount(0);
  await form.locator('#deletion-confirm-username').fill(username);
  const submitted = page.waitForResponse(r => r.url().endsWith('/account/api/deletion-request') && r.request().method() === 'POST');
  await form.getByRole('button', { name: 'Submit Request', exact: true }).click();
  expect((await submitted).status()).toBe(201);
  await expect(page.getByText('Your account remains active until then.', { exact: false })).toBeVisible();
  await expect(page.getByText('Your account has been deleted.', { exact: false })).toHaveCount(0);
  const canceled = page.waitForResponse(r => r.url().endsWith('/account/api/deletion-request') && r.request().method() === 'DELETE');
  await page.getByRole('button', { name: 'Cancel Deletion Request', exact: true }).click();
  expect((await canceled).status()).toBe(204);
  await expect(page.getByRole('button', { name: 'Delete Account', exact: true })).toBeEnabled();
  await cdp.detach();
});
