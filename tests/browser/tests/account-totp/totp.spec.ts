import { test, expect } from '@playwright/test';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:net';
import { generateFreshTOTP, generateTOTP } from '../../totp-helper';

let base: string;
let directory: string;
let server: ChildProcess;
let adminToken: string;
const password = 'Password123!';

async function adminAPI(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') {
  return fetch(base + '/admin/api' + path, {
    method,
    headers: { Authorization: `Bearer ${adminToken}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test.beforeAll(async () => {
  const listener = createServer();
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = (listener.address() as { port: number }).port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  base = `http://localhost:${port}`;
  directory = mkdtempSync(join(tmpdir(), 'autentico-account-totp-browser-'));
  const binary = resolve(process.env.AUTENTICO_TEST_BINARY ?? '../../autentico');
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('AUTENTICO_')) delete env[key];
  Object.assign(env, {
    AUTENTICO_CSRF_SECURE_COOKIE: 'false', AUTENTICO_IDP_SESSION_SECURE: 'false',
    AUTENTICO_RATE_LIMIT_RPS: '0', AUTENTICO_RATE_LIMIT_RPM: '0',
  });
  execFileSync(binary, ['init', '--url', base], { cwd: directory, env, stdio: 'pipe' });
  execFileSync(binary, ['onboard', '--username', 'admin', '--password', password, '--email', 'admin@test.com', '--enable-admin-password-grant'], { cwd: directory, env, stdio: 'pipe' });
  server = spawn(binary, ['start'], { cwd: directory, env, stdio: 'ignore' });
  await expect.poll(async () => {
    try { return (await fetch(base + '/.well-known/openid-configuration')).status; }
    catch { return 0; }
  }, { timeout: 15000 }).toBe(200);
  const token = await fetch(base + '/oauth2/token', {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'password', client_id: 'autentico-admin', username: 'admin', password, scope: 'openid profile email' }),
  });
  expect(token.status).toBe(200);
  adminToken = (await token.json()).access_token;
  expect((await adminAPI('/settings', {
    require_mfa: 'false', mfa_method: 'totp', require_email_verification: 'false', trust_device_enabled: 'false',
  }, 'PUT')).status).toBe(204);
});

test.afterAll(async () => {
  if (server && server.exitCode === null && server.signalCode === null) {
    const exited = new Promise<void>(resolve => server.once('exit', () => resolve()));
    server.kill('SIGTERM');
    await exited;
  }
  if (directory) rmSync(directory, { recursive: true, force: true });
});

test('enrolls and disables personal TOTP through the account UI with both credentials', async ({ page }) => {
  const created = await adminAPI('/users', { username: 'totp-member', password, email: 'totp-member@test.com' });
  expect(created.status).toBe(201);
  const userID = (await created.json()).data.id;
  const isEnrolled = async () => (await (await adminAPI(`/users/${userID}`)).json()).data.totp_verified;

  await page.goto(base + '/account/security');
  await page.locator('#username').fill('totp-member');
  await page.locator('#password').fill(password);
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/account/security');
  await expect(page.getByText('Not configured', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Set Up', exact: true }).click();
  const setup = page.locator('div.fixed').filter({ has: page.getByRole('heading', { name: 'Set Up Authenticator', exact: true }) });
  await setup.getByLabel('Password', { exact: true }).fill(password);
  await setup.getByRole('button', { name: 'Continue', exact: true }).click();
  const secret = (await setup.locator('code').innerText()).trim();
  expect(secret).toMatch(/^[A-Z2-7]+=*$/);
  expect(await isEnrolled()).toBe(false);
  await setup.getByRole('button', { name: 'Continue', exact: true }).click();
  const enrollmentCode = await generateFreshTOTP(secret);
  await setup.locator('input[inputmode=numeric]').fill(enrollmentCode);
  await setup.getByRole('button', { name: 'Enable 2FA', exact: true }).click();
  await expect(setup).not.toBeVisible();
  await expect(page.getByText('Protecting your account', { exact: true })).toBeVisible();
  expect(await isEnrolled()).toBe(true);

  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  const currentPassword = page.getByLabel('Current password (if set)', { exact: true });
  const code = page.getByLabel('Authenticator code', { exact: true });
  const disable = page.getByRole('button', { name: 'Disable 2FA', exact: true });
  await expect(page.getByText('If you just used a code to sign in or set up 2FA, wait for the next code.')).toBeVisible();
  await expect(page.getByText('Disabling 2FA will sign you out on all devices. Sign in again to continue.')).toBeVisible();

  await page.setViewportSize({ width: 1280, height: 900 });
  const desktopPassword = await currentPassword.boundingBox();
  const desktopCode = await code.boundingBox();
  expect(desktopPassword).not.toBeNull();
  expect(desktopCode).not.toBeNull();
  expect(Math.abs(desktopPassword!.y - desktopCode!.y)).toBeLessThan(1);
  expect(desktopCode!.x).toBeGreaterThan(desktopPassword!.x + desktopPassword!.width);
  await page.screenshot({ path: test.info().outputPath('disable-totp-desktop.png'), fullPage: true, animations: 'disabled' });

  await page.setViewportSize({ width: 390, height: 844 });
  const mobilePassword = await currentPassword.boundingBox();
  const mobileCode = await code.boundingBox();
  expect(mobilePassword).not.toBeNull();
  expect(mobileCode).not.toBeNull();
  expect(mobileCode!.y).toBeGreaterThan(mobilePassword!.y + mobilePassword!.height);
  expect(Math.abs(mobilePassword!.x - mobileCode!.x)).toBeLessThan(1);
  await page.screenshot({ path: test.info().outputPath('disable-totp-mobile.png'), fullPage: true, animations: 'disabled' });
  await page.setViewportSize({ width: 1280, height: 900 });

  await expect(disable).toBeDisabled();
  await currentPassword.fill(password);
  await code.fill('12ab34');
  await expect(code).toHaveValue('1234');
  await expect(disable).toBeDisabled();

  // Canceling discards both credentials, including when toggling the section closed.
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(currentPassword).toHaveValue('');
  await expect(code).toHaveValue('');
  await currentPassword.fill(password);
  await code.fill(enrollmentCode);
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await page.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(currentPassword).toHaveValue('');
  await expect(code).toHaveValue('');

  const submit = async (pw: string, otp: string) => {
    await currentPassword.fill(pw);
    await code.fill(otp);
    const response = page.waitForResponse(r => r.url() === base + '/account/api/mfa/totp' && r.request().method() === 'DELETE');
    await disable.click();
    const result = await response;
    expect(result.request().postDataJSON()).toEqual({ current_password: pw, code: otp });
    return result;
  };

  // The account UI must send both fields; password or code alone cannot disable TOTP.
  expect((await submit('', generateTOTP(secret))).status()).toBe(403);
  await expect(page.getByText('Invalid password or TOTP code', { exact: true })).toBeVisible();
  expect(await isEnrolled()).toBe(true);
  const validCodes = new Set([-1, 0, 1].map(offset => generateTOTP(secret, Date.now() + offset * 30000)));
  let invalid = '000000';
  while (validCodes.has(invalid)) invalid = String(Number(invalid) + 1).padStart(6, '0');
  expect((await submit(password, invalid)).status()).toBe(403);
  expect(await isEnrolled()).toBe(true);
  // Enrollment already consumed this code, even if it is still visible in the app.
  expect((await submit(password, enrollmentCode)).status()).toBe(403);
  expect(await isEnrolled()).toBe(true);

  const fresh = await generateFreshTOTP(secret);
  const removed = await submit(password, fresh);
  expect(removed.status()).toBe(200);
  expect(await isEnrolled()).toBe(false);
  // Disabling MFA revokes the session. Signing in again no longer needs TOTP.
  await page.waitForURL('**/oauth2/authorize**');
  await page.locator('#username').fill('totp-member');
  await page.locator('#password').fill(password);
  await page.locator('button[type=submit]').click();
  await page.waitForURL(base + '/account/security');
  await expect(page.getByText('Not configured', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Set Up', exact: true })).toBeVisible();
});
