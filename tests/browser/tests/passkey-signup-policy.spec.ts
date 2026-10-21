import { test, expect } from '@playwright/test';
import { clearEmails, extractLink, waitForNewEmail } from '../smtp-helper';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, TIMEOUT } from '../server-manager';

let adminToken: string;

test.beforeAll(async () => {
  await startServer();
  adminToken = await getAdminToken();
  await updateSettings(adminToken, {
    allow_self_signup: 'true',
    auth_mode: 'passkey_only',
    require_email_verification: 'true',
    // Verification must still request an address if the profile field is hidden.
    profile_field_email: 'hidden',
    smtp_host: 'localhost',
    smtp_port: '2525',
    smtp_from: 'auth@test.com',
  });
});

test.afterAll(() => stopServer());

test('passkey signup waits for email verification and blocks later unverified login', async ({ page }) => {
  await clearEmails();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**', { timeout: TIMEOUT });
  await page.click('text=Create account');
  await page.fill('#username', 'verified-passkey-signup');
  await expect(page.locator('#email')).toBeVisible();
  await expect(page.locator('#email')).toHaveAttribute('required', '');
  await page.fill('#email', 'verified-passkey@test.com');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/verify-email/pending**', { timeout: TIMEOUT });
  await expect(page.getByTestId('account-dashboard')).not.toBeVisible();
  expect((await page.context().cookies()).some((cookie) => cookie.name.includes('idp_session'))).toBe(false);
  const message = await waitForNewEmail();
  const link = extractLink(message, 'verify-email');
  expect(link).toBeTruthy();

  // Try using the newly created passkey before clicking the email link.
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.fill('#username', 'verified-passkey-signup');
  await page.click('#passkey-login-btn');
  await page.waitForURL('**/verify-email/pending**', { timeout: TIMEOUT });
  await expect(page.getByTestId('account-dashboard')).not.toBeVisible();

  await page.goto(link!);
  await expect(page.getByTestId('account-dashboard')).toBeVisible({ timeout: 15000 });
  await cdp.detach();
});

test('policy changes after the signup page is rendered prevent registration', async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**');
  await page.click('text=Create account');
  await page.fill('#username', 'blocked-passkey-signup');
  await page.fill('#email', 'blocked-passkey@test.com');
  await updateSettings(adminToken, { allow_self_signup: 'false' });
  const response = page.waitForResponse((r) => r.url().includes('/passkey/register/begin'));
  await page.click('button[type="submit"]');
  expect((await response).status()).toBe(403);
  await expect(page.locator('#signup-error')).toContainText('disabled');
});
