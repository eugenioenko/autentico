import { test, expect, type Locator } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';

test.beforeAll(async () => {
  await startServer();
  await updateSettings(await getAdminToken(), { allow_self_signup: 'true', require_email_verification: 'false' });
});
test.afterAll(() => stopServer());

async function expectToggle(input: Locator, value: string) {
  const wrapper = input.locator('..');
  const toggle = wrapper.getByRole('button');
  await expect(input).toHaveAttribute('type', 'password');
  await input.fill(value);
  const name = await input.getAttribute('name');
  const autocomplete = await input.getAttribute('autocomplete');
  await expect(toggle).toHaveAttribute('type', 'button');
  await expect(toggle).toHaveAttribute('aria-label', 'Show password');
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  await toggle.focus();
  await toggle.press('Space');
  await expect(input).toHaveAttribute('type', 'text');
  await expect(toggle).toHaveAttribute('aria-label', 'Hide password');
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(input).toHaveValue(value);
  expect(await input.getAttribute('name')).toBe(name);
  expect(await input.getAttribute('autocomplete')).toBe(autocomplete);
  await toggle.press('Enter');
  await expect(input).toHaveAttribute('type', 'password');
  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  await expect(input).toHaveValue(value);
}

for (const colorScheme of ['light', 'dark'] as const) {
  test(`login toggle preserves credentials without submitting (${colorScheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme });
    const violations: string[] = [];
    page.on('console', msg => { if (msg.text().includes('Content Security Policy')) violations.push(msg.text()); });
    let submissions = 0;
    page.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/login')) submissions++;
    });
    await page.goto(`${BASE_URL}/account/`);
    await page.fill('#username', ADMIN_USERNAME);
    await expectToggle(page.locator('#password'), ADMIN_PASSWORD);
    expect(submissions).toBe(0);
    await page.getByRole('button', { name: 'Show password' }).click();
    await page.locator('button[type="submit"]').click();
    await expect(page.getByTestId('account-dashboard')).toBeVisible();
    expect(submissions).toBe(1);
    expect(violations).toEqual([]);
  });
}

test('signup fields toggle independently and reload masked', async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.getByText('Create account', { exact: true }).click();
  await expectToggle(page.locator('#password'), 'NewPassword123!');
  await page.locator('#password').locator('..').getByRole('button').click();
  await expect(page.locator('#confirm_password')).toHaveAttribute('type', 'password');
  await expectToggle(page.locator('#confirm_password'), 'NewPassword123!');
  await expect(page.locator('#password')).toHaveAttribute('type', 'text');
  // A delayed initial pageshow must not undo an explicit reveal while resources load.
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: false })));
  await expect(page.locator('#password')).toHaveAttribute('type', 'text');
  // A history-cache restore must re-mask a previously revealed secret.
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await expect(page.locator('#password')).toHaveAttribute('type', 'password');
  await page.locator('#password').locator('..').getByRole('button').click();
  await page.reload();
  await expect(page.locator('#password')).toHaveAttribute('type', 'password');
  await expect(page.locator('#confirm_password')).toHaveAttribute('type', 'password');
});

test('server password inputs remain usable without JavaScript', async ({ page, browser }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL('**/oauth2/authorize**');
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const noJS = await context.newPage();
    await noJS.goto(page.url());
    await expect(noJS.locator('#password')).toHaveAttribute('type', 'password');
    await expect(noJS.getByRole('button', { name: 'Show password' })).toHaveCount(0);
    await noJS.fill('#username', ADMIN_USERNAME);
    await noJS.fill('#password', ADMIN_PASSWORD);
    await noJS.locator('button[type="submit"]').click();
    await noJS.waitForURL('**/account/**');
  } finally {
    await context.close();
  }
});

test('change-password toggles are independent and reset on reopening', async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByTestId('account-dashboard')).toBeVisible();
  await page.goto(`${BASE_URL}/account/security`);
  await page.getByRole('button', { name: 'Change Password', exact: true }).click();
  let submissions = 0;
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/password')) submissions++;
  });
  const current = page.getByLabel('Current Password', { exact: true });
  const next = page.getByLabel('New Password', { exact: true });
  const confirm = page.getByLabel('Confirm New Password', { exact: true });
  await expectToggle(current, ADMIN_PASSWORD);
  await expectToggle(next, 'NewPassword123!');
  await expectToggle(confirm, 'NewPassword123!');
  await current.locator('..').getByRole('button').click();
  await expect(next).toHaveAttribute('type', 'password');
  await expect(confirm).toHaveAttribute('type', 'password');
  expect(submissions).toBe(0);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('button', { name: 'Change Password', exact: true }).click();
  for (const input of [current, next, confirm]) {
    await expect(input).toHaveAttribute('type', 'password');
    await expect(input).toHaveValue('');
  }
});
