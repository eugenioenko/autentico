import { test, expect } from '@playwright/test';
import { startServer, stopServer, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';

test.beforeAll(() => startServer());
test.afterAll(() => stopServer());
test.beforeEach(async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByTestId('account-dashboard')).toBeVisible();
});

test('desktop sidebar stays in view throughout a long page', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  // Simulate a long account page without coupling layout coverage to session fixtures.
  await page.locator('main').evaluate(el => { el.style.minHeight = '3000px'; });
  for (const scrollY of [0, 1000, 3000]) {
    await page.evaluate(y => window.scrollTo(0, y), scrollY);
    await expect(page.getByTestId('sign-out')).toBeInViewport({ ratio: 1 });
    const sidebar = await page.locator('aside').boundingBox();
    expect(sidebar?.y).toBe(0);
    expect(sidebar?.height).toBe(720);
  }
});

test('short desktop viewport scrolls only navigation', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 320 });
  const nav = page.locator('aside nav');
  expect(await nav.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true);
  await expect(page.locator('aside img')).toBeInViewport({ ratio: 1 });
  await expect(page.getByTestId('sign-out')).toBeInViewport({ ratio: 1 });
  await nav.evaluate(el => { el.scrollTop = el.scrollHeight; });
  expect(await nav.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  await expect(nav.getByText('Connected Providers')).toBeInViewport({ ratio: 0.99 });
  await expect(page.locator('aside img')).toBeInViewport({ ratio: 1 });
  await expect(page.getByTestId('sign-out')).toBeInViewport({ ratio: 1 });
});

test('mobile drawer opens, scrolls navigation and closes', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 320 });
  await expect(page.getByTestId('sign-out')).not.toBeInViewport();
  await page.locator('main header button').first().click();
  await expect(page.getByTestId('sign-out')).toBeInViewport({ ratio: 1 });
  const nav = page.locator('aside nav');
  await nav.evaluate(el => { el.scrollTop = el.scrollHeight; });
  expect(await nav.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  await nav.getByText('Connected Providers').click();
  await expect(page.getByTestId('sign-out')).not.toBeInViewport();
  await page.locator('main header button').first().click();
  await expect(page.getByTestId('sign-out')).toBeInViewport({ ratio: 1 });
  await page.locator('aside button').first().click();
  await expect(page.getByTestId('sign-out')).not.toBeInViewport();
});
