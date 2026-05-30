import { test, expect } from "@playwright/test";
import {
  startServer,
  stopServer,
  getAdminToken,
  updateSettings,
  BASE_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  TIMEOUT,
} from "../server-manager";

test.beforeAll(async () => {
  await startServer();
});

test.afterAll(() => {
  stopServer();
});

test("admin UI dashboard loads after login", async ({ page }) => {
  await page.goto(`${BASE_URL}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("admin-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });
});

test("admin UI logout requires re-authentication", async ({ page }) => {
  await page.goto(`${BASE_URL}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });

  await page.getByTestId("user-menu").click();
  await page.click("text=Logout");

  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
  await expect(page.getByText("You have been signed out.")).toBeVisible({
    timeout: TIMEOUT,
  });

  await page.goto(`${BASE_URL}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});

test("signup via prompt=create from login page", async ({ page, context }) => {
  const token = await getAdminToken();
  await updateSettings(token, { allow_self_signup: "true" });

  await context.clearCookies();

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.click("text=Create account");

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#confirm_password")).toBeVisible({
    timeout: TIMEOUT,
  });

  await page.fill("#username", "newuser");
  await page.fill("#password", "Password123!");
  await page.fill("#confirm_password", "Password123!");
  await page.click('button[type="submit"]');

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });
});

test("account UI login and dashboard", async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });
});

test("account UI logout requires re-authentication", async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });

  await page.getByTestId("sign-out").click();

  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
  await expect(page.getByText("You have been signed out.")).toBeVisible({
    timeout: TIMEOUT,
  });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});
