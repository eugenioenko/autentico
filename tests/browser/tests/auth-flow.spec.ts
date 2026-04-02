import { test, expect } from "@playwright/test";

const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "Password123!";
const ADMIN_EMAIL = "admin@test.com";
const TIMEOUT = 5000;

test("onboarding creates admin account", async ({ page }) => {
  await page.goto("/onboard");
  await expect(page.getByTestId("onboard-title")).toBeVisible({ timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#email", ADMIN_EMAIL);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.fill("#confirm_password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
});

test("admin UI dashboard loads after login", async ({ page }) => {
  await page.goto("/admin/");
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("admin-dashboard")).toBeVisible({ timeout: TIMEOUT });
});

test("admin UI logout requires re-authentication", async ({ page }) => {
  await page.goto("/admin/");
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });

  // Logout via user menu dropdown
  await page.getByTestId("user-menu").click();
  await page.click('text=Logout');

  // Should redirect to login page
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});

test("account UI login and dashboard", async ({ page }) => {
  await page.goto("/account/");
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
});

test("account UI logout requires re-authentication", async ({ page }) => {
  await page.goto("/account/");
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });

  // Logout
  await page.getByTestId("sign-out").click();

  // Should redirect to login page
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});
