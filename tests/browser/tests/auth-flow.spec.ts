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
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("admin-dashboard")).toBeVisible({ timeout: TIMEOUT });
});

test("admin UI logout requires re-authentication", async ({ page }) => {
  await page.goto("/admin/");
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });
  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });

  // Logout via user menu dropdown
  await page.getByTestId("user-menu").click();
  await page.click('text=Logout');

  // Should redirect to login page
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});

test("signup via prompt=create from login page", async ({ page, context }) => {
  // Step 1: Log in as admin and enable self-signup via settings API
  await page.goto("/admin/");
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });
  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("admin-dashboard")).toBeVisible({ timeout: TIMEOUT });

  // Get admin token from oidc-client-ts sessionStorage and enable self-signup
  const token = await page.evaluate(() => {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)!;
      if (key.startsWith("oidc.user:")) {
        const data = JSON.parse(sessionStorage.getItem(key)!);
        return data.access_token;
      }
    }
    return null;
  });
  expect(token).toBeTruthy();
  const res = await page.request.put("http://localhost:9999/admin/api/settings", {
    headers: { Authorization: `Bearer ${token}` },
    data: { allow_self_signup: "true" },
  });
  expect(res.status()).toBe(204);

  // Step 2: Clear cookies to start fresh (new user perspective)
  await context.clearCookies();

  // Step 3: Navigate to account UI — redirects to login
  await page.goto("/account/");
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });

  // Step 4: Click "Create account" link
  await page.click('text=Create account');

  // Should render signup form (via prompt=create)
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#confirm_password")).toBeVisible({ timeout: TIMEOUT });

  // Step 5: Fill signup form and submit
  await page.fill("#username", "newuser");
  await page.fill("#password", "Password123!");
  await page.fill("#confirm_password", "Password123!");
  await page.click('button[type="submit"]');

  // Step 6: Should be redirected to account UI
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
});

test("account UI login and dashboard", async ({ page }) => {
  await page.goto("/account/");
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
});

test("account UI logout requires re-authentication", async ({ page }) => {
  await page.goto("/account/");
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });

  // Logout
  await page.getByTestId("sign-out").click();

  // Should redirect to login page
  await page.waitForURL("**/oauth2/login**", { timeout: TIMEOUT });
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
});
