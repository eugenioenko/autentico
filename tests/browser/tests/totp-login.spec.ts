import { test, expect } from "@playwright/test";
import { clearEmails, extractMagicLinkCode, getLastEmail } from "../smtp-helper";
import type { CapturedEmail } from "../smtp-helper";
import { generateTOTP } from "../totp-helper";
import {
  startServer,
  stopServer,
  getAdminToken,
  updateSettings,
  BASE_URL,
  TIMEOUT,
} from "../server-manager";

const USER = "totpuser";
const USER_EMAIL = "totpuser@test.com";
const PASSWORD = "Password123!";

test.beforeAll(async () => {
  await startServer();

  // Get admin token before enabling MFA (ROPC won't work once MFA is required)
  adminToken = await getAdminToken();
  await updateSettings(adminToken, {
    allow_self_signup: "true",
    require_mfa: "true",
    mfa_method: "totp",
    magic_link_enabled: "true",
    profile_field_email: "required",
    smtp_host: "localhost",
    smtp_port: "2525",
    smtp_from: "test@test.com",
  });
});

test.afterAll(() => {
  stopServer();
});

let totpSecret: string;
let adminToken: string;

test("signup creates account", async ({ page }) => {

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.click("text=Create account");

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await page.fill("#username", USER);
  await page.fill("#email", USER_EMAIL);
  await page.fill("#password", PASSWORD);
  await page.fill("#confirm_password", PASSWORD);
  await page.click('button[type="submit"]');

  // Signup auto-logs in (no MFA on first signup)
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  // Mark email as verified so magic link can look up this user
  const usersResp = await fetch(`${BASE_URL}/admin/api/users`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const users = await usersResp.json();
  const usr = users.data.items.find((u: any) => u.username === USER);
  await fetch(`${BASE_URL}/admin/api/users/${usr.id}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ is_email_verified: true }),
  });

  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
});

test("first password login triggers TOTP enrollment", async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", USER);
  await page.fill("#password", PASSWORD);
  await page.click('button[type="submit"]');

  // Should see TOTP enrollment page
  await expect(page.locator("text=Setup Authenticator")).toBeVisible({
    timeout: TIMEOUT,
  });

  // Extract secret and enroll
  const secretText = await page.locator(".auth-secret-key").textContent();
  expect(secretText).toBeTruthy();
  totpSecret = secretText!.trim();

  const code = generateTOTP(totpSecret);
  await page.fill("#code", code);
  await page.click('button:has-text("Verify")');

  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
});

test("password login requires TOTP", async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.fill("#username", USER);
  await page.fill("#password", PASSWORD);
  await page.click('button[type="submit"]');

  // Should see TOTP verification (not enrollment)
  await expect(page.locator("#code")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("text=Setup Authenticator")).not.toBeVisible();

  const code = generateTOTP(totpSecret);
  await page.fill("#code", code);
  await page.click('button:has-text("Verify")');

  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
});

test("magic link login requires TOTP", async ({ browser }) => {
  await clearEmails();

  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  // Use magic link
  await page.click("text=Sign in with email link");
  await expect(page.locator("#email")).toBeVisible({ timeout: TIMEOUT });
  await page.fill("#email", USER_EMAIL);
  await page.click('button:has-text("Send sign-in link")');

  await expect(page.locator("#code")).toBeVisible({ timeout: TIMEOUT });

  // Get magic link code from email
  let mlCode: string | null = null;
  for (let i = 0; i < 20; i++) {
    const email: CapturedEmail | null = await getLastEmail();
    if (email) {
      mlCode = extractMagicLinkCode(email);
      if (mlCode) break;
    }
    await page.waitForTimeout(250);
  }
  expect(mlCode).toBeTruthy();

  await page.fill("#code", mlCode!);
  await page.click('button:has-text("Verify code")');

  // Should see TOTP verification — magic link doesn't skip TOTP
  await expect(page.locator("#code")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("text=Setup Authenticator")).not.toBeVisible();

  const totpCode = generateTOTP(totpSecret);
  await page.fill("#code", totpCode);
  await page.click('button:has-text("Verify")');

  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await context.close();
});
