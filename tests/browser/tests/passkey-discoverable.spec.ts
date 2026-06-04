import { test, expect, type CDPSession, type Page } from "@playwright/test";
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

const USER_PASSWORD = "Password123!";
let adminToken: string;

test.beforeAll(async () => {
  await startServer();
  adminToken = await getAdminToken();
  await updateSettings(adminToken, {
    allow_self_signup: "true",
    auth_mode: "password_and_passkey",
    passkey_login_mode: "username_first",
  });
});

test.afterAll(() => {
  stopServer();
});

async function addVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  return cdp;
}

async function signupUser(page: Page, username: string): Promise<void> {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.click("text=Create account");

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await page.fill("#username", username);
  await page.fill("#password", USER_PASSWORD);
  await page.fill("#confirm_password", USER_PASSWORD);
  await page.click('button[type="submit"]');

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });
}

async function registerPasskeyViaAccountUI(page: Page): Promise<void> {
  // Navigate to security page
  await page.getByTestId("nav-security").click();
  await page.waitForURL("**/security", { timeout: TIMEOUT });

  // Click "Add Passkey" button
  await page.getByTestId("add-passkey-btn").click();

  // Password prompt modal appears — enter password and confirm
  const passwordInput = page.locator('input[placeholder="Enter your password"]');
  await expect(passwordInput).toBeVisible({ timeout: TIMEOUT });
  await passwordInput.fill(USER_PASSWORD);
  await page.click("text=Continue");

  // Wait for the passkey to appear in the list
  await expect(
    page.getByText(/Passkey [a-f0-9]{4}/i).first()
  ).toBeVisible({ timeout: TIMEOUT });
}

async function logout(page: Page): Promise<void> {
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });
}

// --- username_first mode (default) ---

test("username_first: login page shows username field and passkey button", async ({
  page,
}) => {
  await updateSettings(adminToken, { passkey_login_mode: "username_first" });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#passkey-login-btn")).toBeVisible({
    timeout: TIMEOUT,
  });
});

test("username_first: passkey button requires username", async ({ page }) => {
  await updateSettings(adminToken, { passkey_login_mode: "username_first" });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await page.locator("#passkey-login-btn").click();
  await expect(page.locator("#login-error")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#login-error")).toContainText("username", {
    ignoreCase: true,
  });
});

// --- discoverable mode ---

test("discoverable: signup, register passkey, logout, login with discoverable passkey", async ({
  browser,
}) => {
  await updateSettings(adminToken, { passkey_login_mode: "discoverable" });

  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await addVirtualAuthenticator(page);

  await signupUser(page, "disco_user");
  await registerPasskeyViaAccountUI(page);
  await logout(page);

  // Login with discoverable passkey (no username needed)
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  // Username field should still be visible in discoverable mode
  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#passkey-login-btn")).toBeVisible({
    timeout: TIMEOUT,
  });

  await page.locator("#passkey-login-btn").click();

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });

  await cdp.detach();
  await context.close();
});

// --- conditional mode ---

test("conditional: login page shows username field with webauthn autocomplete", async ({
  page,
}) => {
  await updateSettings(adminToken, { passkey_login_mode: "conditional" });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  const autocomplete = await page
    .locator("#username")
    .getAttribute("autocomplete");
  expect(autocomplete).toContain("webauthn");
});

test("conditional: signup, register passkey, logout, auto-login via conditional mediation", async ({
  browser,
}) => {
  await updateSettings(adminToken, { passkey_login_mode: "conditional" });

  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await addVirtualAuthenticator(page);

  await signupUser(page, "cond_user");
  await registerPasskeyViaAccountUI(page);
  await logout(page);

  // In conditional mode, the browser auto-surfaces the passkey on load.
  // The virtual authenticator resolves it automatically, completing login.
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/account/**", { timeout: 15000 });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });

  await cdp.detach();
  await context.close();
});

// --- passkey_only mode ---

test("passkey_only: login page hides username field", async ({ page }) => {
  await updateSettings(adminToken, {
    auth_mode: "passkey_only",
    passkey_login_mode: "passkey_only",
  });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator("#username")).not.toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#password")).not.toBeVisible({ timeout: TIMEOUT });
  await expect(page.locator("#passkey-login-btn")).toBeVisible({
    timeout: TIMEOUT,
  });

  // Reset for subsequent tests
  await updateSettings(adminToken, {
    auth_mode: "password_and_passkey",
    passkey_login_mode: "username_first",
  });
});

test("passkey_only: signup, register passkey, logout, login with passkey", async ({
  browser,
}) => {
  // Signup with password mode first so the form works
  await updateSettings(adminToken, {
    auth_mode: "password_and_passkey",
    passkey_login_mode: "discoverable",
  });

  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await addVirtualAuthenticator(page);

  await signupUser(page, "pkonly_user");
  await registerPasskeyViaAccountUI(page);
  await logout(page);

  // Switch to passkey_only mode
  await updateSettings(adminToken, {
    auth_mode: "passkey_only",
    passkey_login_mode: "passkey_only",
  });

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator("#username")).not.toBeVisible();
  await page.locator("#passkey-login-btn").click();

  await page.waitForURL("**/account/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: TIMEOUT,
  });

  // Reset
  await updateSettings(adminToken, {
    auth_mode: "password_and_passkey",
    passkey_login_mode: "username_first",
  });

  await cdp.detach();
  await context.close();
});

// --- password fallback ---

test("discoverable: password login still works", async ({ page }) => {
  await updateSettings(adminToken, {
    auth_mode: "password_and_passkey",
    passkey_login_mode: "discoverable",
  });

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
