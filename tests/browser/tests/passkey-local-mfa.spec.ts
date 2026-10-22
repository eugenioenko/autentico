import { test, expect } from "@playwright/test";
import { generateFreshTOTP } from "../totp-helper";
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, TIMEOUT } from "../server-manager";

let adminToken: string;

test.beforeAll(async () => {
  await startServer();
  adminToken = await getAdminToken();
});

test.afterAll(() => stopServer());

async function setConsent(required: boolean) {
  const response = await fetch(`${BASE_URL}/admin/api/clients/autentico-account`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${adminToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ consent_required: required }),
  });
  expect(response.status).toBe(200);
}

for (const mode of ["username_first", "discoverable"]) {
  for (const userVerified of (mode === "discoverable" ? [true] : [false, true])) {
    test(`${mode}, UV=${userVerified}: local MFA precedes consent and account access`, async ({ browser }) => {
      await updateSettings(adminToken, {
        allow_self_signup: "true", auth_mode: "password_and_passkey",
        passkey_login_mode: mode, require_mfa: "false", trust_device_enabled: "false",
      });
      await setConsent(false);
      const context = await browser.newContext();
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: userVerified, isUserVerified: userVerified },
      });
      const username = `mfa_${mode}_${userVerified}`;
      await page.goto(`${BASE_URL}/account/`);
      await page.waitForURL("**/oauth2/authorize**");
      await page.click("text=Create account");
      await page.fill("#username", username);
      await page.fill("#password", "Password123!");
      await page.fill("#confirm_password", "Password123!");
      await page.click('button[type="submit"]');
      await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
      await page.getByTestId("nav-security").click();
      await page.getByTestId("add-passkey-btn").click();
      await page.locator('input[placeholder="Enter your password"]').fill("Password123!");
      await page.click("text=Continue");
      await expect(page.getByText(/Passkey [a-f0-9]{4}/i).first()).toBeVisible({ timeout: TIMEOUT });
      await page.getByTestId("sign-out").click();
      await page.waitForURL("**/oauth2/logout**");

      await updateSettings(adminToken, { require_mfa: "true", mfa_method: "totp" });
      await setConsent(true);
      await page.goto(`${BASE_URL}/account/`);
      await page.waitForURL("**/oauth2/authorize**");
      if (mode === "username_first") await page.fill("#username", username);
      await page.click("#passkey-login-btn");
      await expect(page.getByText("Setup Authenticator", { exact: true })).toBeVisible({ timeout: TIMEOUT });
      expect((await context.cookies()).some(cookie => cookie.name === "autentico_idp_session")).toBe(false);
      await expect(page.getByTestId("account-dashboard")).not.toBeVisible();

      const secret = (await page.locator(".auth-secret-key").textContent())!.trim();
      await page.fill("#code", await generateFreshTOTP(secret));
      await page.click('button:has-text("Verify")');
      await expect(page.getByText("Authorize Access", { exact: true })).toBeVisible({ timeout: TIMEOUT });
      await expect(page.getByTestId("account-dashboard")).not.toBeVisible();
      await page.getByRole("button", { name: "Allow", exact: true }).click();
      await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
      await cdp.detach();
      await context.close();
    });
  }
}

for (const primary of ["password", "passkey"]) {
  test(`${primary} signup requires local TOTP enrollment before consent`, async ({ page }) => {
    await updateSettings(adminToken, {
      allow_self_signup: "true", auth_mode: primary === "passkey" ? "passkey_only" : "password_and_passkey",
      require_mfa: "true", mfa_method: "totp", require_email_verification: "false", trust_device_enabled: "false",
    });
    await setConsent(true);
    const cdp = await page.context().newCDPSession(page);
    if (primary === "passkey") {
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
      });
    }
    await page.goto(`${BASE_URL}/account/`);
    await page.waitForURL("**/oauth2/authorize**");
    await page.click("text=Create account");
    await page.fill("#username", `first_signup_${primary}`);
    if (primary === "password") {
      await page.fill("#password", "Password123!");
      await page.fill("#confirm_password", "Password123!");
    }
    await page.click('button[type="submit"]');
    await expect(page.getByText("Setup Authenticator", { exact: true })).toBeVisible({ timeout: TIMEOUT });
    expect((await page.context().cookies()).some(cookie => cookie.name === "autentico_idp_session")).toBe(false);
    await expect(page.getByTestId("account-dashboard")).not.toBeVisible();
    const secret = (await page.locator(".auth-secret-key").textContent())!.trim();
    await page.fill("#code", await generateFreshTOTP(secret));
    await page.click('button:has-text("Verify")');
    await expect(page.getByText("Authorize Access", { exact: true })).toBeVisible({ timeout: TIMEOUT });
    await page.getByRole("button", { name: "Allow", exact: true }).click();
    await expect(page.getByTestId("account-dashboard")).toBeVisible({ timeout: TIMEOUT });
    await cdp.detach();
  });
}
