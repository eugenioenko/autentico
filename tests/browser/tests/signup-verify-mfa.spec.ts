import { test, expect } from "@playwright/test";
import { createHmac } from "crypto";
import { clearEmails, extractLink, waitForNewEmail } from "../smtp-helper";
import {
  startServer,
  stopServer,
  getAdminToken,
  updateSettings,
  BASE_URL,
  TIMEOUT,
} from "../server-manager";

function generateTOTP(base32Secret: string): string {
  const time = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(0, 0);
  buf.writeUInt32BE(time, 4);

  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits: number[] = [];
  for (const c of base32Secret.toUpperCase()) {
    const val = base32Chars.indexOf(c);
    if (val === -1) continue;
    for (let i = 4; i >= 0; i--) bits.push((val >> i) & 1);
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    bytes.push(byte);
  }
  const key = Buffer.from(bytes);

  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    1000000;
  return code.toString().padStart(6, "0");
}

test.beforeAll(async () => {
  await startServer();

  const token = await getAdminToken();
  await updateSettings(token, {
    allow_self_signup: "true",
    require_mfa: "true",
    mfa_method: "totp",
    require_email_verification: "true",
    profile_field_email: "required",
    smtp_host: "localhost",
    smtp_port: "2525",
    smtp_from: "test@test.com",
  });
});

test.afterAll(() => {
  stopServer();
});

test("signup → email verify → MFA enroll → login with TOTP", async ({
  page,
}) => {
  const userPassword = "Password123!";

  // -- Signup --
  await clearEmails();
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.click("text=Create account");

  await expect(page.locator("#username")).toBeVisible({ timeout: TIMEOUT });
  await page.fill("#username", "newuser");
  await page.fill("#email", "newuser@test.com");
  await page.fill("#password", userPassword);
  await page.fill("#confirm_password", userPassword);
  await page.click('button[type="submit"]');

  // Should see "verify email" page
  await expect(page.getByText("verify your email")).toBeVisible({
    timeout: TIMEOUT,
  });

  // -- Email verification --
  const verifyEmail = await waitForNewEmail();
  const verifyLink = extractLink(verifyEmail, "verify-email");
  expect(verifyLink).toBeTruthy();

  await page.goto(verifyLink!);

  // After verification, auto-logged in (first login skips MFA)
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  // -- Logout --
  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });

  // -- Login again: triggers MFA enrollment --
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.fill("#username", "newuser");
  await page.fill("#password", userPassword);
  await page.click('button[type="submit"]');

  // Should see MFA enrollment page
  await expect(page.locator("text=Setup Authenticator")).toBeVisible({
    timeout: TIMEOUT,
  });

  // Extract TOTP secret and enroll
  const secretText = await page.locator(".auth-secret-key").textContent();
  expect(secretText).toBeTruthy();
  const totpSecret = secretText!.trim();

  const enrollCode = generateTOTP(totpSecret);
  await page.fill("#code", enrollCode);
  await page.click('button:has-text("Verify")');

  // Should land on account dashboard after enrollment
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  // -- Logout again --
  await page.getByTestId("sign-out").click();
  await page.waitForURL("**/oauth2/logout**", { timeout: TIMEOUT });

  // -- Login with TOTP (already enrolled) --
  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.fill("#username", "newuser");
  await page.fill("#password", userPassword);
  await page.click('button[type="submit"]');

  // Should see MFA verification page (not enrollment)
  await expect(page.locator("#code")).toBeVisible({ timeout: TIMEOUT });
  await expect(
    page.locator("text=Setup Authenticator")
  ).not.toBeVisible();

  const loginCode = generateTOTP(totpSecret);
  await page.fill("#code", loginCode);
  await page.click('button:has-text("Verify")');

  // Should land on account dashboard
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });
});
