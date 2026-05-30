import { expect, type Browser } from "@playwright/test";
import { getLastEmail, clearEmails, extractMagicLinkCode } from "./smtp-helper";
import type { CapturedEmail } from "./smtp-helper";
import { BASE_URL, ADMIN_EMAIL, TIMEOUT } from "./server-manager";

export async function magicLinkLogin(browser: Browser) {
  await clearEmails();

  const context = await browser.newContext();
  const page = await context.newPage();

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  // Click "Sign in with email link"
  await page.click("text=Sign in with email link");
  await expect(page.locator("#email")).toBeVisible({ timeout: TIMEOUT });

  // Fill email and submit
  await page.fill("#email", ADMIN_EMAIL);
  await page.click('button:has-text("Send sign-in link")');

  // Should see the code input
  await expect(page.locator("#code")).toBeVisible({ timeout: TIMEOUT });

  // Wait for the email to arrive
  let code: string | null = null;
  for (let i = 0; i < 20; i++) {
    const email: CapturedEmail | null = await getLastEmail();
    if (email) {
      code = extractMagicLinkCode(email);
      if (code) break;
    }
    await page.waitForTimeout(250);
  }
  expect(code).toBeTruthy();

  // Enter the code and verify
  await page.fill("#code", code!);
  await page.click('button:has-text("Verify code")');

  // Should land on account dashboard — no additional MFA prompt
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await context.close();
}
