import { test, expect } from "@playwright/test";
import { getLastEmail, clearEmails, extractMagicLinkCode } from "../smtp-helper";
import type { CapturedEmail } from "../smtp-helper";

const BASE_URL = "http://localhost:9999";
const ADMIN_EMAIL = "admin@test.com";
const TIMEOUT = 5000;

async function getAdminToken(): Promise<string> {
  const resp = await fetch(`${BASE_URL}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      username: "admin",
      password: "Password123!",
      client_id: "autentico-admin",
      scope: "openid profile email",
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to get admin token (${resp.status}): ${text}`);
  }
  const data = await resp.json();
  if (!data.access_token) {
    throw new Error(`No access_token in response: ${JSON.stringify(data)}`);
  }
  return data.access_token;
}

async function enableMagicLink(token: string) {
  // Mark admin email as verified
  const usersResp = await fetch(`${BASE_URL}/admin/api/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const users = await usersResp.json();
  const adminUser = users.data.items.find(
    (u: any) => u.username === "admin"
  );

  await fetch(`${BASE_URL}/admin/api/users/${adminUser.id}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ is_email_verified: true }),
  });

  await fetch(`${BASE_URL}/admin/api/settings`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      magic_link_enabled: "true",
      smtp_host: "localhost",
      smtp_port: "2525",
      smtp_from: "test@test.com",
    }),
  });
}

test("magic link login with code shows account dashboard", async ({
  browser,
}) => {
  // Setup: enable magic link via API (no browser needed)
  const token = await getAdminToken();
  await enableMagicLink(token);
  await clearEmails();

  // Start the login flow from the account UI
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

  // Should land on account dashboard
  await expect(page.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await context.close();
});
