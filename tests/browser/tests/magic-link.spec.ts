import { test, expect } from "@playwright/test";
import { join } from "path";
import Database from "better-sqlite3";

const BASE_URL = "http://localhost:9999";
const OAUTH_URL = `${BASE_URL}/oauth2`;
const ADMIN_USERNAME = "admin";
const ADMIN_PASSWORD = "Password123!";
const ADMIN_EMAIL = "admin@test.com";
const TIMEOUT = 5000;
const DB_FILE = join(__dirname, "../../../autentico.db");

test("magic link login shows account dashboard", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();

  // Onboard if needed (when running in isolation on a fresh DB)
  await page.goto(`${BASE_URL}/onboard`);
  if (await page.locator("#username").isVisible({ timeout: 2000 }).catch(() => false)) {
    await page.fill("#username", ADMIN_USERNAME);
    await page.fill("#email", ADMIN_EMAIL);
    await page.fill("#password", ADMIN_PASSWORD);
    await page.fill("#confirm_password", ADMIN_PASSWORD);
    await page.click('button[type="submit"]');
    await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  }

  // Start fresh — navigate to a neutral page before clearing state
  await page.goto(`${BASE_URL}/healthz`);
  await context.clearCookies();

  // Log in as admin to capture a bearer token
  const apiRequestPromise = page.waitForRequest(
    (req) =>
      req.url().includes("/admin/api/") &&
      (req.headers()["authorization"]?.startsWith("Bearer ") ?? false),
    { timeout: 15000 }
  );

  await page.goto(`${BASE_URL}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/admin/**", { timeout: TIMEOUT });
  await expect(page.getByTestId("admin-dashboard")).toBeVisible({ timeout: TIMEOUT });

  const apiRequest = await apiRequestPromise;
  const token = apiRequest.headers()["authorization"]!.replace("Bearer ", "");

  // Enable magic link + SMTP + verify admin email
  await page.request.put(`${BASE_URL}/admin/api/settings`, {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      magic_link_enabled: "true",
      smtp_host: "localhost",
      smtp_port: "2525",
      smtp_from: "test@test.com",
    },
  });

  const usersResp = await page.request.get(`${BASE_URL}/admin/api/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const users = await usersResp.json();
  const adminUser = users.data.items.find(
    (u: any) => u.username === ADMIN_USERNAME
  );
  await page.request.put(`${BASE_URL}/admin/api/users/${adminUser.id}`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { is_email_verified: true },
  });

  // Start fresh for the account UI login
  const accountContext = await browser.newContext();
  const accountPage = await accountContext.newPage();

  await accountPage.goto(`${BASE_URL}/account/`);
  await accountPage.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });
  await expect(accountPage.locator("text=Sign in with email link")).toBeVisible({ timeout: TIMEOUT });

  // Create a magic link token in the DB
  const crypto = await import("crypto");
  const rawToken = crypto.randomBytes(32).toString("base64url");
  const hash = crypto.createHash("sha256").update(rawToken).digest("hex");

  const db = new Database(DB_FILE);
  db.prepare(
    `INSERT INTO magic_link_tokens (id, user_id, token_hash, expires_at)
     VALUES (?, ?, ?, datetime('now', '+15 minutes'))`
  ).run("test-ml-" + Date.now(), adminUser.id, hash);
  db.close();

  // Get a valid authorize_sig
  const mlResp = await accountPage.request.get(
    `${OAUTH_URL}/magic-link?client_id=autentico-account&redirect_uri=${encodeURIComponent(BASE_URL + "/account/callback")}&state=ml-test&scope=openid+profile+email`
  );
  const mlHtml = await mlResp.text();
  const sigMatch = mlHtml.match(/name="authorize_sig"\s+value="([^"]*)"/);
  expect(sigMatch).toBeTruthy();

  // Open the magic link verify URL
  const verifyParams = new URLSearchParams({
    token: rawToken,
    client_id: "autentico-account",
    redirect_uri: `${BASE_URL}/account/callback`,
    state: "ml-test",
    scope: "openid profile email",
    authorize_sig: sigMatch![1],
  });
  await accountPage.goto(`${OAUTH_URL}/magic-link/verify?${verifyParams}`);

  // The onError handler detects the state mismatch, auto-retries,
  // and SSO auto-login completes the flow.
  await expect(accountPage.getByTestId("account-dashboard")).toBeVisible({
    timeout: 15000,
  });

  await accountContext.close();
  await context.close();
});
