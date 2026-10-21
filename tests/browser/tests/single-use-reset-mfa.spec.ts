import { test, expect } from "@playwright/test";
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL } from "../server-manager";
import { clearEmails, waitForNewEmail, extractLink, extractMagicLinkCode } from "../smtp-helper";

test.setTimeout(60000);
const password = "Password123!";
let admin: string;

test.beforeAll(async () => {
  await startServer();
  admin = await getAdminToken();
  await updateSettings(admin, {
    require_mfa: "false", trust_device_enabled: "true",
    smtp_host: "localhost", smtp_port: "2525", smtp_from: "test@test.com",
  });
  for (const username of ["reset-race", "mfa-race"]) {
    const response = await fetch(`${BASE_URL}/admin/api/users`, {
      method: "POST", headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, email: `${username}@test.com` }),
    });
    expect(response.status).toBe(201);
    const { data } = await response.json();
    const verified = await fetch(`${BASE_URL}/admin/api/users/${data.id}`, {
      method: "PUT", headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
      body: JSON.stringify({ is_email_verified: true }),
    });
    expect(verified.status).toBe(200);
  }
});

test.afterAll(() => stopServer());

test("one reset link changes the password once and revokes the existing browser session", async ({ page }) => {
  await page.goto(`${BASE_URL}/account/`);
  await page.locator("#username").fill("reset-race");
  await page.locator("#password").fill(password);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByTestId("account-dashboard")).toBeVisible();

  await clearEmails();
  await page.goto(`${BASE_URL}/oauth2/forgot-password`);
  await page.locator("#identifier").fill("reset-race");
  await page.locator('button[type="submit"]').click();
  const link = extractLink(await waitForNewEmail(), "reset-password");
  expect(link).toBeTruthy();
  await page.goto(link!);
  const token = await page.locator('input[name="token"]').inputValue();
  const csrf = await page.locator('input[name="gorilla.csrf.Token"]').inputValue();
  const replies = await Promise.all(Array.from({ length: 20 }, async (_, i) => {
    const candidate = `ChangedPassword${i}!`;
    const response = await page.request.post(`${BASE_URL}/oauth2/reset-password`, {
      form: { token, password: candidate, confirm_password: candidate, "gorilla.csrf.Token": csrf },
      headers: { Origin: BASE_URL, Referer: link! }, maxRedirects: 0,
    });
    expect(response.status()).toBe(200);
    return { candidate, success: (await response.text()).includes("reset successfully") };
  }));
  const winners = replies.filter(reply => reply.success);
  expect(winners).toHaveLength(1);
  await page.goto(link!);
  await expect(page.getByText(/already been used/)).toBeVisible();

  // The old SSO cookie is still present, but its server-side session was revoked.
  await page.goto(`${BASE_URL}/account/`);
  await expect(page.locator("#username")).toBeVisible();
  await page.locator("#username").fill("reset-race");
  await page.locator("#password").fill(winners[0].candidate);
  await page.locator('button[type="submit"]').click();
  await expect(page.getByTestId("account-dashboard")).toBeVisible();
});

test("one emailed MFA challenge creates one successful callback under parallel verification", async ({ page }) => {
  await updateSettings(admin, { require_mfa: "true", mfa_method: "email" });
  await clearEmails();
  await page.goto(`${BASE_URL}/account/`);
  await page.locator("#username").fill("mfa-race");
  await page.locator("#password").fill(password);
  await page.locator('button[type="submit"]').click();
  await expect(page.locator("#code")).toBeVisible();
  const code = extractMagicLinkCode(await waitForNewEmail());
  expect(code).toBeTruthy();
  const challenge = await page.locator('input[name="challenge_id"]').inputValue();
  const csrf = await page.locator('input[name="gorilla.csrf.Token"]').inputValue();
  const form = { challenge_id: challenge, code: code!, "gorilla.csrf.Token": csrf, trust_device: "on" };
  const referer = page.url();
  const replies = await Promise.all(Array.from({ length: 20 }, async () => {
    const response = await page.request.post(`${BASE_URL}/oauth2/mfa`, {
      form, headers: { Origin: BASE_URL, Referer: referer }, maxRedirects: 0,
    });
    expect(response.status()).toBe(302);
    return response.headers()["location"];
  }));
  const winners = replies.filter(location => location.startsWith(`${BASE_URL}/account/callback`));
  expect(winners).toHaveLength(1);
  await page.goto(winners[0]);
  await expect(page.getByTestId("account-dashboard")).toBeVisible();
  const replay = await page.request.post(`${BASE_URL}/oauth2/mfa`, {
    form, headers: { Origin: BASE_URL, Referer: referer }, maxRedirects: 0,
  });
  expect(replay.headers()["location"]).not.toContain("/account/callback");
});
