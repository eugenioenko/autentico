import { test } from "@playwright/test";
import {
  startServer,
  stopServer,
  getAdminToken,
  updateSettings,
  BASE_URL,
} from "../server-manager";
import { magicLinkLogin } from "../magic-link-flow";

async function setupMagicLink(extraSettings?: Record<string, string>) {
  const token = await getAdminToken();

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

  await updateSettings(token, {
    magic_link_enabled: "true",
    smtp_host: "localhost",
    smtp_port: "2525",
    smtp_from: "test@test.com",
    ...extraSettings,
  });
}

test.describe("magic link login", () => {
  test.beforeAll(async () => {
    await startServer();
    await setupMagicLink();
  });

  test.afterAll(() => {
    stopServer();
  });

  test("magic link code login shows account dashboard", async ({ browser }) => {
    await magicLinkLogin(browser);
  });
});

test.describe("magic link login with MFA email enabled", () => {
  test.beforeAll(async () => {
    await startServer();
    await setupMagicLink({
      require_mfa: "true",
      mfa_method: "email",
    });
  });

  test.afterAll(() => {
    stopServer();
  });

  test("magic link skips redundant email MFA", async ({ browser }) => {
    await magicLinkLogin(browser);
  });
});
