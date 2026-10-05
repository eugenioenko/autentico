import { test, expect, type Page } from "@playwright/test";
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

const PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
const DATA_URI = `data:image/png;base64,${PNG_BASE64}`;
const CROSS_ORIGIN_LOGO = "https://cdn.example.com/brand/logo.png";

test.beforeAll(async () => {
  await startServer();
});

test.afterAll(async () => {
  const token = await getAdminToken();
  await updateSettings(token, { theme_logo_url: "" });
  stopServer();
});

function collectCspViolations(page: Page): string[] {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (msg.text().includes("Content Security Policy")) violations.push(msg.text());
  });
  return violations;
}

async function serveCrossOriginLogo(page: Page): Promise<void> {
  await page.route(CROSS_ORIGIN_LOGO, (route) =>
    route.fulfill({ status: 200, contentType: "image/png", body: Buffer.from(PNG_BASE64, "base64") })
  );
}

async function expectImageLoaded(page: Page, selector: string): Promise<void> {
  const img = page.locator(selector).first();
  await expect(img).toBeVisible({ timeout: TIMEOUT });
  await expect
    .poll(() => img.evaluate((el: HTMLImageElement) => el.complete && el.naturalWidth > 0), { timeout: TIMEOUT })
    .toBe(true);
}

test("login page renders a data:image logo", async ({ page }) => {
  await updateSettings(await getAdminToken(), { theme_logo_url: DATA_URI });
  const violations = collectCspViolations(page);

  await page.goto(`${BASE_URL}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator(".logo img")).toHaveAttribute("src", DATA_URI);
  await expectImageLoaded(page, ".logo img");
  expect(violations).toEqual([]);
});

test("login page and account UI render a cross-origin https logo", async ({ page }) => {
  await updateSettings(await getAdminToken(), { theme_logo_url: CROSS_ORIGIN_LOGO });
  await serveCrossOriginLogo(page);
  const violations = collectCspViolations(page);

  await page.goto(`${BASE_URL}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: TIMEOUT });

  await expect(page.locator(".logo img")).toHaveAttribute("src", CROSS_ORIGIN_LOGO);
  await expectImageLoaded(page, ".logo img");

  await page.fill("#username", ADMIN_USERNAME);
  await page.fill("#password", ADMIN_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL("**/account/**", { timeout: TIMEOUT });

  await expectImageLoaded(page, 'img[alt="Logo"]');
  await expect(page.locator('img[alt="Logo"]').first()).toHaveAttribute("src", CROSS_ORIGIN_LOGO);
  expect(violations).toEqual([]);
});
