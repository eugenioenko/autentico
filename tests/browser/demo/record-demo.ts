/**
 * Records the Autentico product demo as a WebM video.
 *
 * Runs a real server against a throwaway database and drives a real browser
 * through the whole first-run story: onboarding, a tour of the admin UI,
 * enabling self-signup, registering a client, an end user signing themselves up,
 * turning on 2FA, signing back in with a TOTP code, and finally the audit log
 * showing every event that was just generated.
 *
 *   cd tests/browser && npx tsx demo/record-demo.ts
 *
 * Output: demo/out/autentico-demo.webm (post-processed by demo/encode.sh)
 */
import { chromium, type Browser, type Locator, type Page } from "@playwright/test";
import { spawn, execSync, type ChildProcess } from "child_process";
import { existsSync, mkdirSync, rmSync, renameSync, readdirSync } from "fs";
import { join } from "path";
import { generateTOTP } from "../totp-helper";
import { OVERLAY_INIT } from "./overlay";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ROOT = join(__dirname, "../../..");
const BINARY = join(ROOT, "autentico");
const RUN_DIR = join(__dirname, ".run");
const OUT_DIR = join(__dirname, "out");
const RAW_DIR = join(OUT_DIR, "raw");

const BASE = "http://localhost:9999";
const SIZE = { width: 1280, height: 720 };

const ADMIN = { user: "admin", email: "admin@acme.dev", pass: "Sup3rSecret!" };
const USER = { user: "alex", email: "alex@acme.dev", pass: "MyPassw0rd!" };
const CLIENT = {
  name: "Acme Dashboard",
  id: "acme-dashboard",
  redirect: "https://app.acme.dev/callback",
};

/** Global pacing multiplier; raise for a slower, calmer video. */
const PACE = 1;
const TYPE_DELAY = 45;
const MOVE_MS = 520;

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms * PACE));

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

let server: ChildProcess | null = null;

async function waitForServer(timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${BASE}/.well-known/openid-configuration`);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error("server did not start");
}

async function startServer() {
  if (!existsSync(BINARY)) {
    throw new Error(`binary not found at ${BINARY}; run "make build" first`);
  }
  rmSync(RUN_DIR, { recursive: true, force: true });
  mkdirSync(RUN_DIR, { recursive: true });

  // A fresh .env and empty database, so the demo really does start at onboarding.
  execSync(`${BINARY} init`, { cwd: RUN_DIR, stdio: "pipe" });

  server = spawn(BINARY, ["start"], {
    cwd: RUN_DIR,
    stdio: "pipe",
    env: {
      ...process.env,
      AUTENTICO_CSRF_SECURE_COOKIE: "false",
      AUTENTICO_IDP_SESSION_SECURE: "false",
      AUTENTICO_REFRESH_TOKEN_SECURE: "false",
      AUTENTICO_RATE_LIMIT_RPS: "0",
      AUTENTICO_RATE_LIMIT_RPM: "0",
    },
  });
  server.stderr?.on("data", (d) => process.stderr.write(d));
  await waitForServer();
}

function stopServer() {
  if (server?.pid) {
    try {
      process.kill(server.pid, "SIGTERM");
    } catch {
      /* already gone */
    }
    server = null;
  }
}

// ---------------------------------------------------------------------------
// Camera work: cursor, captions, cards
// ---------------------------------------------------------------------------

const cam = {
  x: SIZE.width / 2,
  y: SIZE.height / 2 + 40,
  caption: "",
};

/** Re-applies overlay state after a navigation wiped the DOM. */
async function sync(page: Page) {
  await page.evaluate(
    ([x, y, caption]) => {
      const d = (window as any).__autenticoDemo;
      if (!d) return;
      d.ensure();
      d.cursor(x as number, y as number, true);
      d.caption(caption as string);
    },
    [cam.x, cam.y, cam.caption] as const
  );
}

async function say(page: Page, text: string, hold = 0) {
  cam.caption = text;
  await page.evaluate((t) => (window as any).__autenticoDemo?.caption(t), text);
  if (hold) await wait(hold);
}

async function clearCaption(page: Page) {
  cam.caption = "";
  await page.evaluate(() => (window as any).__autenticoDemo?.caption(""));
}

async function moveTo(page: Page, x: number, y: number, ms = MOVE_MS) {
  cam.x = x;
  cam.y = y;
  await page.evaluate(
    ([px, py, dur]) => {
      const d = (window as any).__autenticoDemo;
      d?.cursorSpeed(dur as number);
      d?.cursor(px as number, py as number);
    },
    [x, y, ms] as const
  );
  await page.mouse.move(x, y);
  await wait(ms + 90);
}

async function centerOf(target: Locator) {
  await target.scrollIntoViewIfNeeded();
  await wait(120);
  const box = await target.boundingBox();
  if (!box) throw new Error("target has no bounding box");
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

async function click(page: Page, target: Locator, pause = 260) {
  const { x, y } = await centerOf(target);
  await moveTo(page, x, y);
  await page.evaluate(
    ([px, py]) => (window as any).__autenticoDemo?.ripple(px, py),
    [x, y] as const
  );
  await wait(150);
  await page.mouse.click(x, y);
  await wait(pause);
}

async function type(page: Page, target: Locator, text: string) {
  await click(page, target, 120);
  // Some forms arrive prefilled (browser autofill, remembered username); typing
  // over a selection keeps the keystroke animation while replacing the value.
  if (await target.inputValue().catch(() => "")) {
    await page.keyboard.press("Control+a");
    await wait(90);
  }
  await page.keyboard.type(text, { delay: TYPE_DELAY });
  await wait(220);
}

/** Waits for a navigation to finish and restores the overlay on the new document. */
async function settle(page: Page, ms = 500) {
  await page.waitForLoadState("domcontentloaded");
  await sync(page);
  await wait(ms);
}

// ---------------------------------------------------------------------------
// Scenes
// ---------------------------------------------------------------------------

async function sceneIntro(page: Page) {
  await page.evaluate(() =>
    (window as any).__autenticoDemo?.card({
      logo: true,
      kicker: "Open source · AGPL-3.0",
      title: "Auténtico",
      subtitle:
        "A complete OAuth 2.0 and OpenID Connect provider\nin a single self-contained binary.",
    })
  );
  await wait(2900);
  await page.evaluate(() => (window as any).__autenticoDemo?.hideCard());
  await wait(450);
}

async function sceneTerminal(page: Page) {
  await page.evaluate(() =>
    (window as any).__autenticoDemo?.terminal("bash · autentico")
  );
  await wait(700);

  const term = async (fn: string, ...args: unknown[]) =>
    page.evaluate(
      ([f, a]) => (window as any).__autenticoDemo?.[f as string](...(a as unknown[])),
      [fn, args] as const
    );

  await term("prompt");
  await term("type", "./autentico init\n", 34);
  await wait(280);
  await term(
    "write",
    "  ✓ RSA signing key, CSRF and token secrets written to .env\n\n",
    "#7ee787"
  );
  await wait(500);

  await term("prompt");
  await term("type", "./autentico start\n", 34);
  await wait(340);
  await term(
    "write",
    "\n  Autentico OIDC Identity Provider v2.1.3\n\n" +
      "  ONBOARDING: http://localhost:9999/onboard/\n\n" +
      "  Server:     http://localhost:9999\n" +
      "  Admin UI:   http://localhost:9999/admin/\n" +
      "  Account UI: http://localhost:9999/account/\n" +
      "  Issuer:     http://localhost:9999/oauth2\n" +
      "  SQLite:     1 writer, 4 readers (WAL mode)\n",
    "#9ba3af"
  );
  await wait(1500);
  await page.evaluate(() => (window as any).__autenticoDemo?.hideCard());
  await wait(500);
}

async function sceneOnboard(page: Page) {
  await page.goto(`${BASE}/onboard/`);
  await settle(page, 400);
  await say(page, "First run: create the administrator account", 800);

  await type(page, page.locator("#username"), ADMIN.user);
  await type(page, page.locator("#email"), ADMIN.email);
  await type(page, page.locator("#password"), ADMIN.pass);
  await type(page, page.locator("#confirm_password"), ADMIN.pass);

  await say(page, "No config files, no external database, no migrations to run", 600);
  await click(page, page.getByRole("button", { name: "Complete Setup" }));
  // Set the next caption before the wait so it reads during the page load.
  await say(page, "Signed straight in: onboarding opened an SSO session");

  await page.waitForSelector("[data-testid=admin-dashboard]", { timeout: 20000 });
  await settle(page, 1500);
}

async function sceneAdminTour(page: Page) {
  const nav = (label: string) =>
    page.locator(".ant-menu-item").filter({ hasText: new RegExp(`^${label}$`) }).first();

  // Each list fetches on mount, so hold the caption until rows are actually on
  // screen, otherwise the tour narrates an empty table.
  const table = () =>
    page.waitForSelector(".ant-table-row", { timeout: 15000 }).then(() => wait(150));

  await say(page, "Everything is managed from the built-in admin UI", 900);

  await click(page, nav("Users"));
  await table();
  await say(page, "Users: accounts, roles, groups, lockout state", 1100);

  await click(page, nav("Sessions"));
  await table();
  await say(page, "Sessions: every active browser and device, revocable", 1100);

  await click(page, nav("Tokens"));
  await table();
  await say(page, "Tokens: inspect and revoke access and refresh tokens", 1100);
}

async function sceneSelfSignup(page: Page) {
  await click(
    page,
    page.locator(".ant-menu-item").filter({ hasText: /^Settings$/ }).first()
  );
  await wait(600);
  await say(page, "Runtime settings: no restart, no redeploy", 800);

  await click(page, page.getByRole("tab", { name: "Login & Registration" }), 450);

  const toggle = page
    .locator("label.ant-checkbox-wrapper")
    .filter({ hasText: "Allow Self Signup" })
    .first();
  await say(page, "Let people create their own accounts", 450);
  await click(page, toggle, 500);

  await click(page, page.getByRole("button", { name: /Save All Settings/i }));
  await say(page, "Saved: self-service signup is live", 1200);
}

async function sceneCreateClient(page: Page) {
  await click(
    page,
    page.locator(".ant-menu-item").filter({ hasText: /^Clients$/ }).first()
  );
  await page.waitForSelector(".ant-table-row", { timeout: 15000 });
  await wait(500);
  await say(page, "Clients: register an OAuth 2.0 / OIDC application", 900);

  await click(page, page.getByRole("button", { name: /Create Client/i }), 600);

  await type(page, page.locator("#client_name"), CLIENT.name);
  await type(page, page.locator("#client_id"), CLIENT.id);
  await type(page, page.locator("#redirect_uris_0"), CLIENT.redirect);

  await say(page, "Public client with PKCE and refresh tokens by default", 950);
  await click(
    page,
    page.locator(".ant-drawer").getByRole("button", { name: /^Create$/ })
  );
  await wait(900);
  await say(page, "Client registered and ready to use", 1400);
}

async function sceneUserSignup(page: Page) {
  // Leave the admin session so the next scene is a genuine first-time user.
  await click(page, page.getByTestId("user-menu"), 500);
  await click(page, page.getByText("Logout", { exact: true }));
  await page.waitForURL("**/oauth2/logout**", { timeout: 15000 });
  await settle(page, 600);

  await say(page, "Now from the other side: an end user signs themselves up", 1100);
  await page.goto(`${BASE}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: 15000 });
  await settle(page, 600);

  await click(page, page.getByText("Create account"), 500);
  await settle(page, 350);
  await say(page, "The signup link only appears because we enabled it", 700);

  await type(page, page.locator("#username"), USER.user);
  await type(page, page.locator("#password"), USER.pass);
  await type(page, page.locator("#confirm_password"), USER.pass);
  await click(page, page.locator("#signup-btn"));

  await page.waitForSelector("[data-testid=account-dashboard]", { timeout: 20000 });
  await settle(page, 700);
  await say(page, "Signed in: this is the self-service account portal", 1400);
}

async function sceneEnable2FA(page: Page): Promise<string> {
  await click(page, page.getByRole("link", { name: "Security" }), 700);
  await say(page, "Security: password, 2FA, passkeys, connected apps", 1200);

  await click(page, page.getByRole("button", { name: "Set Up", exact: true }), 600);

  // Scope to the modal; the Security page has other password inputs behind it.
  const modal = page.locator("div.fixed.inset-0.z-50");

  await say(page, "Confirm your password first", 350);
  await type(page, modal.locator('input[type="password"]'), USER.pass);
  await click(page, modal.getByRole("button", { name: "Continue" }));
  await wait(900);

  await say(page, "Scan the QR code with any authenticator app", 1800);

  const secret = (await modal.locator("code").first().textContent())?.trim() ?? "";
  if (!secret) throw new Error("could not read TOTP secret");

  await click(page, modal.getByRole("button", { name: "Continue" }), 600);

  // Avoid submitting a code that expires mid-request.
  const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
  if (secondsLeft < 5) await wait(secondsLeft * 1000 + 500);

  await say(page, "Enter the 6-digit code", 300);
  await type(page, modal.locator('input[inputmode="numeric"]'), generateTOTP(secret));
  await click(page, modal.getByRole("button", { name: /Enable 2FA/i }));
  await wait(1100);

  await say(page, "Two-factor authentication is on", 1500);
  return secret;
}

async function sceneLoginWith2FA(page: Page, secret: string) {
  await click(page, page.getByTestId("sign-out"));
  await page.waitForURL("**/oauth2/logout**", { timeout: 15000 });
  await settle(page, 700);

  await say(page, "So the next sign-in asks for the code", 700);
  await page.goto(`${BASE}/account/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: 15000 });
  await settle(page, 500);

  await type(page, page.locator("#username"), USER.user);
  await type(page, page.locator("#password"), USER.pass);
  await click(page, page.locator('button[type="submit"]'));

  await page.waitForSelector("#code", { timeout: 15000 });
  await settle(page, 600);
  await say(page, "Password accepted: now the second factor", 700);

  const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
  if (secondsLeft < 5) await wait(secondsLeft * 1000 + 500);

  await type(page, page.locator("#code"), generateTOTP(secret));
  await click(page, page.getByRole("button", { name: /Verify/i }));

  await page.waitForSelector("[data-testid=account-dashboard]", { timeout: 20000 });
  await settle(page, 700);
  await say(page, "In. Two factors, zero third-party services", 1500);
}

async function sceneAuditLog(page: Page) {
  await click(page, page.getByTestId("sign-out"));
  await page.waitForURL("**/oauth2/logout**", { timeout: 15000 });
  await settle(page, 500);

  await say(page, "Back on the admin side…", 700);
  await page.goto(`${BASE}/admin/`);
  await page.waitForURL("**/oauth2/authorize**", { timeout: 15000 });
  await settle(page, 500);

  await type(page, page.locator("#username"), ADMIN.user);
  await type(page, page.locator("#password"), ADMIN.pass);
  await click(page, page.locator('button[type="submit"]'));
  await page.waitForSelector("[data-testid=admin-dashboard]", { timeout: 20000 });
  await settle(page, 800);

  await click(
    page,
    page.locator(".ant-menu-item").filter({ hasText: /^Audit Log$/ }).first()
  );
  await page.waitForSelector(".ant-table-row", { timeout: 15000 });
  await wait(400);
  await say(page, "Every event we just triggered is in the audit log", 2600);
}

async function sceneOutro(page: Page) {
  await clearCaption(page);
  await page.evaluate(() =>
    (window as any).__autenticoDemo?.card({
      logo: true,
      title: "Auténtico",
      subtitle: "Self-hosted identity, ready in one command.",
      bullets: [
        "Authorization Code + PKCE",
        "MFA · TOTP · Passkeys",
        "SSO sessions",
        "Audit log",
        "Passes OIDC conformance",
        "Single binary + SQLite",
      ],
      link: "github.com/eugenioenko/autentico",
    })
  );
  await wait(3900);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  rmSync(RAW_DIR, { recursive: true, force: true });
  mkdirSync(RAW_DIR, { recursive: true });

  await startServer();

  let browser: Browser | null = null;
  try {
    browser = await chromium.launch({
      args: ["--force-device-scale-factor=1", "--hide-scrollbars"],
    });
    const context = await browser.newContext({
      viewport: SIZE,
      deviceScaleFactor: 1,
      bypassCSP: true,
      recordVideo: { dir: RAW_DIR, size: SIZE },
      colorScheme: "light",
    });
    // Injected as source rather than as a function: tsx compiles with esbuild's
    // keepNames, which wraps inner functions in a `__name` helper that only
    // exists in the module scope. The shim makes the serialized source runnable.
    await context.addInitScript({
      content:
        `globalThis.__name = globalThis.__name || ((f) => f);\n` +
        `(${OVERLAY_INIT.toString()})();`,
    });

    const page = await context.newPage();

    // Start on a real page so the intro cards render on the app's own origin
    // (the logo and fonts are same-origin assets).
    await page.goto(`${BASE}/onboard/`);
    await settle(page, 300);

    await sceneIntro(page);
    await sceneTerminal(page);
    await sceneOnboard(page);
    await sceneAdminTour(page);
    await sceneSelfSignup(page);
    await sceneCreateClient(page);
    await sceneUserSignup(page);
    const secret = await sceneEnable2FA(page);
    await sceneLoginWith2FA(page, secret);
    await sceneAuditLog(page);
    await sceneOutro(page);

    const video = page.video();
    await context.close();

    if (video) {
      const src = await video.path();
      const dest = join(OUT_DIR, "autentico-demo.webm");
      renameSync(src, dest);
      console.log(`\nRecorded: ${dest}`);
    } else {
      const files = readdirSync(RAW_DIR);
      console.log("video files:", files);
    }
  } finally {
    await browser?.close();
    stopServer();
  }
}

main().catch((err) => {
  console.error(err);
  stopServer();
  process.exit(1);
});
