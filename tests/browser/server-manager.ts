import { execSync, spawn, type ChildProcess } from "child_process";
import { existsSync, unlinkSync } from "fs";
import { join } from "path";

const ROOT = join(__dirname, "../..");
const BINARY = join(ROOT, "autentico");
const DB_FILE = join(ROOT, "autentico.db");
const ENV_FILE = join(ROOT, ".env");

export const BASE_URL = "http://localhost:9999";
export const ADMIN_USERNAME = "admin";
export const ADMIN_PASSWORD = "Password123!";
export const ADMIN_EMAIL = "admin@test.com";
export const TIMEOUT = 5000;

let serverProcess: ChildProcess | null = null;

async function waitForServer(url: string, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Server did not start within ${timeoutMs}ms`);
}

export async function startServer(): Promise<void> {
  // Clean previous state
  if (existsSync(DB_FILE)) unlinkSync(DB_FILE);
  for (const f of [DB_FILE + "-shm", DB_FILE + "-wal"]) {
    if (existsSync(f)) unlinkSync(f);
  }
  if (existsSync(ENV_FILE)) unlinkSync(ENV_FILE);

  // Generate .env
  execSync(`${BINARY} init`, { cwd: ROOT, stdio: "pipe" });

  // Onboard admin with ROPC grant before start seeds the client
  execSync(
    `${BINARY} onboard --username "${ADMIN_USERNAME}" --password "${ADMIN_PASSWORD}" --email "${ADMIN_EMAIL}" --enable-admin-password-grant`,
    { cwd: ROOT, stdio: "pipe" }
  );

  // Start server
  serverProcess = spawn(BINARY, ["start"], {
    cwd: ROOT,
    stdio: "pipe",
    detached: false,
    env: {
      ...process.env,
      AUTENTICO_CSRF_SECURE_COOKIE: "false",
      AUTENTICO_IDP_SESSION_SECURE: "false",
      AUTENTICO_RATE_LIMIT_RPS: "0",
      AUTENTICO_RATE_LIMIT_RPM: "0",
    },
  });

  serverProcess.stdout?.on("data", (d) => process.stdout.write(d));
  serverProcess.stderr?.on("data", (d) => process.stderr.write(d));

  await waitForServer(`${BASE_URL}/.well-known/openid-configuration`);
}

export function stopServer(): void {
  if (serverProcess?.pid) {
    try {
      process.kill(serverProcess.pid, "SIGTERM");
    } catch {}
    serverProcess = null;
  }
}

export async function getAdminToken(): Promise<string> {
  const resp = await fetch(`${BASE_URL}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      username: ADMIN_USERNAME,
      password: ADMIN_PASSWORD,
      client_id: "autentico-admin",
      scope: "openid profile email",
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to get admin token (${resp.status}): ${text}`);
  }
  const data = await resp.json();
  return data.access_token;
}

export async function updateSettings(
  token: string,
  settings: Record<string, string>
): Promise<void> {
  const resp = await fetch(`${BASE_URL}/admin/api/settings`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(settings),
  });
  if (!resp.ok) {
    throw new Error(`Failed to update settings (${resp.status})`);
  }
}
