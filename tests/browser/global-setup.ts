import { execSync, spawn } from "child_process";
import { existsSync, unlinkSync } from "fs";
import { join } from "path";

const ROOT = join(__dirname, "../..");
const BINARY = join(ROOT, "autentico");
const DB_FILE = join(ROOT, "autentico.db");
const ENV_FILE = join(ROOT, ".env");
const BASE_URL = "http://localhost:9999";

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

export default async function globalSetup() {
  // Build the binary if not already present (CI uploads it as an artifact)
  if (!existsSync(BINARY)) {
    console.log("[setup] Building Autentico...");
    execSync("make build", { cwd: ROOT, stdio: "inherit" });
  } else {
    console.log("[setup] Binary already exists, skipping build.");
  }

  // Clean previous state
  if (existsSync(DB_FILE)) unlinkSync(DB_FILE);
  if (existsSync(ENV_FILE)) unlinkSync(ENV_FILE);

  // Generate .env
  console.log("[setup] Initializing configuration...");
  execSync(`${BINARY} init`, { cwd: ROOT, stdio: "inherit" });

  // Start the server
  console.log("[setup] Starting server...");
  const server = spawn(BINARY, ["start"], {
    cwd: ROOT,
    stdio: "pipe",
    detached: false,
    env: {
      ...process.env,
      AUTENTICO_CSRF_SECURE_COOKIE: "false",
      AUTENTICO_IDP_SESSION_SECURE: "false",
    },
  });

  server.stdout?.on("data", (d) => process.stdout.write(d));
  server.stderr?.on("data", (d) => process.stderr.write(d));

  // Store PID for teardown
  (globalThis as any).__AUTENTICO_PID__ = server.pid;

  // Wait for server to be ready
  await waitForServer(`${BASE_URL}/.well-known/openid-configuration`);
  console.log("[setup] Server is ready.");
}
