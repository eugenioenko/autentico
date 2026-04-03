import { execSync, spawn, type ChildProcess } from 'child_process';
import { existsSync, mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const ROOT = join(import.meta.dirname, '../..');
const BINARY = join(ROOT, 'autentico');
const PORT = 19999;
const BASE_URL = `http://localhost:${PORT}`;

let serverProcess: ChildProcess | null = null;
let tempDir: string | null = null;

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

export async function setup() {
  // 1. Build the Go binary (skip if already built, e.g. by CI build job)
  if (existsSync(BINARY)) {
    console.log('[functional] Binary already exists, skipping build.');
  } else {
    console.log('[functional] Building binary...');
    execSync('make build-go', { cwd: ROOT, stdio: 'inherit' });
  }

  // 2. Create a temp working directory for .env and .db
  tempDir = mkdtempSync(join(tmpdir(), 'autentico-functional-'));
  console.log(`[functional] Temp dir: ${tempDir}`);

  const env = {
    ...process.env,
    AUTENTICO_DB_FILE_PATH: join(tempDir, 'autentico.db'),
  };

  // 3. Initialize configuration
  console.log('[functional] Running init...');
  execSync(`${BINARY} init --url ${BASE_URL}`, { cwd: tempDir, stdio: 'inherit', env });

  // 4. Create admin account via CLI onboard
  console.log('[functional] Running onboard...');
  execSync(
    `${BINARY} onboard --username admin --password Password123! --email admin@test.com --auto-migrate`,
    { cwd: tempDir, stdio: 'inherit', env }
  );

  // 5. Start the server
  console.log('[functional] Starting server...');
  serverProcess = spawn(BINARY, ['start', '--auto-migrate'], {
    cwd: tempDir,
    stdio: 'pipe',
    detached: false,
    env: {
      ...env,
      AUTENTICO_CSRF_SECURE_COOKIE: 'false',
      AUTENTICO_IDP_SESSION_SECURE: 'false',
      AUTENTICO_REFRESH_TOKEN_SECURE: 'false',
      AUTENTICO_RATE_LIMIT_RPS: '0',
      AUTENTICO_RATE_LIMIT_RPM: '0',
    },
  });

  serverProcess.stdout?.on('data', (d) => process.stdout.write(d));
  serverProcess.stderr?.on('data', (d) => process.stderr.write(d));

  // 6. Wait for server readiness
  await waitForServer(`${BASE_URL}/.well-known/openid-configuration`);
  console.log('[functional] Server is ready.');
}

export async function teardown() {
  // Kill server
  if (serverProcess?.pid) {
    console.log('[functional] Stopping server...');
    serverProcess.kill('SIGTERM');
    serverProcess = null;
  }

  // Clean up temp dir
  if (tempDir) {
    rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
}
