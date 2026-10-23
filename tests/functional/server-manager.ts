import { execSync, spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const ROOT = join(import.meta.dirname, '../..');
const BINARY = join(ROOT, 'autentico');
const PORT = 19999;
const BASE_URL = `http://localhost:${PORT}`;

let serverProcess: ChildProcess | null = null;
let tempDir: string | null = null;
let launchServer: (() => Promise<void>) | null = null;

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

export async function startServer(fixture?: { binary: string; args: string[]; env: NodeJS.ProcessEnv }): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), 'autentico-functional-'));
  tempDir = directory;

  const env = {
    ...process.env,
    AUTENTICO_DB_FILE_PATH: join(tempDir, 'autentico.db'),
  };

  execSync(`${BINARY} init --url ${BASE_URL}`, { cwd: tempDir, stdio: 'pipe', env });

  execSync(
    `${BINARY} onboard --username admin --password Password123! --email admin@test.com --enable-admin-password-grant`,
    { cwd: tempDir, stdio: 'pipe', env }
  );

  launchServer = async () => {
    serverProcess = spawn(fixture?.binary ?? BINARY, fixture?.args ?? ['start'], {
      cwd: directory,
      stdio: 'pipe',
      detached: false,
      env: {
        ...env,
        AUTENTICO_CSRF_SECURE_COOKIE: 'false',
        AUTENTICO_IDP_SESSION_SECURE: 'false',
        AUTENTICO_REFRESH_TOKEN_SECURE: 'false',
        AUTENTICO_RATE_LIMIT_RPS: '0',
        AUTENTICO_RATE_LIMIT_RPM: '0',
        ...fixture?.env,
      },
    });

    serverProcess.stdout?.on('data', (d: Buffer) => process.stdout.write(d));
    serverProcess.stderr?.on('data', (d: Buffer) => process.stderr.write(d));

    await waitForServer(`${BASE_URL}/.well-known/openid-configuration`);
  };
  await launchServer();
}

/** Restart the same executable, database and keys without reinitializing or onboarding. */
export async function restartServer(): Promise<void> {
  const launch = launchServer;
  if (!launch || !tempDir) throw new Error('No running fixture to restart');
  await stopProcess();
  await launch();
}

/** Wait until the child has closed its database and released the listening port. */
async function stopProcess(): Promise<void> {
  const child = serverProcess;
  serverProcess = null;
  if (child && child.exitCode === null && child.signalCode === null) {
    await new Promise<void>(resolve => {
      const force = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.once('exit', () => { clearTimeout(force); resolve(); });
      child.kill('SIGTERM');
    });
  }
}

/** Wait for shutdown before removing its database or reusing the listen port. */
export async function stopServer(): Promise<void> {
  await stopProcess();
  launchServer = null;
  if (tempDir) {
    rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
}
