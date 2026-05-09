import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const ROOT = join(import.meta.dirname, '../../..');
const BINARY = join(ROOT, 'autentico');
const PORT = 19997;
const BASE_URL = `http://localhost:${PORT}`;
const OAUTH_PATH = '/oidc';
const OAUTH_URL = `${BASE_URL}${OAUTH_PATH}`;

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'Password123!';
const ADMIN_CLIENT_ID = 'autentico-admin';
const ADMIN_REDIRECT_URI = `http://localhost:${PORT}/admin/callback`;

// RFC 7636 Appendix B test vectors for PKCE
const TEST_CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const TEST_CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

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

async function postForm(url: string, data: Record<string, string>): Promise<Response> {
  const body = new URLSearchParams(data);
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    redirect: 'manual',
  });
}

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'autentico-custom-path-'));

  const env = {
    ...process.env,
    AUTENTICO_DB_FILE_PATH: join(tempDir, 'autentico.db'),
  };

  // Initialize configuration
  execSync(`${BINARY} init --url ${BASE_URL}`, { cwd: tempDir, stdio: 'pipe', env });

  // Create admin account
  execSync(
    `${BINARY} onboard --username ${ADMIN_USERNAME} --password ${ADMIN_PASSWORD} --email admin@test.com --enable-admin-password-grant`,
    { cwd: tempDir, stdio: 'pipe', env }
  );

  // Start server with custom OAuth path
  serverProcess = spawn(BINARY, ['start'], {
    cwd: tempDir,
    stdio: 'pipe',
    detached: false,
    env: {
      ...env,
      AUTENTICO_APP_OAUTH_PATH: OAUTH_PATH,
      AUTENTICO_CSRF_SECURE_COOKIE: 'false',
      AUTENTICO_IDP_SESSION_SECURE: 'false',
      AUTENTICO_REFRESH_TOKEN_SECURE: 'false',
      AUTENTICO_RATE_LIMIT_RPS: '0',
      AUTENTICO_RATE_LIMIT_RPM: '0',
    },
  });

  serverProcess.stdout?.on('data', (d: Buffer) => process.stdout.write(d));
  serverProcess.stderr?.on('data', (d: Buffer) => process.stderr.write(d));

  await waitForServer(`${BASE_URL}/.well-known/openid-configuration`);
}, 30000);

afterAll(() => {
  if (serverProcess?.pid) {
    serverProcess.kill('SIGTERM');
    serverProcess = null;
  }
  if (tempDir) {
    rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
});

describe('Custom OAuth Path (/oidc)', () => {
  describe('Discovery', () => {
    it('returns issuer with custom path at root discovery URL', async () => {
      const resp = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
      expect(resp.ok).toBe(true);

      const config = await resp.json();
      expect(config.issuer).toBe(OAUTH_URL);
      expect(config.authorization_endpoint).toContain(OAUTH_PATH);
      expect(config.token_endpoint).toContain(OAUTH_PATH);
    });

    it('returns discovery at custom path as well', async () => {
      const resp = await fetch(`${OAUTH_URL}/.well-known/openid-configuration`);
      expect(resp.ok).toBe(true);

      const config = await resp.json();
      expect(config.issuer).toBe(OAUTH_URL);
    });
  });

  describe('JWKS', () => {
    it('returns keys at custom path', async () => {
      const resp = await fetch(`${OAUTH_URL}/.well-known/jwks.json`);
      expect(resp.ok).toBe(true);

      const jwks = await resp.json();
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].kty).toBe('RSA');
    });
  });

  describe('Auth Code Flow', () => {
    it('completes full flow with custom path: authorize -> login -> token', async () => {
      const state = 'custom-path-state';

      // Step 1: GET /oidc/authorize
      const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
      authorizeURL.searchParams.set('response_type', 'code');
      authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
      authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
      authorizeURL.searchParams.set('scope', 'openid profile email');
      authorizeURL.searchParams.set('state', state);
      authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
      authorizeURL.searchParams.set('code_challenge_method', 'S256');

      const authorizeResp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
      expect(authorizeResp.status).toBe(200);

      const html = await authorizeResp.text();
      expect(html).toContain('<form');

      // Extract CSRF token, authorize signature, and cookie
      const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
      expect(csrfMatch).toBeTruthy();
      const csrfToken = csrfMatch![1];

      const sigMatch = html.match(/name="authorize_sig"\s+value="([^"]*)"/);
      const authorizeSig = sigMatch ? sigMatch[1] : '';

      const cookies = authorizeResp.headers.getSetCookie();
      const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));
      expect(csrfCookie).toBeTruthy();

      // Step 2: POST /oidc/login
      const loginResp = await fetch(`${OAUTH_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: csrfCookie!.split(';')[0],
          Origin: BASE_URL,
        },
        body: new URLSearchParams({
          username: ADMIN_USERNAME,
          password: ADMIN_PASSWORD,
          'gorilla.csrf.Token': csrfToken,
          authorize_sig: authorizeSig,
          client_id: ADMIN_CLIENT_ID,
          redirect_uri: ADMIN_REDIRECT_URI,
          scope: 'openid profile email',
          state,
          response_type: 'code',
          code_challenge: TEST_CODE_CHALLENGE,
          code_challenge_method: 'S256',
        }),
        redirect: 'manual',
      });

      expect(loginResp.status).toBe(302);
      const location = loginResp.headers.get('Location');
      expect(location).toBeTruthy();

      const redirectURL = new URL(location!);
      const code = redirectURL.searchParams.get('code');
      expect(code).toBeTruthy();
      expect(redirectURL.searchParams.get('state')).toBe(state);

      // Step 3: POST /oidc/token
      const tokenResp = await postForm(`${OAUTH_URL}/token`, {
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: ADMIN_REDIRECT_URI,
        client_id: ADMIN_CLIENT_ID,
        code_verifier: TEST_CODE_VERIFIER,
      });
      expect(tokenResp.ok).toBe(true);

      const tokens = await tokenResp.json();
      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
      expect(tokens.id_token).toBeTruthy();
      expect(tokens.token_type).toBe('Bearer');
    });
  });
});
