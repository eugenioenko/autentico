import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  BASE_URL,
  OAUTH_URL,
  ADMIN_CLIENT_ID,
  ADMIN_REDIRECT_URI,
  getAdminToken,
  postJSON,
  putJSON,
  deleteRequest,
  getResponse,
  postForm,
} from '../helpers';

const ROOT = join(import.meta.dirname, '../../..');
const BINARY = join(ROOT, 'autentico');

const PORT_B = 19998;
const BASE_URL_B = `http://localhost:${PORT_B}`;
const OAUTH_URL_B = `${BASE_URL_B}/oauth2`;

const FEDERATION_PROVIDER_ID = 'autentico-b';
const FED_CLIENT_ID = 'instance-a-fed';
const FED_CLIENT_SECRET = 'instance-a-secret';

const TEST_CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const TEST_CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

let instanceBProcess: ChildProcess | null = null;
let instanceBTempDir: string | null = null;
let adminTokenB: string | null = null;

// Track user IDs created during setup for assertions
let locallinkUserId: string;

async function waitForServer(url: string, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Server at ${url} did not start within ${timeoutMs}ms`);
}

async function getAdminTokenB(): Promise<string> {
  if (adminTokenB) return adminTokenB;
  const resp = await postForm(`${OAUTH_URL_B}/token`, {
    grant_type: 'password',
    username: 'admin',
    password: 'Password123!',
    client_id: 'autentico-admin',
    scope: 'openid profile email',
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Failed to get admin token on Instance B (${resp.status}): ${text}`);
  }
  const tokens = await resp.json();
  adminTokenB = tokens.access_token;
  return adminTokenB!;
}

async function createUserOnB(
  username: string,
  password: string,
  email: string,
  verifyEmail: boolean
): Promise<string> {
  const token = await getAdminTokenB();
  const resp = await postJSON(`${BASE_URL_B}/admin/api/users`, { username, password, email }, token);
  if (resp.status !== 201) {
    const text = await resp.text();
    throw new Error(`Failed to create user ${username} on B (${resp.status}): ${text}`);
  }
  const body = await resp.json();
  const userId = body.data?.id ?? body.id;
  if (verifyEmail) {
    const updateResp = await putJSON(`${BASE_URL_B}/admin/api/users/${userId}`, { is_email_verified: true }, token);
    if (!updateResp.ok) {
      const text = await updateResp.text();
      throw new Error(`Failed to verify email for ${username} on B (${updateResp.status}): ${text}`);
    }
  }
  return userId;
}

async function createUserOnA(
  username: string,
  password: string,
  email: string,
  verifyEmail: boolean
): Promise<string> {
  const token = await getAdminToken();
  const resp = await postJSON(`${BASE_URL}/admin/api/users`, { username, password, email }, token);
  if (resp.status !== 201) {
    const text = await resp.text();
    throw new Error(`Failed to create user ${username} on A (${resp.status}): ${text}`);
  }
  const body = await resp.json();
  const userId = body.data?.id ?? body.id;
  if (verifyEmail) {
    const updateResp = await putJSON(`${BASE_URL}/admin/api/users/${userId}`, { is_email_verified: true }, token);
    if (!updateResp.ok) {
      const text = await updateResp.text();
      throw new Error(`Failed to verify email for ${username} on A (${updateResp.status}): ${text}`);
    }
  }
  return userId;
}

async function searchUsersOnA(email: string): Promise<Array<{ id: string; email: string; username: string; is_email_verified: boolean }>> {
  const token = await getAdminToken();
  const resp = await getResponse(`${BASE_URL}/admin/api/users?search=${encodeURIComponent(email)}`, token);
  if (!resp.ok) throw new Error(`Failed to search users on A: ${resp.status}`);
  const body = await resp.json();
  const items = body.data?.items ?? body.items ?? [];
  return items.filter((u: { email: string }) => u.email === email);
}

/**
 * Performs the full federated login redirect chain between Instance A and Instance B.
 * Returns tokens on success, or the callback HTTP status if it fails.
 */
async function performFederatedLogin(
  usernameOnB: string,
  passwordOnB: string
): Promise<{
  access_token: string;
  id_token: string;
  refresh_token: string;
  callbackStatus: number;
}> {
  // Step 1: GET Instance A /oauth2/authorize — renders login page with federation button
  const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
  authorizeURL.searchParams.set('response_type', 'code');
  authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
  authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
  authorizeURL.searchParams.set('scope', 'openid profile email');
  authorizeURL.searchParams.set('state', 'fed-test-state');
  authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
  authorizeURL.searchParams.set('code_challenge_method', 'S256');

  const authorizeResp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
  if (authorizeResp.status !== 200) {
    throw new Error(`Instance A authorize returned ${authorizeResp.status}`);
  }

  const html = await authorizeResp.text();

  // Step 2: Extract federation link from HTML
  const fedLinkMatch = html.match(/href="([^"]*\/federation\/autentico-b[^"]*)"/);
  if (!fedLinkMatch) throw new Error('Federation link not found in login page HTML');

  let fedLink = fedLinkMatch[1];
  // The link may be relative or use HTML entities
  fedLink = fedLink.replace(/&amp;/g, '&');
  if (fedLink.startsWith('/')) fedLink = `${BASE_URL}${fedLink}`;

  // Step 3: GET Instance A /oauth2/federation/autentico-b → 302 to Instance B
  const fedBeginResp = await fetch(fedLink, { redirect: 'manual' });
  if (fedBeginResp.status !== 302) {
    throw new Error(`Federation begin returned ${fedBeginResp.status}, expected 302`);
  }
  const idpAuthorizeURL = fedBeginResp.headers.get('Location');
  if (!idpAuthorizeURL) throw new Error('No Location header from federation begin');

  // Step 4: GET Instance B /oauth2/authorize — renders login page
  const idpAuthorizeResp = await fetch(idpAuthorizeURL, { redirect: 'manual' });
  if (idpAuthorizeResp.status !== 200) {
    throw new Error(`Instance B authorize returned ${idpAuthorizeResp.status}`);
  }

  const idpHtml = await idpAuthorizeResp.text();
  const csrfMatch = idpHtml.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
  if (!csrfMatch) throw new Error('Could not extract CSRF token from Instance B login page');
  const csrfToken = csrfMatch[1];

  const sigMatch = idpHtml.match(/name="authorize_sig"\s+value="([^"]*)"/);
  const authorizeSig = sigMatch ? sigMatch[1] : '';

  const idpCookies = idpAuthorizeResp.headers.getSetCookie();
  const csrfCookie = idpCookies.find((c) => c.startsWith('_gorilla_csrf='));
  if (!csrfCookie) throw new Error('Could not extract CSRF cookie from Instance B');

  // Extract hidden form fields from Instance B's login page
  const idpURL = new URL(idpAuthorizeURL);
  const idpClientId = idpURL.searchParams.get('client_id') || '';
  const idpRedirectUri = idpURL.searchParams.get('redirect_uri') || '';
  const idpScope = idpURL.searchParams.get('scope') || '';
  const idpState = idpURL.searchParams.get('state') || '';
  const idpCodeChallenge = idpURL.searchParams.get('code_challenge') || '';
  const idpCodeChallengeMethod = idpURL.searchParams.get('code_challenge_method') || '';
  const idpResponseType = idpURL.searchParams.get('response_type') || 'code';

  // Step 5: POST Instance B /oauth2/login — submit credentials
  const loginResp = await fetch(`${OAUTH_URL_B}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: csrfCookie.split(';')[0],
      Origin: BASE_URL_B,
    },
    body: new URLSearchParams({
      username: usernameOnB,
      password: passwordOnB,
      'gorilla.csrf.Token': csrfToken,
      authorize_sig: authorizeSig,
      client_id: idpClientId,
      redirect_uri: idpRedirectUri,
      scope: idpScope,
      state: idpState,
      response_type: idpResponseType,
      code_challenge: idpCodeChallenge,
      code_challenge_method: idpCodeChallengeMethod,
    }),
    redirect: 'manual',
  });

  if (loginResp.status !== 302) {
    const body = await loginResp.text();
    throw new Error(`Instance B login returned ${loginResp.status}: ${body}`);
  }

  const callbackURL = loginResp.headers.get('Location');
  if (!callbackURL) throw new Error('No Location header from Instance B login');

  // Step 6: GET Instance A /oauth2/federation/autentico-b/callback
  const callbackResp = await fetch(callbackURL, { redirect: 'manual' });

  if (callbackResp.status !== 302) {
    return {
      access_token: '',
      id_token: '',
      refresh_token: '',
      callbackStatus: callbackResp.status,
    };
  }

  const finalRedirect = callbackResp.headers.get('Location');
  if (!finalRedirect) throw new Error('No Location header from federation callback');

  const code = new URL(finalRedirect).searchParams.get('code');
  if (!code) throw new Error('No code in federation callback redirect');

  // Step 7: POST Instance A /oauth2/token — exchange code
  const tokenResp = await postForm(`${OAUTH_URL}/token`, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: ADMIN_REDIRECT_URI,
    client_id: ADMIN_CLIENT_ID,
    code_verifier: TEST_CODE_VERIFIER,
  });

  if (!tokenResp.ok) {
    const text = await tokenResp.text();
    throw new Error(`Token exchange failed (${tokenResp.status}): ${text}`);
  }

  const tokens = await tokenResp.json();
  return { ...tokens, callbackStatus: 302 };
}

describe('Federation flow — two Autentico instances', () => {
  beforeAll(async () => {
    // 1. Start Instance B
    instanceBTempDir = mkdtempSync(join(tmpdir(), 'autentico-fed-b-'));
    console.log(`[federation] Instance B temp dir: ${instanceBTempDir}`);

    const envB = {
      ...process.env,
      AUTENTICO_DB_FILE_PATH: join(instanceBTempDir, 'autentico.db'),
    };

    execSync(`${BINARY} init --url ${BASE_URL_B}`, {
      cwd: instanceBTempDir,
      stdio: 'inherit',
      env: envB,
    });

    execSync(
      `${BINARY} onboard --username admin --password Password123! --email adminb@test.com --enable-admin-password-grant`,
      { cwd: instanceBTempDir, stdio: 'inherit', env: envB }
    );

    instanceBProcess = spawn(BINARY, ['start'], {
      cwd: instanceBTempDir,
      stdio: 'pipe',
      detached: false,
      env: {
        ...envB,
        AUTENTICO_CSRF_SECURE_COOKIE: 'false',
        AUTENTICO_IDP_SESSION_SECURE: 'false',
        AUTENTICO_REFRESH_TOKEN_SECURE: 'false',
        AUTENTICO_RATE_LIMIT_RPS: '0',
        AUTENTICO_RATE_LIMIT_RPM: '0',
      },
    });

    instanceBProcess.stdout?.on('data', (d: Buffer) => process.stdout.write(`[B] ${d}`));
    instanceBProcess.stderr?.on('data', (d: Buffer) => process.stderr.write(`[B] ${d}`));

    await waitForServer(`${BASE_URL_B}/.well-known/openid-configuration`);
    console.log('[federation] Instance B is ready.');

    // 2. Get admin token on Instance B and register Instance A as a client
    const tokenB = await getAdminTokenB();

    const clientResp = await postJSON(
      `${BASE_URL_B}/admin/api/clients`,
      {
        client_id: FED_CLIENT_ID,
        client_secret: FED_CLIENT_SECRET,
        client_name: 'Instance A Federation',
        redirect_uris: [`${BASE_URL}/oauth2/federation/${FEDERATION_PROVIDER_ID}/callback`],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scopes: 'openid profile email',
        client_type: 'confidential',
        token_endpoint_auth_method: 'client_secret_basic',
      },
      tokenB
    );
    if (clientResp.status !== 201) {
      const text = await clientResp.text();
      throw new Error(`Failed to register federation client on B (${clientResp.status}): ${text}`);
    }

    // 3. Register Instance B as a federation provider on Instance A
    const tokenA = await getAdminToken();

    const fedResp = await postJSON(
      `${BASE_URL}/admin/api/federation`,
      {
        id: FEDERATION_PROVIDER_ID,
        name: 'Autentico B',
        issuer: OAUTH_URL_B,
        client_id: FED_CLIENT_ID,
        client_secret: FED_CLIENT_SECRET,
        enabled: true,
      },
      tokenA
    );
    if (fedResp.status !== 201) {
      const text = await fedResp.text();
      throw new Error(`Failed to register federation provider on A (${fedResp.status}): ${text}`);
    }

    // 4. Create test users on Instance B
    await createUserOnB('feduser', 'Password123!', 'feduser@test.com', true);
    await createUserOnB('linkuser', 'Password123!', 'linkuser@test.com', true);
    await createUserOnB('unverifieduser', 'Password123!', 'unverified@test.com', false);
    await createUserOnB('nolinkuser', 'Password123!', 'nolink-collision@test.com', true);

    // 5. Create pre-existing users on Instance A
    locallinkUserId = await createUserOnA('locallink', 'Password123!', 'linkuser@test.com', true);
    await createUserOnA('localnolink', 'Password123!', 'nolink-collision@test.com', false);

    console.log('[federation] Setup complete.');
  }, 60000);

  afterAll(async () => {
    // Clean up federation provider on Instance A
    try {
      const token = await getAdminToken();
      await deleteRequest(`${BASE_URL}/admin/api/federation/${FEDERATION_PROVIDER_ID}`, token);
    } catch {}

    // Stop Instance B
    if (instanceBProcess?.pid) {
      console.log('[federation] Stopping Instance B...');
      instanceBProcess.kill('SIGTERM');
      instanceBProcess = null;
    }

    // Clean up temp dir
    if (instanceBTempDir) {
      rmSync(instanceBTempDir, { recursive: true, force: true });
      instanceBTempDir = null;
    }
  }, 15000);

  it('creates a new user via federation login (happy path)', async () => {
    const result = await performFederatedLogin('feduser', 'Password123!');
    expect(result.callbackStatus).toBe(302);
    expect(result.access_token).toBeTruthy();
    expect(result.id_token).toBeTruthy();

    const users = await searchUsersOnA('feduser@test.com');
    expect(users.length).toBe(1);
    expect(users[0].email).toBe('feduser@test.com');
  });

  it('auto-links accounts when both emails are verified', async () => {
    const result = await performFederatedLogin('linkuser', 'Password123!');
    expect(result.callbackStatus).toBe(302);
    expect(result.access_token).toBeTruthy();

    const users = await searchUsersOnA('linkuser@test.com');
    expect(users.length).toBe(1);
    expect(users[0].id).toBe(locallinkUserId);
  });

  it('returns generic error when local email is unverified and collides (intentional)', async () => {
    const result = await performFederatedLogin('nolinkuser', 'Password123!');
    expect(result.callbackStatus).toBe(500);
    expect(result.access_token).toBe('');
  });

  it('creates new user when IdP email is not verified (no collision)', async () => {
    const result = await performFederatedLogin('unverifieduser', 'Password123!');
    expect(result.callbackStatus).toBe(302);
    expect(result.access_token).toBeTruthy();

    const users = await searchUsersOnA('unverified@test.com');
    expect(users.length).toBe(1);
  });

  it('reuses existing federated identity on second login', async () => {
    const result = await performFederatedLogin('feduser', 'Password123!');
    expect(result.callbackStatus).toBe(302);
    expect(result.access_token).toBeTruthy();

    const users = await searchUsersOnA('feduser@test.com');
    expect(users.length).toBe(1);
  });

  it('hides disabled federation provider from login page', async () => {
    const token = await getAdminToken();

    // Disable the provider
    const disableResp = await putJSON(`${BASE_URL}/admin/api/federation/${FEDERATION_PROVIDER_ID}`, {
      name: 'Autentico B',
      issuer: OAUTH_URL_B,
      client_id: FED_CLIENT_ID,
      enabled: false,
    }, token);
    expect(disableResp.ok).toBe(true);

    // Check login page
    const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
    authorizeURL.searchParams.set('response_type', 'code');
    authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
    authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
    authorizeURL.searchParams.set('scope', 'openid profile email');
    authorizeURL.searchParams.set('state', 'disabled-test');
    authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
    authorizeURL.searchParams.set('code_challenge_method', 'S256');

    const resp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
    const html = await resp.text();
    expect(html).not.toContain('Autentico B');
    expect(html).not.toContain(`/federation/${FEDERATION_PROVIDER_ID}`);

    // Re-enable for subsequent tests
    await putJSON(`${BASE_URL}/admin/api/federation/${FEDERATION_PROVIDER_ID}`, {
      name: 'Autentico B',
      issuer: OAUTH_URL_B,
      client_id: FED_CLIENT_ID,
      enabled: true,
    }, token);
  });

  it('renders custom SVG icon on login page', async () => {
    const token = await getAdminToken();

    const testSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>';
    const updateResp = await putJSON(`${BASE_URL}/admin/api/federation/${FEDERATION_PROVIDER_ID}`, {
      name: 'Autentico B',
      issuer: OAUTH_URL_B,
      client_id: FED_CLIENT_ID,
      icon_svg: testSvg,
    }, token);
    expect(updateResp.ok).toBe(true);

    const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
    authorizeURL.searchParams.set('response_type', 'code');
    authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
    authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
    authorizeURL.searchParams.set('scope', 'openid profile email');
    authorizeURL.searchParams.set('state', 'icon-test');
    authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
    authorizeURL.searchParams.set('code_challenge_method', 'S256');

    const resp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
    const html = await resp.text();
    expect(html).toContain(`/oauth2/federation/${FEDERATION_PROVIDER_ID}/icon.svg`);
  });
});
