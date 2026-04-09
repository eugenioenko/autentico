import { describe, it, expect, beforeAll } from 'vitest';
import { TOTP } from 'otpauth';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, postForm } from '../helpers';

const USERS_API = `${BASE_URL}/admin/api/users`;
const ACCOUNT_API = `${BASE_URL}/account/api`;
// ROPC client for MFA tests
const MFA_CLIENT_ID = 'mfa-test-client';

/**
 * Helper: create a user via admin API.
 */
async function createUser(token: string, username: string, password: string, email: string) {
  const resp = await postJSON(USERS_API, { username, password, email }, token);
  expect(resp.status).toBe(201);
  const body = await resp.json();
  return body.data as { id: string; username: string };
}

/**
 * Helper: obtain access token via ROPC, optionally with totp_code.
 */
async function ropcLogin(username: string, password: string, totpCode?: string): Promise<Response> {
  const data: Record<string, string> = {
    grant_type: 'password',
    username,
    password,
    scope: 'openid profile email',
    client_id: MFA_CLIENT_ID,
  };
  if (totpCode) {
    data.totp_code = totpCode;
  }
  return postForm(`${OAUTH_URL}/token`, data);
}

/**
 * Helper: get a bearer token for a user via ROPC.
 */
async function getUserToken(username: string, password: string, totpCode?: string): Promise<string> {
  const resp = await ropcLogin(username, password, totpCode);
  expect(resp.status).toBe(200);
  const body = await resp.json();
  return body.access_token;
}

/**
 * Helper: setup and verify TOTP for a user, returning the secret.
 */
async function setupAndVerifyTotp(userToken: string): Promise<string> {
  // Setup TOTP
  const setupResp = await postJSON(`${ACCOUNT_API}/mfa/totp/setup`, {}, userToken);
  expect(setupResp.status).toBe(200);
  const setupBody = await setupResp.json();
  const secret = setupBody.data.secret;

  // Generate valid code
  const totp = new TOTP({ secret });
  const code = totp.generate();

  // Verify TOTP
  const verifyResp = await postJSON(`${ACCOUNT_API}/mfa/totp/verify`, { code }, userToken);
  expect(verifyResp.status).toBe(200);

  return secret;
}

/**
 * Helper: generate a TOTP code from a secret.
 */
function generateCode(secret: string): string {
  const totp = new TOTP({ secret });
  return totp.generate();
}

/**
 * Helper: make a JSON DELETE request with a body.
 */
async function deleteWithBody(url: string, body: unknown, bearer: string): Promise<Response> {
  return fetch(url, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${bearer}`,
    },
    body: JSON.stringify(body),
  });
}

// Create ROPC client for MFA tests
beforeAll(async () => {
  const adminToken = await getAdminToken();

  const resp = await postJSON(
    `${OAUTH_URL}/register`,
    {
      client_id: MFA_CLIENT_ID,
      client_name: 'MFA Test ROPC Client',
      redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['authorization_code', 'password', 'refresh_token'],
      response_types: ['code'],
      scopes: 'openid profile email offline_access',
      client_type: 'public',
      token_endpoint_auth_method: 'none',
    },
    adminToken
  );
  expect(resp.status).toBe(201);
});

// --- Fix 1: Password grant enforces MFA ---

describe('Password grant MFA enforcement', () => {
  it('ROPC succeeds without MFA when not required', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-ropc1', 'Password123!', 'mfa-ropc1@test.com');

    const resp = await ropcLogin('mfa-ropc1', 'Password123!');
    expect(resp.status).toBe(200);
  });

  it('ROPC with TOTP enrolled requires totp_code', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-ropc2', 'Password123!', 'mfa-ropc2@test.com');

    // Get token and enroll TOTP
    const userToken = await getUserToken('mfa-ropc2', 'Password123!');
    const secret = await setupAndVerifyTotp(userToken);

    // ROPC without totp_code should fail
    const resp = await ropcLogin('mfa-ropc2', 'Password123!');
    expect(resp.status).toBe(403);
    const body = await resp.json();
    expect(body.error).toBe('mfa_required');

    // ROPC with valid totp_code should succeed
    const code = generateCode(secret);
    const resp2 = await ropcLogin('mfa-ropc2', 'Password123!', code);
    expect(resp2.status).toBe(200);
  });

  it('ROPC with invalid totp_code is rejected', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-ropc3', 'Password123!', 'mfa-ropc3@test.com');

    const userToken = await getUserToken('mfa-ropc3', 'Password123!');
    await setupAndVerifyTotp(userToken);

    const resp = await ropcLogin('mfa-ropc3', 'Password123!', '000000');
    expect(resp.status).toBe(403);
    const body = await resp.json();
    expect(body.error).toBe('invalid_mfa_code');
  });
});

// --- Fix 2: Block TOTP re-enrollment ---

describe('TOTP re-enrollment blocked', () => {
  it('returns 409 when TOTP is already verified', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-reenroll', 'Password123!', 'mfa-reenroll@test.com');

    const userToken = await getUserToken('mfa-reenroll', 'Password123!');
    await setupAndVerifyTotp(userToken);

    // Try to setup again — should be blocked
    // Need a fresh token since the user now has TOTP
    const secret2Resp = await postJSON(`${ACCOUNT_API}/mfa/totp/setup`, {}, userToken);
    expect(secret2Resp.status).toBe(409);
    const body = await secret2Resp.json();
    expect(body.error).toBe('already_enrolled');
  });
});

// --- Fix 3: Require OTP code to disable TOTP ---

describe('TOTP disable requires OTP code', () => {
  it('rejects disable without TOTP code', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-disable1', 'Password123!', 'mfa-disable1@test.com');

    const userToken = await getUserToken('mfa-disable1', 'Password123!');
    await setupAndVerifyTotp(userToken);

    const resp = await deleteWithBody(`${ACCOUNT_API}/mfa/totp`, { current_password: 'Password123!' }, userToken);
    expect(resp.status).toBe(400);
  });

  it('rejects disable with wrong TOTP code', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-disable2', 'Password123!', 'mfa-disable2@test.com');

    const userToken = await getUserToken('mfa-disable2', 'Password123!');
    await setupAndVerifyTotp(userToken);

    const resp = await deleteWithBody(
      `${ACCOUNT_API}/mfa/totp`,
      { current_password: 'Password123!', code: '000000' },
      userToken
    );
    expect(resp.status).toBe(403);
  });

  it('succeeds with correct password and TOTP code', async () => {
    const adminToken = await getAdminToken();
    await createUser(adminToken, 'mfa-disable3', 'Password123!', 'mfa-disable3@test.com');

    const userToken = await getUserToken('mfa-disable3', 'Password123!');
    const secret = await setupAndVerifyTotp(userToken);

    const code = generateCode(secret);
    const resp = await deleteWithBody(
      `${ACCOUNT_API}/mfa/totp`,
      { current_password: 'Password123!', code },
      userToken
    );
    expect(resp.status).toBe(200);
  });
});
