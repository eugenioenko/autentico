import { describe, it, expect, beforeAll } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, postForm, postFormBasic, deleteRequest, getResponse } from '../helpers';

const API = `${BASE_URL}/admin/api/users`;
const INTROSPECT = `${OAUTH_URL}/introspect`;
const INTROSPECT_CLIENT_ID = 'lifecycle-introspect-client';
const INTROSPECT_CLIENT_SECRET = 'lifecycle-introspect-secret!';

/**
 * Helper: create a user via admin API and return { id, username }.
 */
async function createUser(token: string, username: string, password: string, email: string) {
  const resp = await postJSON(API, { username, password, email }, token);
  expect(resp.status).toBe(201);
  const body = await resp.json();
  return body.data as { id: string; username: string; email: string };
}

/**
 * Helper: POST to an action endpoint (deactivate/reactivate).
 */
async function postAction(url: string, token: string): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

/**
 * Helper: introspect a token using client_secret_basic and return the response body.
 */
async function introspect(accessToken: string): Promise<{ active: boolean; sub?: string }> {
  const resp = await postFormBasic(INTROSPECT, { token: accessToken }, INTROSPECT_CLIENT_ID, INTROSPECT_CLIENT_SECRET);
  expect(resp.ok).toBe(true);
  return resp.json();
}

/**
 * Helper: attempt ROPC login, returning the response (not throwing on failure).
 */
async function attemptROPCLogin(username: string, password: string): Promise<Response> {
  // Use the same ROPC client that obtainTokenViaROPC creates.
  // First call obtainTokenViaROPC to ensure the client exists, then use postForm directly.
  // We need a simpler approach — just call the token endpoint with the test-client.
  return postForm(`${OAUTH_URL}/token`, {
    grant_type: 'password',
    username,
    password,
    scope: 'openid profile email',
    client_id: 'test-ropc-lifecycle',
  });
}

// Create a confidential client for introspection and a public client for ROPC
beforeAll(async () => {
  const adminToken = await getAdminToken();

  // Confidential client for introspection
  const introspectResp = await postJSON(
    `${OAUTH_URL}/register`,
    {
      client_id: INTROSPECT_CLIENT_ID,
      client_name: 'Lifecycle Introspect Client',
      client_secret: INTROSPECT_CLIENT_SECRET,
      redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['authorization_code', 'password', 'refresh_token'],
      response_types: ['code'],
      scopes: 'openid profile email offline_access',
      client_type: 'confidential',
      token_endpoint_auth_method: 'client_secret_basic',
    },
    adminToken
  );
  expect(introspectResp.status).toBe(201);

  // Public client for ROPC login attempts
  const ropcResp = await postJSON(
    `${OAUTH_URL}/register`,
    {
      client_id: 'test-ropc-lifecycle',
      client_name: 'Lifecycle ROPC Client',
      redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['authorization_code', 'password', 'refresh_token'],
      response_types: ['code'],
      scopes: 'openid profile email offline_access',
      client_type: 'public',
      token_endpoint_auth_method: 'none',
    },
    adminToken
  );
  expect(ropcResp.status).toBe(201);
});

// --- Deactivation ---

describe('User Deactivation', () => {
  it('deactivates a user and returns 204', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func1', 'Password123!', 'deact-func1@test.com');

    const resp = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp.status).toBe(204);
  });

  it('deactivated user cannot login via ROPC', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func2', 'Password123!', 'deact-func2@test.com');

    // Login works before deactivation
    const loginBefore = await attemptROPCLogin('deact-func2', 'Password123!');
    expect(loginBefore.status).toBe(200);

    // Deactivate
    const deactResp = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(deactResp.status).toBe(204);

    // Login fails after deactivation
    const loginAfter = await attemptROPCLogin('deact-func2', 'Password123!');
    expect(loginAfter.status).not.toBe(200);
  });

  it('existing token returns active=false after deactivation', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func-intr', 'Password123!', 'deact-func-intr@test.com');

    // Get a token for the user
    const loginResp = await attemptROPCLogin('deact-func-intr', 'Password123!');
    expect(loginResp.status).toBe(200);
    const tokens = await loginResp.json();

    // Token should be active before deactivation
    const before = await introspect(tokens.access_token);
    expect(before.active).toBe(true);

    // Deactivate
    const deactResp = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(deactResp.status).toBe(204);

    // Token should be inactive after deactivation
    const after = await introspect(tokens.access_token);
    expect(after.active).toBe(false);
  });

  it('deactivated user does not appear in user list', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func3', 'Password123!', 'deact-func3@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);

    const listResp = await getResponse(API, token);
    const body = await listResp.json();
    const found = body.data.find((u: { username: string }) => u.username === 'deact-func3');
    expect(found).toBeUndefined();
  });

  it('returns 404 when deactivating already deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func4', 'Password123!', 'deact-func4@test.com');

    const resp1 = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp1.status).toBe(204);

    const resp2 = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp2.status).toBe(404);
  });

  it('returns 404 when deactivating nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await postAction(`${API}/nonexistent-id/deactivate`, token);
    expect(resp.status).toBe(404);
  });
});

// --- Reactivation ---

describe('User Reactivation', () => {
  it('reactivates a deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func1', 'Password123!', 'react-func1@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    const resp = await postAction(`${API}/${user.id}/reactivate`, token);
    expect(resp.status).toBe(204);

    // User should appear in list again
    const listResp = await getResponse(API, token);
    const body = await listResp.json();
    const found = body.data.find((u: { username: string }) => u.username === 'react-func1');
    expect(found).toBeTruthy();
  });

  it('reactivated user can login again', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func2', 'Password123!', 'react-func2@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    await postAction(`${API}/${user.id}/reactivate`, token);

    const loginResp = await attemptROPCLogin('react-func2', 'Password123!');
    expect(loginResp.status).toBe(200);
  });

  it('returns 404 when reactivating a non-deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func3', 'Password123!', 'react-func3@test.com');

    const resp = await postAction(`${API}/${user.id}/reactivate`, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 when reactivating nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await postAction(`${API}/nonexistent-id/reactivate`, token);
    expect(resp.status).toBe(404);
  });
});

// --- Hard Delete ---

describe('User Hard Delete', () => {
  it('permanently deletes a user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func1', 'Password123!', 'hd-func1@test.com');

    const resp = await deleteRequest(`${API}/${user.id}`, token);
    expect(resp.status).toBe(204);

    // User should be gone
    const getResp = await getResponse(`${API}/${user.id}`, token);
    expect(getResp.status).toBe(404);
  });

  it('existing token returns active=false after hard delete', async () => {
    const token = await getAdminToken();
    await createUser(token, 'hd-func-intr', 'Password123!', 'hd-func-intr@test.com');

    // Get a token for the user
    const loginResp = await attemptROPCLogin('hd-func-intr', 'Password123!');
    expect(loginResp.status).toBe(200);
    const tokens = await loginResp.json();

    // Token active before delete
    const before = await introspect(tokens.access_token);
    expect(before.active).toBe(true);

    // Hard-delete
    const user = await getResponse(API, token).then(r => r.json()).then(body =>
      body.data.find((u: { username: string }) => u.username === 'hd-func-intr')
    );
    const delResp = await deleteRequest(`${API}/${user.id}`, token);
    expect(delResp.status).toBe(204);

    // Token inactive after delete
    const after = await introspect(tokens.access_token);
    expect(after.active).toBe(false);
  });

  it('frees username and email after hard delete', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func2', 'Password123!', 'hd-func2@test.com');

    await deleteRequest(`${API}/${user.id}`, token);

    // Re-create with same username/email should work
    const newUser = await createUser(token, 'hd-func2', 'Password123!', 'hd-func2@test.com');
    expect(newUser.id).not.toBe(user.id);
  });

  it('can hard-delete a deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func3', 'Password123!', 'hd-func3@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    const resp = await deleteRequest(`${API}/${user.id}`, token);
    expect(resp.status).toBe(204);
  });

  it('returns 404 for nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-id`, token);
    expect(resp.status).toBe(404);
  });
});
