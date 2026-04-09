import { describe, it, expect, beforeAll } from 'vitest';
import { OAUTH_URL, getAdminToken, postForm, postFormBasic, postJSON } from '../helpers';

const INTROSPECT = `${OAUTH_URL}/introspect`;
const CLIENT_ID = 'introspect-test-client';
const CLIENT_SECRET = 'introspect-test-secret!';

describe('Token Introspection — happy path', () => {
  beforeAll(async () => {
    const adminToken = await getAdminToken();
    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_id: CLIENT_ID,
        client_name: 'Introspect Test Client',
        client_secret: CLIENT_SECRET,
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['authorization_code', 'password', 'refresh_token'],
        response_types: ['code'],
        scopes: 'openid profile email offline_access',
        client_type: 'confidential',
        token_endpoint_auth_method: 'client_secret_basic',
      },
      adminToken
    );
    expect(resp.status).toBe(201);
  });

  it('returns active=true with claims for valid token', async () => {
    // Issue token via the same client that will introspect it
    const tokenResp = await postFormBasic(`${OAUTH_URL}/token`, {
      grant_type: 'password', username: 'admin', password: 'Password123!', scope: 'openid profile email',
    }, CLIENT_ID, CLIENT_SECRET);
    const tokens = await tokenResp.json();

    const resp = await postFormBasic(INTROSPECT, { token: tokens.access_token }, CLIENT_ID, CLIENT_SECRET);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(true);
    expect(body.sub).toBeTruthy();
    expect(body.iss).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
  });

  it('returns active=false for revoked token', async () => {
    const tokenResp = await postFormBasic(`${OAUTH_URL}/token`, {
      grant_type: 'password', username: 'admin', password: 'Password123!', scope: 'openid profile email',
    }, CLIENT_ID, CLIENT_SECRET);
    const tokens = await tokenResp.json();

    // Revoke (with client auth)
    await postFormBasic(`${OAUTH_URL}/revoke`, { token: tokens.access_token }, CLIENT_ID, CLIENT_SECRET);

    // Introspect (with client auth)
    const resp = await postFormBasic(INTROSPECT, { token: tokens.access_token }, CLIENT_ID, CLIENT_SECRET);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(false);
  });
});

describe('Token Introspection — error cases', () => {
  it('returns active=false for garbage token', async () => {
    const resp = await postFormBasic(INTROSPECT, { token: 'garbage-not-a-jwt' }, CLIENT_ID, CLIENT_SECRET);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(false);
  });

  it('returns 400 for missing token param', async () => {
    const resp = await postFormBasic(INTROSPECT, {}, CLIENT_ID, CLIENT_SECRET);
    expect(resp.status).toBe(400);
  });

  it('returns 400 for empty token', async () => {
    const resp = await postFormBasic(INTROSPECT, { token: '' }, CLIENT_ID, CLIENT_SECRET);
    expect(resp.status).toBe(400);
  });

  it('returns 401 without client credentials', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');
    const resp = await postForm(INTROSPECT, { token: tokens.access_token });
    expect(resp.status).toBe(401);
  });
});
