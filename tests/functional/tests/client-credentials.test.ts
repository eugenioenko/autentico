import { describe, it, expect, beforeAll } from 'vitest';
import { OAUTH_URL, getAdminToken, postJSON, postForm } from '../helpers';

const CLIENT_ID = 'cc-functional-client';
const CLIENT_SECRET = 'cc-functional-secret!';

describe('Client Credentials Grant', () => {
  beforeAll(async () => {
    const adminToken = await getAdminToken();
    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_id: CLIENT_ID,
        client_name: 'Functional Test CC Client',
        client_secret: CLIENT_SECRET,
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['client_credentials'],
        response_types: ['code'],
        scopes: 'openid profile email read write',
        client_type: 'confidential',
        token_endpoint_auth_method: 'client_secret_basic',
      },
      adminToken
    );
    expect(resp.status).toBe(201);
  });

  it('obtains an access token with valid credentials (Basic Auth)', async () => {
    const credentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
    const resp = await fetch(`${OAUTH_URL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'read write',
      }),
    });

    expect(resp.status).toBe(200);
    const body = await resp.json();

    // RFC 6749 §4.4.3: access_token and token_type MUST be present
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe('read write');

    // RFC 6749 §4.4.3: refresh token SHOULD NOT be included
    expect(body.refresh_token).toBeFalsy();

    // No ID token — no user identity to assert
    expect(body.id_token).toBeFalsy();
  });

  it('obtains an access token with valid credentials (secret_post)', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: 'read',
    });

    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
  });

  it('rejects wrong client secret', async () => {
    const credentials = btoa(`${CLIENT_ID}:wrong-secret`);
    const resp = await fetch(`${OAUTH_URL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'read write',
      }),
    });

    expect(resp.status).toBe(401);
    const body = await resp.json();
    expect(body.error).toBe('invalid_client');
  });

  it('rejects unknown client_id', async () => {
    const credentials = btoa(`nonexistent-client:some-secret`);
    const resp = await fetch(`${OAUTH_URL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
      }),
    });

    expect(resp.status).toBe(401);
    const body = await resp.json();
    expect(body.error).toBe('invalid_client');
  });

  it('rejects request with no credentials', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'client_credentials',
      scope: 'read',
    });

    expect(resp.status).toBe(401);
    const body = await resp.json();
    expect(body.error).toBe('invalid_client');
  });

  it('token is active when introspected', async () => {
    const credentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
    const tokenResp = await fetch(`${OAUTH_URL}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'read',
      }),
    });
    const tokens = await tokenResp.json();

    const introspectCredentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
    const introspectResp = await fetch(`${OAUTH_URL}/introspect`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${introspectCredentials}`,
      },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    expect(introspectResp.status).toBe(200);
    const introspection = await introspectResp.json();
    expect(introspection.active).toBe(true);
    expect(introspection.scope).toBe('read');
  });
});
