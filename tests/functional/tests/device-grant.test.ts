import { describe, it, expect, beforeAll } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, postForm, postFormBasic, putJSON } from '../helpers';

const CLIENT_ID = 'device-functional-client';

describe('Device Authorization Grant (RFC 8628)', () => {
  beforeAll(async () => {
    const adminToken = await getAdminToken();
    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_id: CLIENT_ID,
        client_name: 'Device Functional Test Client',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
        response_types: ['code'],
        scopes: 'openid profile email',
        client_type: 'public',
        token_endpoint_auth_method: 'none',
      },
      adminToken
    );
    expect(resp.status).toBe(201);
  });

  it('issues device_code and user_code from device_authorization endpoint', async () => {
    const resp = await postForm(`${OAUTH_URL}/device_authorization`, {
      client_id: CLIENT_ID,
      scope: 'openid profile',
    });

    expect(resp.status).toBe(200);
    const body = await resp.json();

    // RFC 8628 §3.2: required fields
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toBeTruthy();
    expect(body.verification_uri).toBeTruthy();
    expect(body.expires_in).toBeGreaterThan(0);

    // User code should be formatted with hyphen
    expect(body.user_code).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);

    // verification_uri_complete should include user_code
    expect(body.verification_uri_complete).toContain(body.user_code);
  });

  it('returns authorization_pending when polling before user authorizes', async () => {
    const deviceResp = await postForm(`${OAUTH_URL}/device_authorization`, {
      client_id: CLIENT_ID,
      scope: 'openid',
    });
    const { device_code } = await deviceResp.json();

    const tokenResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code,
      client_id: CLIENT_ID,
    });

    expect(tokenResp.status).toBe(400);
    const body = await tokenResp.json();
    expect(body.error).toBe('authorization_pending');
  });

  it('rejects device_authorization for client without device_code grant', async () => {
    const resp = await postForm(`${OAUTH_URL}/device_authorization`, {
      client_id: 'autentico-admin',
      scope: 'openid',
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('unauthorized_client');
  });

  it('rejects device_authorization with unknown client_id', async () => {
    const resp = await postForm(`${OAUTH_URL}/device_authorization`, {
      client_id: 'nonexistent-client',
      scope: 'openid',
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_client');
  });

  it('rejects device_authorization without client_id', async () => {
    const resp = await postForm(`${OAUTH_URL}/device_authorization`, {
      scope: 'openid',
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toContain('invalid_request');
  });

  it('rejects token polling with invalid device_code', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: 'totally-invalid-code',
      client_id: CLIENT_ID,
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_grant');
  });

  it('rejects token polling without device_code field', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: CLIENT_ID,
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toContain('invalid_request');
  });

  it('rejects invalid scope in device_authorization', async () => {
    const resp = await postForm(`${OAUTH_URL}/device_authorization`, {
      client_id: CLIENT_ID,
      scope: 'openid admin_super_scope',
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_scope');
  });

  it('discovery document includes device_authorization_endpoint', async () => {
    const resp = await fetch(`${OAUTH_URL}/.well-known/openid-configuration`);
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.device_authorization_endpoint).toBeTruthy();
    expect(body.device_authorization_endpoint).toContain('/device_authorization');
    expect(body.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:device_code');
  });
});


describe('device authorization client authentication', () => {
  const secret = 'device-client-secret';
  const grant = 'urn:ietf:params:oauth:grant-type:device_code';
  beforeAll(async () => {
    const admin = await getAdminToken();
    for (const id of ['device-basic', 'device-post', 'device-inactive', 'device-no-grant', 'device-inactive-public']) {
      const publicClient = id === 'device-inactive-public';
      const response = await postJSON(`${OAUTH_URL}/register`, { client_id: id, client_name: id,
        client_type: publicClient ? 'public' : 'confidential', client_secret: publicClient ? undefined : secret,
        token_endpoint_auth_method: publicClient ? 'none' : id === 'device-post' ? 'client_secret_post' : 'client_secret_basic',
        redirect_uris: ['http://localhost/unused'], scopes: 'openid profile',
        grant_types: id === 'device-no-grant' ? ['authorization_code'] : [grant], response_types: ['code'] }, admin);
      expect(response.status).toBe(201);
      if (id.includes('inactive')) expect((await putJSON(`${BASE_URL}/admin/api/clients/${id}`, { is_active: false }, admin)).status).toBe(200);
    }
  });

  it('accepts Basic authentication without a body client_id and binds token polling to that client', async () => {
    const response = await postFormBasic(`${OAUTH_URL}/device_authorization`, { scope: 'openid' }, 'device-basic', secret);
    expect(response.status).toBe(200);
    const issued = await response.json(); expect(issued.device_code).toBeTruthy();
    const other = await postFormBasic(`${OAUTH_URL}/token`, { grant_type: grant, device_code: issued.device_code }, 'device-post', secret);
    expect(other.status).toBe(400); expect((await other.json()).error).toBe('invalid_grant');
    const poll = await postFormBasic(`${OAUTH_URL}/token`, { grant_type: grant, device_code: issued.device_code }, 'device-basic', secret);
    expect(poll.status).toBe(400); expect((await poll.json()).error).toBe('authorization_pending');
  });

  it('accepts form credentials through device authorization and token polling', async () => {
    const credentials = { client_id: 'device-post', client_secret: secret };
    const response = await postForm(`${OAUTH_URL}/device_authorization`, { ...credentials, scope: 'openid' });
    expect(response.status).toBe(200);
    const issued = await response.json(); expect(issued.device_code).toBeTruthy();
    const poll = await postForm(`${OAUTH_URL}/token`, { ...credentials, grant_type: grant, device_code: issued.device_code });
    expect(poll.status).toBe(400); expect((await poll.json()).error).toBe('authorization_pending');
  });

  it('rejects missing/wrong form secrets without issuing a code', async () => {
    for (const client_secret of ['', 'wrong']) {
      const response = await postForm(`${OAUTH_URL}/device_authorization`, { client_id: 'device-post', client_secret, scope: 'openid' });
      expect(response.status).toBe(400);
      const body = await response.json(); expect(body.error).toBe('invalid_client'); expect(body.device_code).toBeUndefined();
    }
  });

  it('challenges incorrect or malformed Basic credentials without falling back to form credentials', async () => {
    const wrong = await postFormBasic(`${OAUTH_URL}/device_authorization`, { scope: 'openid' }, 'device-basic', 'wrong');
    const malformed = await fetch(`${OAUTH_URL}/device_authorization`, { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic invalid-base64' },
      body: new URLSearchParams({ client_id: 'device-post', client_secret: secret, scope: 'openid' }) });
    for (const response of [wrong, malformed]) {
      expect(response.status).toBe(401); expect(response.headers.get('WWW-Authenticate')).toBe('Basic realm="device_authorization"');
      const body = await response.json(); expect(body.error).toBe('invalid_client'); expect(body.device_code).toBeUndefined();
    }
  });

  it('retains inactive-client, grant and scope restrictions after authentication', async () => {
    const inactive = await postFormBasic(`${OAUTH_URL}/device_authorization`, {}, 'device-inactive', secret);
    expect(inactive.status).toBe(401); expect((await inactive.json()).error).toBe('invalid_client');
    const inactivePublic = await postForm(`${OAUTH_URL}/device_authorization`, { client_id: 'device-inactive-public' });
    expect(inactivePublic.status).toBe(400); expect((await inactivePublic.json()).error).toBe('invalid_client');
    const disallowed = await postFormBasic(`${OAUTH_URL}/device_authorization`, {}, 'device-no-grant', secret);
    expect(disallowed.status).toBe(400); expect((await disallowed.json()).error).toBe('unauthorized_client');
    const scope = await postFormBasic(`${OAUTH_URL}/device_authorization`, { scope: 'openid forbidden' }, 'device-basic', secret);
    expect(scope.status).toBe(400); expect((await scope.json()).error).toBe('invalid_scope');
  });
});
