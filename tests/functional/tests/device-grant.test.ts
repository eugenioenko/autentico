import { describe, it, expect, beforeAll } from 'vitest';
import { OAUTH_URL, getAdminToken, postJSON, postForm } from '../helpers';

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
