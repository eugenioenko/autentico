import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, postForm, obtainAuthorizationCode, putJSON } from '../helpers';

const callback = 'http://localhost:3000/callback';
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

describe('Client registration authentication metadata', () => {
  for (const clientType of ['', 'public', 'confidential', 'unsupported']) {
    for (const method of ['', 'none', 'client_secret_basic', 'client_secret_post', 'unsupported']) {
      it(`registers or rejects type=${clientType || 'omitted'} method=${method || 'omitted'} consistently`, async () => {
        const admin = await getAdminToken();
        const id = `metadata-${clientType || 'default'}-${method || 'default'}`;
        const response = await postJSON(`${OAUTH_URL}/register`, {
          client_id: id, client_name: id, redirect_uris: [callback],
          ...(clientType ? { client_type: clientType } : {}),
          ...(method ? { token_endpoint_auth_method: method } : {}),
        }, admin);
        const contradictory = clientType === 'unsupported' || method === 'unsupported' || (clientType === 'public' && method !== '' && method !== 'none') ||
          (clientType === 'confidential' && method === 'none');
        if (contradictory) {
          expect(response.status).toBe(400);
          expect(await response.json()).toMatchObject({ error: 'invalid_client_metadata' });
          const absent = await fetch(`${BASE_URL}/admin/api/clients/${id}`, { headers: { Authorization: `Bearer ${admin}` } });
          expect(absent.status).toBe(404);
          return;
        }
        expect(response.status).toBe(201);
        const body = await response.json();
        const effectiveType = clientType || (method === 'none' ? 'public' : 'confidential');
        const effectiveMethod = method || (effectiveType === 'public' ? 'none' : 'client_secret_basic');
        expect(body).toMatchObject({ client_type: effectiveType, token_endpoint_auth_method: effectiveMethod });
        if (effectiveType === 'public') expect(body).not.toHaveProperty('client_secret');
        else expect(body.client_secret).toBeTruthy();
        const read = await fetch(`${OAUTH_URL}/register/${id}`, { headers: { Authorization: `Bearer ${admin}` } });
        expect(read.status).toBe(200);
        expect(await read.json()).toMatchObject({ client_type: effectiveType, token_endpoint_auth_method: effectiveMethod });
      });
    }
  }

  it('infers a public client from none and permits PKCE exchange and refresh without a secret', async () => {
    const admin = await getAdminToken();
    const clientId = 'standard-none-client';
    const registered = await postJSON(`${OAUTH_URL}/register`, {
      client_id: clientId, client_name: clientId, redirect_uris: [callback],
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'],
      scopes: 'openid offline_access',
    }, admin);
    expect(registered.status).toBe(201);
    expect(await registered.json()).toMatchObject({ client_type: 'public', token_endpoint_auth_method: 'none' });
    const missingChallenge = await fetch(`${OAUTH_URL}/authorize?${new URLSearchParams({
      client_id: clientId, redirect_uri: callback, response_type: 'code', scope: 'openid', state: 'missing-challenge',
    })}`, { redirect: 'manual' });
    expect(missingChallenge.status).toBe(302);
    const denied = new URL(missingChallenge.headers.get('location')!);
    expect(denied.origin + denied.pathname).toBe(callback);
    expect(denied.searchParams.get('error')).toBe('invalid_request');
    expect(denied.searchParams.get('error_description')).toContain('code_challenge is required');
    expect(denied.searchParams.get('state')).toBe('missing-challenge');
    expect(denied.searchParams.has('code')).toBe(false);
    const { code } = await obtainAuthorizationCode(clientId, callback, 'admin', 'Password123!', 'openid offline_access');
    const missingPKCE = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: callback,
    });
    expect(missingPKCE.status).toBe(400);
    const exchanged = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'authorization_code', client_id: clientId, code, redirect_uri: callback, code_verifier: verifier,
    });
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    const tokens = await exchanged.json();
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    const refreshed = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token', client_id: clientId, refresh_token: tokens.refresh_token,
    });
    expect(refreshed.status).toBe(200);
  });

  for (const clientType of ['public', 'confidential']) {
    it(`rejects contradictory updates without changing a ${clientType} client's authentication`, async () => {
      const admin = await getAdminToken();
      const clientId = `update-metadata-${clientType}`;
      const registered = await postJSON(`${BASE_URL}/admin/api/clients`, {
        client_id: clientId, client_name: clientId, client_type: clientType, redirect_uris: [callback],
        grant_types: ['password', 'refresh_token'], scopes: 'openid offline_access',
      }, admin);
      expect(registered.status).toBe(201);
      const original = await registered.json();
      const response = await putJSON(`${OAUTH_URL}/register/${clientId}`, {
        client_name: 'must-not-change', token_endpoint_auth_method: clientType === 'public' ? 'client_secret_basic' : 'none',
      }, admin);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_client_metadata' });
      const read = await fetch(`${BASE_URL}/admin/api/clients/${clientId}`, { headers: { Authorization: `Bearer ${admin}` } });
      expect(read.status).toBe(200);
      expect(await read.json()).toMatchObject({ client_name: clientId, client_type: clientType,
        token_endpoint_auth_method: original.token_endpoint_auth_method });
      const fields = { grant_type: 'password', client_id: clientId, username: 'admin', password: 'Password123!', scope: 'openid' };
      const noSecret = await postForm(`${OAUTH_URL}/token`, fields);
      expect(noSecret.status).toBe(clientType === 'public' ? 200 : 401);
      if (clientType === 'confidential') {
        const validSecret = await postForm(`${OAUTH_URL}/token`, { ...fields, client_secret: original.client_secret });
        expect(validSecret.status).toBe(200);
      }
    });
  }
});
