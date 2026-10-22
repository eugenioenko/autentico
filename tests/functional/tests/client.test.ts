import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, putJSON, getJSON } from '../helpers';

describe('Client registration (admin API)', () => {
  it('creates a confidential client', async () => {
    const token = await getAdminToken();

    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_name: 'Functional Test Client',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scopes: 'openid profile email',
      },
      token
    );
    expect(resp.status).toBe(201);

    const client = await resp.json();
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeTruthy();
    expect(client.client_name).toBe('Functional Test Client');
    expect(client.client_type).toBe('confidential');
    expect(client.token_endpoint_auth_method).toBe('client_secret_basic');
    expect(client.client_secret_expires_at).toBe(0);
    expect(client.client_id_issued_at).toBeGreaterThan(0);
  });

  it('creates a public client', async () => {
    const token = await getAdminToken();

    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_name: 'Public Test Client',
        redirect_uris: ['http://localhost:3000/callback'],
        client_type: 'public',
      },
      token
    );
    expect(resp.status).toBe(201);

    const client = await resp.json();
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeFalsy();
    expect(client.client_type).toBe('public');
    expect(client.token_endpoint_auth_method).toBe('none');
  });

  it('lists registered clients', async () => {
    const token = await getAdminToken();

    const resp = await getJSON<{ data: { items: unknown[]; total: number } }>(
      `${BASE_URL}/admin/api/clients`,
      token
    );
    // At minimum: autentico-admin, autentico-account, plus the ones we created above
    expect(resp.data.items.length).toBeGreaterThanOrEqual(2);
    expect(resp.data.total).toBeGreaterThanOrEqual(2);
  });

  it('rejects registration without auth', async () => {
    const resp = await postJSON(`${OAUTH_URL}/register`, {
      client_name: 'No Auth Client',
      redirect_uris: ['http://localhost:3000/callback'],
    });
    expect(resp.status).toBe(401);
  });

  it('returns invalid_client_metadata for bad grant type', async () => {
    const token = await getAdminToken();

    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_name: 'Bad Grant Client',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['unsupported_grant'],
      },
      token
    );
    expect(resp.status).toBe(400);

    const body = await resp.json();
    expect(body.error).toBe('invalid_client_metadata');
  });
});


describe('implemented authorization response types', () => {
  it('rejects unsupported response types during registration and update', async () => {
    const token = await getAdminToken();
    const created = await postJSON(`${OAUTH_URL}/register`, { client_name: 'Code-only responses',
      redirect_uris: ['http://localhost:3000/callback'], response_types: ['code'], client_type: 'public' }, token);
    expect(created.status).toBe(201);
    const client = await created.json();
    for (const response_types of [['token'], ['id_token'], ['code', 'token'], ['code id_token']]) {
      for (const endpoint of [`${OAUTH_URL}/register`, `${BASE_URL}/admin/api/clients`]) {
        const response = await postJSON(endpoint, { client_name: 'Unsupported response',
          redirect_uris: ['http://localhost:3000/callback'], response_types }, token);
        expect(response.status).toBe(400);
      }
      const updated = await putJSON(`${BASE_URL}/admin/api/clients/${client.client_id}`, { response_types }, token);
      expect(updated.status).toBe(400);
    }
    const stored = await getJSON<{ response_types: string[] }>(`${BASE_URL}/admin/api/clients/${client.client_id}`, token);
    expect(stored.response_types).toEqual(['code']);
    const query = new URLSearchParams({ client_id: client.client_id, redirect_uri: 'http://localhost:3000/callback',
      response_type: 'code', state: 'opaque & state', scope: 'openid',
      code_challenge: 'challenge', code_challenge_method: 'S256' });
    for (const responseType of ['token', 'id_token', 'code token', 'unknown']) {
      query.set('response_type', responseType);
      const response = await fetch(`${OAUTH_URL}/authorize?${query}`, { redirect: 'manual' });
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get('Location')!);
      expect(target.searchParams.get('error')).toBe('unsupported_response_type');
      expect(target.searchParams.get('state')).toBe('opaque & state');
      expect(target.searchParams.get('code')).toBeNull();
    }
    query.set('response_type', 'code');
    const supported = await fetch(`${OAUTH_URL}/authorize?${query}`, { redirect: 'manual' });
    expect(supported.status).toBe(200);
    expect(await supported.text()).toContain('name="authorize_sig"');
  });
});
