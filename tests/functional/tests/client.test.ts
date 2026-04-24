import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, getJSON } from '../helpers';

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
