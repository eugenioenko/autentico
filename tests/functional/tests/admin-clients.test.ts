import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, putJSON, deleteRequest, getResponse, getJSON } from '../helpers';

const API = `${BASE_URL}/admin/api/clients`;

describe('Admin Clients — happy path', () => {
  let confidentialClientId: string;
  let publicClientId: string;

  it('creates a confidential client', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      client_name: 'Functional Confidential',
      redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scopes: 'openid profile email',
    }, token);
    expect(resp.status).toBe(201);

    const client = await resp.json();
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeTruthy();
    expect(client.client_type).toBe('confidential');
    expect(client.token_endpoint_auth_method).toBe('client_secret_basic');
    confidentialClientId = client.client_id;
  });

  it('creates a public client', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      client_name: 'Functional Public',
      redirect_uris: ['http://localhost:3000/callback'],
      client_type: 'public',
    }, token);
    expect(resp.status).toBe(201);

    const client = await resp.json();
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeFalsy();
    expect(client.client_type).toBe('public');
    expect(client.token_endpoint_auth_method).toBe('none');
    publicClientId = client.client_id;
  });

  it('lists clients including created ones', async () => {
    const token = await getAdminToken();
    const clients = await getJSON<unknown[]>(API, token);
    expect(Array.isArray(clients)).toBe(true);
    const names = (clients as { client_name: string }[]).map(c => c.client_name);
    expect(names).toContain('Functional Confidential');
    expect(names).toContain('Functional Public');
  });

  it('gets client by ID', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${confidentialClientId}`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.client_name).toBe('Functional Confidential');
  });

  it('updates client name', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/${confidentialClientId}`, {
      client_name: 'Updated Confidential',
    }, token);
    expect(resp.ok).toBe(true);
  });

  it('verifies update persisted', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${confidentialClientId}`, token);
    const body = await resp.json();
    expect(body.client_name).toBe('Updated Confidential');
  });

  it('deletes (deactivates) client', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/${publicClientId}`, token);
    expect(resp.status).toBe(204);
  });
});

describe('Admin Clients — error cases', () => {
  it('rejects without token', async () => {
    const resp = await postJSON(API, { client_name: 'X', redirect_uris: ['http://x.com/cb'] });
    expect(resp.status).toBe(401);
  });

  it('rejects empty body', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {}, token);
    expect(resp.status).toBe(400);
  });

  it('rejects missing client_name', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { redirect_uris: ['http://x.com/cb'] }, token);
    expect(resp.status).toBe(400);
  });

  it('rejects missing redirect_uris', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { client_name: 'No URIs' }, token);
    expect(resp.status).toBe(400);
  });

  it('rejects invalid redirect URI with invalid_redirect_uri error', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      client_name: 'Bad URI',
      redirect_uris: ['not-a-uri'],
    }, token);
    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_redirect_uri');
  });

  it('rejects invalid grant_type with invalid_client_metadata error', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      client_name: 'Bad Grant',
      redirect_uris: ['http://x.com/cb'],
      grant_types: ['unsupported_grant'],
    }, token);
    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_client_metadata');
  });

  it('rejects invalid response_type', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      client_name: 'Bad Response Type',
      redirect_uris: ['http://x.com/cb'],
      response_types: ['invalid_type'],
    }, token);
    expect(resp.status).toBe(400);
  });

  it('returns 404 for nonexistent client', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/nonexistent-client-xyz`, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for PUT nonexistent client', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/nonexistent-client-xyz`, { client_name: 'X' }, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for DELETE nonexistent client', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-client-xyz`, token);
    expect(resp.status).toBe(404);
  });
});
