import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, putJSON, deleteRequest, getResponse } from '../helpers';

const API = `${BASE_URL}/admin/api/federation`;

describe('Admin Federation Providers — happy path', () => {
  const providerId = 'func-test-github';

  it('creates a federation provider', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      id: providerId,
      name: 'Test GitHub',
      issuer: 'https://github.com',
      client_id: 'gh-client-id',
      client_secret: 'gh-client-secret',
    }, token);
    expect(resp.status).toBe(201);
  });

  it('lists providers', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(API, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    const providers = body.data ?? body;
    expect(Array.isArray(providers)).toBe(true);
    const found = providers.find((p: { id: string }) => p.id === providerId);
    expect(found).toBeTruthy();
  });

  it('gets provider by ID', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${providerId}`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    const provider = body.data ?? body;
    expect(provider.name).toBe('Test GitHub');
  });

  it('updates provider', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/${providerId}`, {
      name: 'Updated GitHub',
      issuer: 'https://github.com',
      client_id: 'gh-client-id',
    }, token);
    expect(resp.ok).toBe(true);
  });

  it('verifies update persisted', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${providerId}`, token);
    const body = await resp.json();
    const provider = body.data ?? body;
    expect(provider.name).toBe('Updated GitHub');
  });

  it('deletes provider', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/${providerId}`, token);
    expect(resp.ok).toBe(true);
  });

  it('returns 404 after deletion', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${providerId}`, token);
    expect(resp.status).toBe(404);
  });
});

describe('Admin Federation Providers — error cases', () => {
  it('rejects without token', async () => {
    const resp = await postJSON(API, { id: 'x', name: 'X', issuer: 'https://x.com', client_id: 'x', client_secret: 'x' });
    expect(resp.status).toBe(401);
  });

  it('rejects missing required fields', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { name: 'Missing fields' }, token);
    expect(resp.status).toBe(400);
  });

  it('returns 404 for nonexistent provider GET', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/nonexistent-provider-id`, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for nonexistent provider PUT', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/nonexistent-provider-id`, { name: 'X', issuer: 'https://x.com', client_id: 'x' }, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for nonexistent provider DELETE', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-provider-id`, token);
    expect(resp.status).toBe(404);
  });
});
