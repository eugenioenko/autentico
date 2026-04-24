import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, putJSON, deleteRequest, getResponse, getJSON } from '../helpers';

const API = `${BASE_URL}/admin/api/users`;

describe('Admin Users — happy path', () => {
  let createdUserId: string;

  it('creates a user', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {
      username: 'testuser1',
      password: 'TestPass123!',
      email: 'testuser1@example.com',
    }, token);
    expect(resp.status).toBe(201);

    const user = await resp.json();
    expect(user.data.id).toBeTruthy();
    expect(user.data.username).toBe('testuser1');
    expect(user.data.email).toBe('testuser1@example.com');
    createdUserId = user.data.id;
  });

  it('lists users and includes the created user', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(API, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    const users = body.data.items;
    expect(Array.isArray(users)).toBe(true);
    const found = users.find((u: { username: string }) => u.username === 'testuser1');
    expect(found).toBeTruthy();
  });

  it('gets user by ID', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${createdUserId}`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data.username).toBe('testuser1');
    expect(body.data.email).toBe('testuser1@example.com');
  });

  it('updates user email', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/${createdUserId}`, {
      email: 'updated@example.com',
    }, token);
    expect(resp.ok).toBe(true);
  });

  it('verifies update persisted', async () => {
    const token = await getAdminToken();
    const body = await getJSON<{ data: { email: string } }>(`${API}/${createdUserId}`, token);
    expect(body.data.email).toBe('updated@example.com');
  });

  it('deletes user', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/${createdUserId}`, token);
    expect(resp.status).toBe(204);
  });

  it('returns 404 after deletion', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/${createdUserId}`, token);
    expect(resp.status).toBe(404);
  });
});

describe('Admin Users — error cases', () => {
  it('rejects request without token', async () => {
    const resp = await postJSON(API, { username: 'x', password: 'y' });
    expect(resp.status).toBe(401);
  });

  it('rejects request with invalid token', async () => {
    const resp = await postJSON(API, { username: 'x', password: 'y' }, 'garbage-token');
    expect(resp.status).toBe(401);
  });

  it('rejects empty body', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, {}, token);
    expect(resp.status).toBe(400);
  });

  it('rejects missing username', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { password: 'TestPass123!' }, token);
    expect(resp.status).toBe(400);
  });

  it('rejects missing password', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { username: 'nopass' }, token);
    expect(resp.status).toBe(400);
  });

  it('rejects password too short', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(API, { username: 'shortpw', password: 'ab' }, token);
    expect(resp.status).toBe(400);
  });

  it('rejects duplicate username', async () => {
    const token = await getAdminToken();
    // Create first
    await postJSON(API, { username: 'dupuser', password: 'TestPass123!' }, token);
    // Try duplicate
    const resp = await postJSON(API, { username: 'dupuser', password: 'TestPass123!' }, token);
    expect(resp.status).toBe(400);
  });

  it('returns 404 for nonexistent user GET', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${API}/nonexistent-id-12345`, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for nonexistent user PUT', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(`${API}/nonexistent-id-12345`, { email: 'x@y.com' }, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 for nonexistent user DELETE', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-id-12345`, token);
    expect(resp.status).toBe(404);
  });

  it('GET list rejects without token', async () => {
    const resp = await getResponse(API);
    expect(resp.status).toBe(401);
  });
});
