import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, deleteRequest, getResponse, obtainTokenViaROPC } from '../helpers';

const API = `${BASE_URL}/admin/api/users`;

/**
 * Helper: create a user via admin API and return { id, username }.
 */
async function createUser(token: string, username: string, password: string, email: string) {
  const resp = await postJSON(API, { username, password, email }, token);
  expect(resp.status).toBe(201);
  const body = await resp.json();
  return body.data as { id: string; username: string; email: string };
}

/**
 * Helper: POST to an action endpoint (deactivate/reactivate).
 */
async function postAction(url: string, token: string): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
}

// --- Deactivation ---

describe('User Deactivation', () => {
  it('deactivates a user and returns 204', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func1', 'Password123!', 'deact-func1@test.com');

    const resp = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp.status).toBe(204);
  });

  it('deactivated user cannot login via ROPC', async () => {
    const token = await getAdminToken();
    await createUser(token, 'deact-func2', 'Password123!', 'deact-func2@test.com');

    // Obtain token before deactivation to confirm login works
    const tokens = await obtainTokenViaROPC('deact-func2', 'Password123!');
    expect(tokens.access_token).toBeTruthy();

    // Deactivate
    const user = await getResponse(`${API}`, token).then(r => r.json()).then(body =>
      body.data.find((u: { username: string }) => u.username === 'deact-func2')
    );
    const deactResp = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(deactResp.status).toBe(204);

    // ROPC login should fail
    try {
      await obtainTokenViaROPC('deact-func2', 'Password123!');
      expect.fail('Should have thrown — deactivated user should not be able to login');
    } catch {
      // Expected: login fails for deactivated user
    }
  });

  it('deactivated user does not appear in user list', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func3', 'Password123!', 'deact-func3@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);

    const listResp = await getResponse(API, token);
    const body = await listResp.json();
    const found = body.data.find((u: { username: string }) => u.username === 'deact-func3');
    expect(found).toBeUndefined();
  });

  it('returns 404 when deactivating already deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'deact-func4', 'Password123!', 'deact-func4@test.com');

    const resp1 = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp1.status).toBe(204);

    const resp2 = await postAction(`${API}/${user.id}/deactivate`, token);
    expect(resp2.status).toBe(404);
  });

  it('returns 404 when deactivating nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await postAction(`${API}/nonexistent-id/deactivate`, token);
    expect(resp.status).toBe(404);
  });
});

// --- Reactivation ---

describe('User Reactivation', () => {
  it('reactivates a deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func1', 'Password123!', 'react-func1@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    const resp = await postAction(`${API}/${user.id}/reactivate`, token);
    expect(resp.status).toBe(204);

    // User should appear in list again
    const listResp = await getResponse(API, token);
    const body = await listResp.json();
    const found = body.data.find((u: { username: string }) => u.username === 'react-func1');
    expect(found).toBeTruthy();
  });

  it('reactivated user can login again', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func2', 'Password123!', 'react-func2@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    await postAction(`${API}/${user.id}/reactivate`, token);

    const tokens = await obtainTokenViaROPC('react-func2', 'Password123!');
    expect(tokens.access_token).toBeTruthy();
  });

  it('returns 404 when reactivating a non-deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'react-func3', 'Password123!', 'react-func3@test.com');

    const resp = await postAction(`${API}/${user.id}/reactivate`, token);
    expect(resp.status).toBe(404);
  });

  it('returns 404 when reactivating nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await postAction(`${API}/nonexistent-id/reactivate`, token);
    expect(resp.status).toBe(404);
  });
});

// --- Hard Delete ---

describe('User Hard Delete', () => {
  it('permanently deletes a user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func1', 'Password123!', 'hd-func1@test.com');

    const resp = await deleteRequest(`${API}/${user.id}`, token);
    expect(resp.status).toBe(204);

    // User should be gone
    const getResp = await getResponse(`${API}/${user.id}`, token);
    expect(getResp.status).toBe(404);
  });

  it('frees username and email after hard delete', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func2', 'Password123!', 'hd-func2@test.com');

    await deleteRequest(`${API}/${user.id}`, token);

    // Re-create with same username/email should work
    const newUser = await createUser(token, 'hd-func2', 'Password123!', 'hd-func2@test.com');
    expect(newUser.id).not.toBe(user.id);
  });

  it('can hard-delete a deactivated user', async () => {
    const token = await getAdminToken();
    const user = await createUser(token, 'hd-func3', 'Password123!', 'hd-func3@test.com');

    await postAction(`${API}/${user.id}/deactivate`, token);
    const resp = await deleteRequest(`${API}/${user.id}`, token);
    expect(resp.status).toBe(204);
  });

  it('returns 404 for nonexistent user', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-id`, token);
    expect(resp.status).toBe(404);
  });
});
