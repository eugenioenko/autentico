import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, deleteRequest, getResponse, obtainTokenViaROPC } from '../helpers';

const ADMIN_API = `${BASE_URL}/admin/api`;

describe('Admin Deletion Requests — happy path', () => {
  it('lists deletion requests', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${ADMIN_API}/deletion-requests`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
    expect(Array.isArray(body.data)).toBe(true);
  });

  it('approve flow: create user → user requests deletion → admin approves → user deleted', async () => {
    const adminToken = await getAdminToken();

    // Create a test user
    const createResp = await postJSON(`${ADMIN_API}/users`, {
      username: 'deleteme',
      password: 'Password123!',
      email: 'deleteme@example.com',
    }, adminToken);
    expect(createResp.status).toBe(201);
    const user = await createResp.json();
    const userId = user.data.id;

    // Get a token for the test user
    const userTokens = await obtainTokenViaROPC('deleteme', 'Password123!');

    // User requests deletion
    const delReqResp = await postJSON(`${BASE_URL}/account/api/deletion-request`, {}, userTokens.access_token);
    expect(delReqResp.status).toBe(201);
    const delReq = await delReqResp.json();

    // Admin lists deletion requests
    const listResp = await getResponse(`${ADMIN_API}/deletion-requests`, adminToken);
    const list = await listResp.json();
    const pending = list.data.find((r: { user_id: string }) => r.user_id === userId);
    expect(pending).toBeTruthy();

    // Admin approves
    const approveResp = await postJSON(`${ADMIN_API}/deletion-requests/${pending.id}/approve`, {}, adminToken);
    expect(approveResp.ok).toBe(true);

    // User should be gone
    const userResp = await getResponse(`${ADMIN_API}/users/${userId}`, adminToken);
    expect(userResp.status).toBe(404);
  });

  it('dismiss flow: create user → user requests deletion → admin dismisses', async () => {
    const adminToken = await getAdminToken();

    // Create a test user
    const createResp = await postJSON(`${ADMIN_API}/users`, {
      username: 'dismissme',
      password: 'Password123!',
      email: 'dismissme@example.com',
    }, adminToken);
    expect(createResp.status).toBe(201);
    const user = await createResp.json();
    const userId = user.data.id;

    // Get a token for the test user
    const userTokens = await obtainTokenViaROPC('dismissme', 'Password123!');

    // User requests deletion
    await postJSON(`${BASE_URL}/account/api/deletion-request`, {}, userTokens.access_token);

    // Admin lists and finds the request
    const listResp = await getResponse(`${ADMIN_API}/deletion-requests`, adminToken);
    const list = await listResp.json();
    const pending = list.data.find((r: { user_id: string }) => r.user_id === userId);
    expect(pending).toBeTruthy();

    // Admin dismisses
    const dismissResp = await deleteRequest(`${ADMIN_API}/deletion-requests/${pending.id}`, adminToken);
    expect(dismissResp.ok).toBe(true);

    // User should still exist
    const userResp = await getResponse(`${ADMIN_API}/users/${userId}`, adminToken);
    expect(userResp.ok).toBe(true);
  });
});

describe('Admin Deletion Requests — error cases', () => {
  it('rejects list without token', async () => {
    const resp = await getResponse(`${ADMIN_API}/deletion-requests`);
    expect(resp.status).toBe(401);
  });

  it('returns error for approve nonexistent request', async () => {
    const token = await getAdminToken();
    const resp = await postJSON(`${ADMIN_API}/deletion-requests/nonexistent-id/approve`, {}, token);
    expect(resp.ok).toBe(false);
  });

  it('returns error for dismiss nonexistent request', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${ADMIN_API}/deletion-requests/nonexistent-id`, token);
    expect(resp.ok).toBe(false);
  });
});
