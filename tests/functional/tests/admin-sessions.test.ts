import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, obtainTokenViaROPC, deleteRequest, getResponse, getJSON } from '../helpers';

const API = `${BASE_URL}/admin/api/sessions`;

describe('Admin Sessions — happy path', () => {
  it('lists sessions', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(API, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);
  });

  it('deactivates a session', async () => {
    const adminToken = await getAdminToken();

    // List sessions
    const resp = await getResponse(API, adminToken);
    const body = await resp.json();
    const sessions = body.data;
    expect(sessions.length).toBeGreaterThan(0);

    // Find an active session
    const activeSession = sessions.find((s: { deactivated_at: string | null }) => !s.deactivated_at);
    expect(activeSession).toBeTruthy();

    // Deactivate it
    const deleteResp = await deleteRequest(`${API}/${activeSession.id}`, adminToken);
    expect(deleteResp.ok).toBe(true);
  });
});

describe('Admin Sessions — error cases', () => {
  it('rejects list without token', async () => {
    const resp = await getResponse(API);
    expect(resp.status).toBe(401);
  });

  it('rejects delete without token', async () => {
    const resp = await deleteRequest(`${API}/some-id`);
    expect(resp.status).toBe(401);
  });

  it('returns error for nonexistent session', async () => {
    const token = await getAdminToken();
    const resp = await deleteRequest(`${API}/nonexistent-session-id`, token);
    expect(resp.ok).toBe(false);
  });
});
