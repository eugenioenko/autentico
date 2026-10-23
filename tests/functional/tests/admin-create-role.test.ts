import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, postJSON, getResponse, obtainTokenViaAuthCode } from '../helpers';

const API = `${BASE_URL}/admin/api/users`;
const password = 'Password123!';

describe('Admin user creation roles', () => {
  it.each([
    { label: 'admin', role: 'admin', expected: 'admin' },
    { label: 'user', role: 'user', expected: 'user' },
    { label: 'empty', role: '', expected: 'user' },
    { label: 'omitted', role: undefined, expected: 'user' },
  ])('persists the $label role and enforces its privileges', async ({ label, role, expected }) => {
    const admin = await getAdminToken();
    const username = `role-${label}`;
    const response = await postJSON(API, { username, password, role }, admin);
    expect(response.status).toBe(201);
    const { data: created } = await response.json();
    expect(created.role).toBe(expected);

    const stored = await getResponse(`${API}/${created.id}`, admin);
    expect(stored.status).toBe(200);
    expect((await stored.json()).data.role).toBe(expected);

    const { access_token: token } = await obtainTokenViaAuthCode(username, password);
    expect((await getResponse(API, token)).status).toBe(expected === 'admin' ? 200 : 403);
    if (expected === 'user') {
      const escalation = await postJSON(API, {
        username: `escalated-${label}`, password, role: 'admin',
      }, token);
      expect(escalation.status).toBe(403);
      const users = await getResponse(`${API}?search=escalated-${label}`, admin);
      expect((await users.json()).data.items).toHaveLength(0);
    }
  });

  it.each(['owner', 'ADMIN', ' user '])('rejects unsupported role %s without creating a user', async role => {
    const admin = await getAdminToken();
    const username = `invalid-${role.trim().toLowerCase()}`;
    const response = await postJSON(API, { username, password, role }, admin);
    expect(response.status).toBe(400);
    const users = await getResponse(`${API}?search=${encodeURIComponent(username)}`, admin);
    expect((await users.json()).data.items).toHaveLength(0);
  });
});
