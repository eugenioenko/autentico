import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, getResponse, getJSON } from '../helpers';

describe('Admin Stats', () => {
  it('returns stats with counts', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/admin/api/stats`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
  });

  it('rejects without token', async () => {
    const resp = await getResponse(`${BASE_URL}/admin/api/stats`);
    expect(resp.status).toBe(401);
  });
});

describe('Admin Audit Logs', () => {
  it('returns audit log entries', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/admin/api/audit-logs`, token);
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.data).toBeTruthy();
  });

  it('rejects without token', async () => {
    const resp = await getResponse(`${BASE_URL}/admin/api/audit-logs`);
    expect(resp.status).toBe(401);
  });
});
