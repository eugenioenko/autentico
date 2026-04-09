import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, getResponse } from '../helpers';

describe('Security Headers', () => {
  it('admin API returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/admin/api/users`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('account API returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/account/api/settings`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('userinfo returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${OAUTH_URL}/userinfo`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('discovery endpoint returns Cache-Control: no-store', async () => {
    const resp = await getResponse(`${BASE_URL}/.well-known/openid-configuration`);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('all responses include X-Frame-Options and X-Content-Type-Options', async () => {
    const resp = await getResponse(`${BASE_URL}/.well-known/openid-configuration`);
    expect(resp.headers.get('X-Frame-Options')).toBe('DENY');
    expect(resp.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('error responses also include cache headers', async () => {
    // Unauthenticated request to admin API — should still have cache headers
    const resp = await getResponse(`${BASE_URL}/admin/api/users`);
    expect(resp.status).toBe(401);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });
});
