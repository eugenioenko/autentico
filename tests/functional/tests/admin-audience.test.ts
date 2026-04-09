import { describe, it, expect } from 'vitest';
import { BASE_URL, getAdminToken, obtainTokenViaROPC, getResponse, ADMIN_USERNAME, ADMIN_PASSWORD } from '../helpers';

const USERS_API = `${BASE_URL}/admin/api/users`;

describe('Admin API — audience enforcement', () => {
  it('accepts token from autentico-admin client', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(USERS_API, token);
    expect(resp.status).toBe(200);
  });

  it('rejects admin-role token from a different client', async () => {
    // obtainTokenViaROPC uses a separate ROPC client, not autentico-admin.
    // The admin user's token will have aud: [issuer, ropc-client-id] — no "autentico-admin".
    const tokens = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);
    const resp = await getResponse(USERS_API, tokens.access_token);
    expect(resp.status).toBe(403);
    const body = await resp.json();
    expect(body.error_description).toContain('Token not issued for admin API');
  });
});
