import { describe, it, expect } from 'vitest';
import {
  ADMIN_CLIENT_ID,
  ADMIN_PASSWORD,
  ADMIN_USERNAME,
  BASE_URL,
  OAUTH_URL,
  getResponse,
  postForm,
} from '../helpers';

// Verifies the --enable-admin-password-grant CLI flag: the onboard step seeds
// autentico-admin with the `password` (ROPC) grant, so CI/automation can mint
// admin-API tokens without driving a browser. The global setup.ts passes the
// flag to `autentico onboard`, so the behavior is active for this suite.
describe('Admin password grant (headless admin-API access)', () => {
  it('issues a token via grant_type=password for the admin client', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'password',
      username: ADMIN_USERNAME,
      password: ADMIN_PASSWORD,
      client_id: ADMIN_CLIENT_ID,
      scope: 'openid profile email',
    });

    expect(resp.ok).toBe(true);
    const body = await resp.json();
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
  });

  it('calls an admin-API endpoint with the password-grant token', async () => {
    const tokenResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'password',
      username: ADMIN_USERNAME,
      password: ADMIN_PASSWORD,
      client_id: ADMIN_CLIENT_ID,
      scope: 'openid profile email',
    });
    expect(tokenResp.ok).toBe(true);
    const { access_token } = await tokenResp.json();

    const statsResp = await getResponse(`${BASE_URL}/admin/api/stats`, access_token);
    expect(statsResp.status).toBe(200);
    const stats = await statsResp.json();
    expect(stats.data).toBeTruthy();
  });

  it('rejects wrong credentials with invalid_grant', async () => {
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'password',
      username: ADMIN_USERNAME,
      password: 'wrong-password',
      client_id: ADMIN_CLIENT_ID,
    });

    expect(resp.status).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe('invalid_grant');
  });
});
