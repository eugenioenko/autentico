import { describe, it, expect } from 'vitest';
import {
  BASE_URL,
  OAUTH_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  obtainTokenViaAuthCode,
  obtainTokenViaROPC,
  postForm,
  getResponse,
} from '../helpers';

// Same bug family as issue #225 but on the tokens table instead of sessions:
// a token marked tokens.revoked_at via /oauth2/revoke (RFC 7009) must be
// rejected everywhere — including /account/api/* and /admin/api/*, not just
// /oauth2/userinfo.
describe('Account API honors token revocation (tokens.revoked_at)', () => {
  it('rejects a user token at /account/api/profile after /oauth2/revoke', async () => {
    // Use a fresh admin token rather than the cached helper — other tests
    // in this suite revoke the admin user's authorization_code tokens,
    // which correctly fails the admin bearer gate on /oauth2/revoke.
    const admin = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    const user = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    // Sanity: the user token works before revocation
    const pre = await getResponse(`${BASE_URL}/account/api/profile`, user.access_token);
    expect(pre.status).toBe(200);

    // Admin revokes the user's access token
    const revoke = await postForm(
      `${OAUTH_URL}/revoke`,
      { token: user.access_token },
      admin.access_token,
    );
    expect(revoke.status).toBe(200);

    // /oauth2/userinfo rejects (already covered by token.test.ts — keep for sanity)
    const userinfo = await getResponse(`${OAUTH_URL}/userinfo`, user.access_token);
    expect(userinfo.status).toBe(401);

    // Account API must also reject — this is the new behavior.
    const profile = await getResponse(`${BASE_URL}/account/api/profile`, user.access_token);
    expect(profile.status).toBe(401);
  });
});
