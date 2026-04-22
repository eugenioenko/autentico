import { describe, it, expect } from 'vitest';
import { BASE_URL, obtainTokenViaROPC, deleteRequest, getResponse } from '../helpers';

function sidFromAccessToken(accessToken: string): string {
  const [, payload] = accessToken.split('.');
  const json = Buffer.from(payload, 'base64url').toString('utf-8');
  const claims = JSON.parse(json) as { sid?: string };
  if (!claims.sid) throw new Error('access token has no sid claim');
  return claims.sid;
}

// Regression for https://github.com/eugenioenko/autentico/issues/225:
// revoking session A via /account/api/sessions/:id must invalidate Token A
// everywhere — including /account/api/*, not just /oauth2/userinfo.
describe('Account API honors session revocation (issue #225)', () => {
  it('rejects token A at /account/api/profile after session A is revoked by token B', async () => {
    // Step 1: obtain two separate tokens for the same user
    const a = await obtainTokenViaROPC('admin', 'Password123!');
    const b = await obtainTokenViaROPC('admin', 'Password123!');
    expect(a.access_token).not.toBe(b.access_token);

    const sessionAID = sidFromAccessToken(a.access_token);
    const sessionBID = sidFromAccessToken(b.access_token);
    expect(sessionAID).not.toBe(sessionBID);

    // Step 2: Token B revokes Session A — expect 200 OK with "Session revoked"
    const revoke = await deleteRequest(
      `${BASE_URL}/account/api/sessions/${sessionAID}`,
      b.access_token,
    );
    expect(revoke.status).toBe(200);
    const revokeBody = await revoke.json();
    expect(revokeBody.data.message).toBe('Session revoked');

    // Step 3: the OAuth2 layer rejects Token A — 401 invalid_token
    const userinfo = await getResponse(`${BASE_URL}/oauth2/userinfo`, a.access_token);
    expect(userinfo.status).toBe(401);
    const userinfoBody = await userinfo.json();
    expect(userinfoBody.error).toBe('invalid_token');
    expect(userinfoBody.error_description).toContain('deactivated');

    // Step 4: the account API must ALSO reject Token A — this is the fix.
    // Before issue #225 was patched, this returned 200 with the full profile.
    const profile = await getResponse(`${BASE_URL}/account/api/profile`, a.access_token);
    expect(profile.status).toBe(401);
  });
});
