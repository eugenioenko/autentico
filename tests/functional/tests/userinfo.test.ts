import { describe, it, expect } from 'vitest';
import { OAUTH_URL, ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_EMAIL, obtainTokenViaROPC } from '../helpers';

describe('UserInfo endpoint', () => {
  it('returns claims for valid token', async () => {
    const tokens = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    const resp = await fetch(`${OAUTH_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(resp.ok).toBe(true);

    const claims = await resp.json();
    expect(claims.sub).toBeTruthy();
    expect(claims.email).toBe(ADMIN_EMAIL);
    expect(claims.preferred_username).toBe(ADMIN_USERNAME);
  });

  it('returns 401 for invalid token', async () => {
    const resp = await fetch(`${OAUTH_URL}/userinfo`, {
      headers: { Authorization: 'Bearer garbage-token' },
    });
    expect(resp.status).toBe(401);
  });

  it('returns 401 when no token provided', async () => {
    const resp = await fetch(`${OAUTH_URL}/userinfo`);
    expect(resp.status).toBe(401);
  });
});
