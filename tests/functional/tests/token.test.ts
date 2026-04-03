import { describe, it, expect } from 'vitest';
import {
  OAUTH_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  obtainTokenViaROPC,
  postForm,
} from '../helpers';

describe('Token endpoint — ROPC', () => {
  it('returns access, refresh, and id tokens', async () => {
    const tokens = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.token_type).toBe('Bearer');
  });
});

describe('Token endpoint — Refresh', () => {
  it('returns new tokens from refresh token', async () => {
    const original = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: original.refresh_token,
    });
    expect(resp.ok).toBe(true);

    const refreshed = await resp.json();
    expect(refreshed.access_token).toBeTruthy();
    expect(refreshed.refresh_token).toBeTruthy();
    expect(refreshed.access_token).not.toBe(original.access_token);
  });
});

describe('Token revocation', () => {
  it('revoked token is rejected by userinfo', async () => {
    const tokens = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    // Revoke
    const revokeResp = await postForm(`${OAUTH_URL}/revoke`, {
      token: tokens.access_token,
    });
    expect(revokeResp.status).toBe(200);

    // Verify rejected
    const userinfo = await fetch(`${OAUTH_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.status).toBe(401);
  });
});
