import { describe, it, expect } from 'vitest';
import {
  OAUTH_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  obtainTokenViaROPC,
  postForm,
  getAdminToken,
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

  it('rotates refresh token — old token is revoked after use', async () => {
    const original = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    // Use refresh token — should rotate
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: original.refresh_token,
    });
    expect(resp.ok).toBe(true);

    const rotated = await resp.json();
    expect(rotated.refresh_token).not.toBe(original.refresh_token);

    // Old refresh token must be rejected
    const replayResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: original.refresh_token,
    });
    expect(replayResp.status).toBe(400);

    const error = await replayResp.json();
    expect(error.error).toBe('invalid_grant');
  });

  it('replay detection revokes all user tokens', async () => {
    const original = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);

    // Rotate
    const resp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: original.refresh_token,
    });
    expect(resp.ok).toBe(true);
    const rotated = await resp.json();

    // Replay old token — triggers theft detection
    const replayResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: original.refresh_token,
    });
    expect(replayResp.status).toBe(400);

    // New token should also be revoked (all user tokens invalidated)
    const newResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'refresh_token',
      refresh_token: rotated.refresh_token,
    });
    expect(newResp.status).toBe(400);
  });
});

describe('Token revocation', () => {
  it('revoked token is rejected by userinfo', async () => {
    const tokens = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);
    const adminToken = await getAdminToken();

    // Revoke (with bearer auth — admin token)
    const revokeResp = await postForm(`${OAUTH_URL}/revoke`, {
      token: tokens.access_token,
    }, adminToken);
    expect(revokeResp.status).toBe(200);

    // Verify rejected
    const userinfo = await fetch(`${OAUTH_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.status).toBe(401);
  });
});
