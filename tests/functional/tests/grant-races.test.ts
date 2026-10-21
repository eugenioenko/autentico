import { describe, it, expect } from 'vitest';
import {
  BASE_URL, OAUTH_URL, ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_CLIENT_ID,
  ADMIN_REDIRECT_URI, obtainAuthorizationCode,
  obtainTokenViaAuthCode, obtainTokenViaROPC, postForm, postJSON,
} from '../helpers';

const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

async function raceGrant(form: Record<string, string>, device = false) {
  const replies = await Promise.all(Array.from({ length: 20 }, async () => {
    const response = await postForm(`${OAUTH_URL}/token`, form);
    return { status: response.status, body: await response.json() };
  }));
  const winners = replies.filter(r => r.status === 200);
  expect(winners).toHaveLength(1);
  expect(winners[0].body.access_token).toBeTruthy();
  expect(winners[0].body.refresh_token).toBeTruthy();
  for (const rejected of replies.filter(r => r.status !== 200)) {
    expect(rejected.status).toBe(400);
    expect(device ? ['invalid_grant', 'slow_down'] : ['invalid_grant']).toContain(rejected.body.error);
    expect(rejected.body.access_token).toBeUndefined();
    expect(rejected.body.refresh_token).toBeUndefined();
  }
}

describe('Single-use grants under concurrent redemption', () => {
  it('issues one token pair for twenty authorization-code exchanges', async () => {
    const { code } = await obtainAuthorizationCode(ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI, ADMIN_USERNAME, ADMIN_PASSWORD);
    await raceGrant({ grant_type: 'authorization_code', code, client_id: ADMIN_CLIENT_ID,
      redirect_uri: ADMIN_REDIRECT_URI, code_verifier: verifier });
  });

  it('issues one replacement for twenty refresh requests', async () => {
    const original = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD);
    const { azp: client_id } = JSON.parse(Buffer.from(original.refresh_token.split('.')[1], 'base64url').toString());
    await raceGrant({ grant_type: 'refresh_token', refresh_token: original.refresh_token, client_id });
  });

  it('issues one token pair for twenty approved device-code polls', async () => {
    // The preceding refresh replay revoked cached admin tokens; sign in again.
    const { access_token: admin } = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    const client_id = 'atomic-device-client';
    const registration = await postJSON(`${OAUTH_URL}/register`, {
      client_id, client_name: 'Atomic device test', client_type: 'public',
      token_endpoint_auth_method: 'none', redirect_uris: ['http://localhost:3000/callback'],
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      response_types: ['code'], scopes: 'openid profile email',
    }, admin);
    expect(registration.status).toBe(201);
    const requested = await postForm(`${OAUTH_URL}/device_authorization`, { client_id, scope: 'openid profile' });
    expect(requested.status).toBe(200);
    const { user_code, device_code } = await requested.json();
    const approved = await postJSON(`${BASE_URL}/account/api/device/authorize`, { user_code }, admin);
    expect(approved.status).toBe(200);
    await raceGrant({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code, client_id }, true);
  });

  it('preserves a refresh token after an invalid scope so a valid retry succeeds', async () => {
    const original = await obtainTokenViaROPC(ADMIN_USERNAME, ADMIN_PASSWORD, 'openid profile');
    const { azp: client_id } = JSON.parse(Buffer.from(original.refresh_token.split('.')[1], 'base64url').toString());
    const form = { grant_type: 'refresh_token', refresh_token: original.refresh_token, client_id };
    const invalid = await postForm(`${OAUTH_URL}/token`, { ...form, scope: 'not-granted' });
    expect(invalid.status).toBe(400);
    expect((await invalid.json()).error).toBe('invalid_scope');
    const valid = await postForm(`${OAUTH_URL}/token`, form);
    expect(valid.status).toBe(200);
    expect((await valid.json()).refresh_token).not.toBe(original.refresh_token);
  });
});
