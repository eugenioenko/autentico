import { it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, ADMIN_USERNAME, ADMIN_PASSWORD, obtainAuthCodeSession, getAdminToken, postJSON, postForm } from '../helpers';

it('reports exactly one device decision and polling follows that decision', async () => {
  const admin = await getAdminToken();
  const browser = await obtainAuthCodeSession(ADMIN_USERNAME, ADMIN_PASSWORD);
  const client_id = 'device-decision-race';
  const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';
  expect((await postJSON(`${OAUTH_URL}/register`, {
    client_id, client_name: client_id, client_type: 'public', token_endpoint_auth_method: 'none',
    redirect_uris: ['http://localhost/callback'], grant_types: [grant_type], response_types: ['code'], scopes: 'openid',
  }, admin)).status).toBe(201);
  for (let round = 0; round < 40; round++) {
    const issued = await postForm(`${OAUTH_URL}/device_authorization`, { client_id, scope: 'openid' });
    expect(issued.status).toBe(200);
    const { device_code, user_code } = await issued.json();
    const decisions = await Promise.all(['authorize', 'deny'].map(action =>
      postJSON(`${BASE_URL}/account/api/device/${action}`, { user_code }, browser.access_token)));
    expect(decisions.map(r => r.status).sort()).toEqual([200, 409]);
    const authorized = decisions[0].status === 200;
    const poll = await postForm(`${OAUTH_URL}/token`, { grant_type, device_code, client_id });
    expect(poll.status).toBe(authorized ? 200 : 400);
    const outcome = await poll.json();
    if (authorized) expect(outcome.access_token).toBeTruthy();
    else { expect(outcome.error).toBe('access_denied'); expect(outcome.access_token).toBeUndefined(); }
  }
});
