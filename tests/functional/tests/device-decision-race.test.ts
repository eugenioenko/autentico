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

it('polling follows both deterministic approval-wins and denial-wins decisions', async () => {
 const admin = await getAdminToken();
 const browser = await obtainAuthCodeSession(ADMIN_USERNAME, ADMIN_PASSWORD);
 const client_id = 'device-decision-outcomes';
 const grant_type = 'urn:ietf:params:oauth:grant-type:device_code';
 expect((await postJSON(`${OAUTH_URL}/register`, {client_id,client_name:client_id,client_type:'public',token_endpoint_auth_method:'none',redirect_uris:['http://localhost/callback'],grant_types:[grant_type],response_types:['code'],scopes:'openid'},admin)).status).toBe(201);
 for (const winner of ['authorize','deny']) {
  const issued = await postForm(`${OAUTH_URL}/device_authorization`,{client_id,scope:'openid'});
  expect(issued.status).toBe(200);
  const {device_code,user_code} = await issued.json();
  expect((await postJSON(`${BASE_URL}/account/api/device/${winner}`,{user_code},browser.access_token)).status).toBe(200);
  const loser = await postJSON(`${BASE_URL}/account/api/device/${winner === 'authorize' ? 'deny' : 'authorize'}`,{user_code},browser.access_token);
  expect(loser.status).toBe(409);
  expect(await loser.json()).toMatchObject({error:'already_used'});
  const poll = await postForm(`${OAUTH_URL}/token`,{grant_type,device_code,client_id});
  expect(poll.status).toBe(winner === 'authorize' ? 200 : 400);
  const outcome=await poll.json();
  if (winner === 'authorize') expect(outcome.access_token).toBeTruthy();
  else {expect(outcome.error).toBe('access_denied');expect(outcome.access_token).toBeUndefined();}
 }
});
