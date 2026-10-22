import { beforeAll, describe, expect, it } from 'vitest';
import { OAUTH_URL, getAdminToken, postJSON, postForm, postFormBasic, basicClientAuthorization } from '../helpers';

const CLIENT = 'oauth+client:%2B space é';
const SECRET = 'oauth+secret:%2B space é';
const PEER = 'oauth-auth-peer';
const DEVICE = 'urn:ietf:params:oauth:grant-type:device_code';
const endpoints = ['token', 'device_authorization', 'introspect', 'revoke'];
function requestFields(endpoint: string): Record<string, string> {
  return endpoint === 'token' ? { grant_type: 'client_credentials', scope: 'profile' }
    : endpoint === 'device_authorization' ? { scope: 'openid' } : { token: 'not-a-token' };
}
async function assertError(response: Response, status: number, code: string) {
  expect(response.status).toBe(status);
  const body = await response.json(); expect(body.error).toBe(code);
  expect(body.access_token).toBeUndefined(); expect(body.device_code).toBeUndefined();
  expect(JSON.stringify(body)).not.toContain(SECRET);
}

describe('OAuth client credential transports', () => {
  beforeAll(async () => {
    const admin = await getAdminToken();
    for (const id of [CLIENT, PEER]) {
      const response = await postJSON(`${OAUTH_URL}/register`, { client_id: id, client_name: 'OAuth credential transport',
        client_type: 'confidential', client_secret: SECRET, token_endpoint_auth_method: 'client_secret_basic',
        redirect_uris: ['http://localhost/unused'], scopes: 'openid profile', response_types: ['code'],
        grant_types: ['client_credentials', DEVICE] }, admin);
      expect(response.status).toBe(201); expect((await response.json()).client_id).toBe(id);
    }
  });

  it('preserves exactly-once decoded identity through issuance, introspection, JSON compatibility and revocation', async () => {
    const issued = await postFormBasic(`${OAUTH_URL}/token`, { grant_type: 'client_credentials', scope: 'profile' }, CLIENT, SECRET);
    expect(issued.status).toBe(200);
    const token = (await issued.json()).access_token;
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    expect(claims.azp).toBe(CLIENT); expect(claims.sub).toBe(CLIENT); expect(claims.aud).toContain(CLIENT);
    const introspected = await postFormBasic(`${OAUTH_URL}/introspect`, { token }, CLIENT, SECRET);
    expect(introspected.status).toBe(200);
    const active = await introspected.json(); expect(active.active).toBe(true);
    const peerView = await postFormBasic(`${OAUTH_URL}/introspect`, { token }, PEER, SECRET);
    expect(peerView.status).toBe(200); expect((await peerView.json()).active).toBe(false);
    const legacyJSON = await fetch(`${OAUTH_URL}/introspect`, { method: 'POST',
      headers: { Authorization: basicClientAuthorization(CLIENT, SECRET), 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    expect(legacyJSON.status).toBe(200); expect((await legacyJSON.json()).active).toBe(true);
    const revoked = await postFormBasic(`${OAUTH_URL}/revoke`, { token }, CLIENT, SECRET);
    expect(revoked.status).toBe(200);
    const checked = await postFormBasic(`${OAUTH_URL}/introspect`, { token }, CLIENT, SECRET);
    expect(checked.status).toBe(200); expect((await checked.json()).active).toBe(false);
  });

  it('binds encoded device credentials to the same client and rejects another authenticated client without burning the code', async () => {
    const response = await postFormBasic(`${OAUTH_URL}/device_authorization`, { scope: 'openid' }, CLIENT, SECRET);
    expect(response.status).toBe(200); const { device_code } = await response.json(); expect(device_code).toBeTruthy();
    const other = await postFormBasic(`${OAUTH_URL}/token`, { grant_type: DEVICE, device_code }, PEER, SECRET);
    await assertError(other, 400, 'invalid_grant');
    const matching = await postFormBasic(`${OAUTH_URL}/token`, { grant_type: DEVICE, device_code }, CLIENT, SECRET);
    await assertError(matching, 400, 'authorization_pending');
  });

  it('allows redundant body identification only when it matches the decoded Basic identity', async () => {
    const response = await postFormBasic(`${OAUTH_URL}/token`, { client_id: CLIENT, grant_type: 'client_credentials', scope: 'profile' }, CLIENT, SECRET);
    expect(response.status).toBe(200);
    const token = (await response.json()).access_token;
    expect(JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).azp).toBe(CLIENT);
  });

  it('treats empty URI parameters as omitted while rejecting later non-empty credential values', async () => {
    for (const query of ['client_id=', 'client_secret=', 'client_id', 'client_secret', 'client_id=&client_secret=']) {
      const response = await postForm(`${OAUTH_URL}/token?${query}`, {
        ...requestFields('token'), client_id: CLIENT, client_secret: SECRET });
      expect(response.status).toBe(200);
      expect((await response.json()).access_token).toBeTruthy();
    }
    await assertError(await postForm(`${OAUTH_URL}/token?client_id=&client_secret=`, requestFields('token')), 401, 'invalid_client');
    for (const key of ['client_id', 'client_secret']) {
      const query = new URLSearchParams({ [key]: '' }); query.append(key, key === 'client_id' ? CLIENT : SECRET);
      await assertError(await postForm(`${OAUTH_URL}/token?${query}`, { ...requestFields('token'), client_id: CLIENT, client_secret: SECRET }), 400, 'invalid_request');
    }
  });

  for (const endpoint of endpoints) {
    it(`${endpoint} rejects URL credentials, multiple methods and contradictory body identities`, async () => {
      const query = new URLSearchParams({ client_id: CLIENT, client_secret: SECRET });
      await assertError(await postForm(`${OAUTH_URL}/${endpoint}?${query}`, requestFields(endpoint)), 400, 'invalid_request');
      await assertError(await postFormBasic(`${OAUTH_URL}/${endpoint}`, { ...requestFields(endpoint), client_id: CLIENT, client_secret: SECRET }, CLIENT, SECRET), 400, 'invalid_request');
      await assertError(await postFormBasic(`${OAUTH_URL}/${endpoint}`, { ...requestFields(endpoint), client_id: PEER }, CLIENT, SECRET), 400, 'invalid_request');
      const duplicate = new URLSearchParams({ ...requestFields(endpoint), client_id: CLIENT, client_secret: SECRET }); duplicate.append('client_secret', SECRET);
      await assertError(await fetch(`${OAUTH_URL}/${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: duplicate }), 400, 'invalid_request');
    });

    it(`${endpoint} challenges wrong or malformed Basic credentials without form fallback`, async () => {
      const wrong = await postFormBasic(`${OAUTH_URL}/${endpoint}`, requestFields(endpoint), CLIENT, 'wrong');
      const malformed = await fetch(`${OAUTH_URL}/${endpoint}`, { method: 'POST',
        headers: { Authorization: 'Basic invalid-base64', 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ ...requestFields(endpoint), client_id: CLIENT, client_secret: SECRET }) });
      const invalidEncoding = await fetch(`${OAUTH_URL}/${endpoint}`, { method: 'POST',
        headers: { Authorization: `Basic ${btoa(`${PEER}:secret%ZZ`)}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(requestFields(endpoint)) });
      for (const response of [wrong, malformed, invalidEncoding]) {
        expect(response.headers.get('WWW-Authenticate')).toMatch(/^Basic realm="/);
        await assertError(response, 401, 'invalid_client');
      }
    });
  }

  it('returns Basic challenges for unidentified token clients and matching Bearer challenges for invalid revocation credentials', async () => {
    const requests: Record<string, string>[] = [{ grant_type: 'client_credentials', scope: 'profile' },
      { grant_type: 'refresh_token', refresh_token: 'untrusted-token' },
      { grant_type: 'password', username: 'irrelevant', password: 'irrelevant' }];
    for (const form of requests) {
      const response = await postForm(`${OAUTH_URL}/token`, form);
      expect(response.headers.get('WWW-Authenticate')).toMatch(/^Basic realm="/); await assertError(response, 401, 'invalid_client');
    }
    const unidentified = await postForm(`${OAUTH_URL}/revoke`, { token: 'not-a-token' });
    expect(unidentified.headers.get('WWW-Authenticate')).toMatch(/^Basic realm="/); await assertError(unidentified, 401, 'invalid_client');
    const bearer = await postForm(`${OAUTH_URL}/revoke`, { token: 'not-a-token' }, 'invalid-bearer');
    expect(bearer.headers.get('WWW-Authenticate')).toMatch(/^Bearer .*error="invalid_token"/); await assertError(bearer, 401, 'invalid_token');
  });
});
