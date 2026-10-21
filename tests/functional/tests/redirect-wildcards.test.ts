import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, putJSON, getResponse, obtainAuthorizationCode, postForm } from '../helpers';

const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const pattern = 'http://localhost:3000/test/*/callback?fixed=1';

describe('Redirect wildcard boundaries', () => {
  it('accepts a conformance identifier and rejects traversal/query variants before redirecting', async () => {
    const admin = await getAdminToken();
    const registered = await postJSON(`${OAUTH_URL}/register`, {
      client_id: 'bounded-wildcard', client_name: 'Bounded wildcard', redirect_uris: [pattern],
      grant_types: ['authorization_code'], response_types: ['code'], scopes: 'openid',
      client_type: 'public', token_endpoint_auth_method: 'none',
    }, admin);
    expect(registered.status).toBe(201);
    const callback = 'http://localhost:3000/test/run-123_a.b~/callback?fixed=1';
    const authorized = await obtainAuthorizationCode('bounded-wildcard', callback, 'admin', 'Password123!', 'openid');
    const target = new URL(authorized.redirectURL);
    expect(target.pathname).toBe('/test/run-123_a.b~/callback');
    expect(target.searchParams.get('fixed')).toBe('1');
    const exchange = await postForm(`${OAUTH_URL}/token`, { grant_type: 'authorization_code', client_id: 'bounded-wildcard',
      code: authorized.code, redirect_uri: callback, code_verifier: verifier });
    expect(exchange.status).toBe(200);
    for (const candidate of [
      'http://localhost:3000/test/a/../../other/callback?fixed=1',
      'http://localhost:3000/test/../callback?fixed=1',
      'http://localhost:3000/test/%2e%2e/callback?fixed=1',
      'http://localhost:3000/test/%252e%252e/callback?fixed=1',
      'http://localhost:3000/test/a%2fb/callback?fixed=1',
      'http://localhost:3000/test/a?next=/callback?fixed=1',
      'http://localhost:3000/test/a#/callback?fixed=1',
      'http://localhost:3000/test/run/callback?fixed=2',
    ]) {
      // Keep the candidate as a query value so the test client cannot normalize
      // dot segments before the authorization server receives them.
      const query = new URLSearchParams({ response_type: 'code', client_id: 'bounded-wildcard', redirect_uri: candidate,
        scope: 'openid', state: 'wildcard-test', code_challenge: challenge, code_challenge_method: 'S256' });
      const response = await getResponse(`${OAUTH_URL}/authorize?${query}`);
      expect(response.status, candidate).toBe(400);
      expect(response.headers.get('location')).toBeNull();
    }
  });

  it('rejects broader patterns on registration and update without changing an existing client', async () => {
    const admin = await getAdminToken();
    const created = await postJSON(`${OAUTH_URL}/register`, {
      client_id: 'wildcard-update', client_name: 'Wildcard update', redirect_uris: [pattern],
    }, admin);
    expect(created.status).toBe(201);
    for (const invalid of [
      'http://localhost:3000/test/pre*suf/callback',
      'http://localhost:3000/test/*/*/callback',
      'http://localhost:3000/callback?next=*',
      'http://localhost:3000/test/../*/callback',
    ]) {
      const registered = await postJSON(`${OAUTH_URL}/register`, {
        client_name: 'Invalid wildcard', redirect_uris: [invalid],
      }, admin);
      expect(registered.status, invalid).toBe(400);
      expect((await registered.json()).error).toBe('invalid_redirect_uri');
      const updated = await putJSON(`${BASE_URL}/admin/api/clients/wildcard-update`, { redirect_uris: [invalid] }, admin);
      expect(updated.status, invalid).toBe(400);
      const current = await getResponse(`${BASE_URL}/admin/api/clients/wildcard-update`, admin);
      expect(current.status).toBe(200);
      expect((await current.json()).redirect_uris).toEqual([pattern]);
    }
  });
});
