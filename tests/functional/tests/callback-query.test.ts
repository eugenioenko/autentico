import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, putJSON, postForm, obtainAuthorizationCode } from '../helpers';

const callback = 'http://localhost:3000/callback?existing=a%26b&repeat=1&repeat=2';
const state = 'state & injected=1 + %25 # é';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

function assertQuery(location: string): URL {
  const target = new URL(location);
  expect(target.origin + target.pathname).toBe('http://localhost:3000/callback');
  expect(target.hash).toBe('');
  expect(target.searchParams.getAll('existing')).toEqual(['a&b']);
  expect(target.searchParams.getAll('repeat')).toEqual(['1', '2']);
  expect(target.searchParams.getAll('state')).toEqual([state]);
  expect(target.searchParams.has('injected')).toBe(false);
  return target;
}

function decodeAttribute(value: string): string {
  return value.replace(/&#(x[0-9a-f]+|[0-9]+);/gi, (_, number: string) =>
    String.fromCodePoint(number.toLowerCase().startsWith('x') ? parseInt(number.slice(1), 16) : parseInt(number, 10)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

describe('Authorization callbacks preserve existing query values', () => {
  it('covers password login, SSO, authorization errors and both consent outcomes', async () => {
    const admin = await getAdminToken();
    for (const consent of [false, true]) {
      const response = await postJSON(`${OAUTH_URL}/register`, {
        client_id: consent ? 'query-consent' : 'query-login', client_name: `Query ${consent}`,
        redirect_uris: [callback], grant_types: ['authorization_code'], response_types: ['code'],
        scopes: 'openid', client_type: 'public', token_endpoint_auth_method: 'none', consent_required: consent,
      }, admin);
      expect(response.status).toBe(201);
    }
    const login = await obtainAuthorizationCode('query-login', callback, 'admin', 'Password123!', 'openid', state);
    expect(assertQuery(login.redirectURL).searchParams.get('code')).toBe(login.code);
    const exchange = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'authorization_code', client_id: 'query-login', code: login.code,
      redirect_uri: callback, code_verifier: verifier,
    });
    expect(exchange.status).toBe(200);

    function authorize(client: string): URL {
      const target = new URL(`${OAUTH_URL}/authorize`);
      target.search = new URLSearchParams({ response_type: 'code', client_id: client, redirect_uri: callback,
        scope: 'openid', state, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
      return target;
    }
    for (const hasSession of [false, true]) {
      const request = authorize('query-login');
      request.searchParams.set('prompt', 'none');
      const response = await fetch(request, {
        headers: hasSession ? { Cookie: login.idpSessionCookie } : {}, redirect: 'manual',
      });
      expect(response.status).toBe(302);
      const target = assertQuery(response.headers.get('location')!);
      if (hasSession) expect(target.searchParams.get('code')).toBeTruthy();
      else expect(target.searchParams.get('error')).toBe('login_required');
    }
    for (const action of ['deny', 'allow']) {
      const request = authorize('query-consent');
      request.searchParams.set('prompt', 'consent');
      const response = await fetch(request, { headers: { Cookie: login.idpSessionCookie }, redirect: 'manual' });
      expect(response.status).toBe(302);
      const consentURL = new URL(response.headers.get('location')!, BASE_URL);
      expect(consentURL.pathname).toBe('/oauth2/consent');
      const page = await fetch(consentURL, { headers: { Cookie: login.idpSessionCookie }, redirect: 'manual' });
      expect(page.status).toBe(200);
      const html = await page.text();
      const form = new URLSearchParams();
      for (const match of html.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)) {
        form.set(match[1], decodeAttribute(match[2]));
      }
      expect(form.get('consent_sig')).toBeTruthy();
      expect(form.get('gorilla.csrf.Token')).toBeTruthy();
      const csrf = page.headers.getSetCookie().find(cookie => cookie.startsWith('_gorilla_csrf='));
      expect(csrf).toBeTruthy();
      form.set('action', action);
      const completed = await fetch(`${OAUTH_URL}/consent`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: BASE_URL,
          Cookie: `${login.idpSessionCookie}; ${csrf!.split(';')[0]}` }, body: form, redirect: 'manual',
      });
      expect(completed.status).toBe(302);
      const target = assertQuery(completed.headers.get('location')!);
      if (action === 'deny') {
        expect(target.searchParams.get('error')).toBe('access_denied');
        expect(target.searchParams.has('code')).toBe(false);
      } else {
        const exchange = await postForm(`${OAUTH_URL}/token`, {
          grant_type: 'authorization_code', client_id: 'query-consent', code: target.searchParams.get('code')!,
          redirect_uri: callback, code_verifier: verifier,
        });
        expect(exchange.status).toBe(200);
      }
    }
  });
});

describe('Consent uses current registration policy', () => {
  it('rejects signed pages after scopes, code grants or public-client PKCE requirements change', async () => {
    const admin = await getAdminToken();
    const bootstrap = await postJSON(`${OAUTH_URL}/register`, {
      client_id: 'consent-policy-login', client_name: 'Policy login', redirect_uris: [callback],
      grant_types: ['authorization_code'], response_types: ['code'], scopes: 'openid',
      client_type: 'public', token_endpoint_auth_method: 'none',
    }, admin);
    expect(bootstrap.status).toBe(201);
    const login = await obtainAuthorizationCode('consent-policy-login', callback, 'admin', 'Password123!', 'openid');
    for (const mutation of ['scopes', 'grant', 'pkce-policy']) {
      const clientId = `consent-policy-${mutation}`;
      const registered = await postJSON(`${OAUTH_URL}/register`, {
        client_id: clientId, client_name: clientId, redirect_uris: [callback],
        grant_types: ['authorization_code'], response_types: ['code'], scopes: 'openid profile',
        client_type: 'public', token_endpoint_auth_method: 'none', consent_required: true,
      }, admin);
      expect(registered.status).toBe(201);
      const query = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: callback, scope: 'openid' });
      query.set('code_challenge', mutation === 'pkce-policy' ? verifier : challenge);
      query.set('code_challenge_method', mutation === 'pkce-policy' ? 'plain' : 'S256');
      if (mutation === 'pkce-policy') expect((await putJSON(`${BASE_URL}/admin/api/settings`, { pkce_enforce_s256: 'false' }, admin)).status).toBe(204);
      const authorized = await fetch(`${OAUTH_URL}/authorize?${query}`, { headers: { Cookie: login.idpSessionCookie }, redirect: 'manual' });
      expect(authorized.status).toBe(302);
      const consentURL = new URL(authorized.headers.get('location')!, BASE_URL);
      expect(consentURL.pathname).toBe('/oauth2/consent');
      const page = await fetch(consentURL, { headers: { Cookie: login.idpSessionCookie }, redirect: 'manual' });
      expect(page.status).toBe(200);
      const form = new URLSearchParams();
      for (const match of (await page.text()).matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)) form.set(match[1], decodeAttribute(match[2]));
      expect(form.get('consent_sig')).toBeTruthy();
      const csrf = page.headers.getSetCookie().find(cookie => cookie.startsWith('_gorilla_csrf='));
      expect(csrf).toBeTruthy(); form.set('action', 'allow');
      if (mutation === 'pkce-policy') {
        expect((await putJSON(`${BASE_URL}/admin/api/settings`, { pkce_enforce_s256: 'true' }, admin)).status).toBe(204);
      } else {
        const changes = mutation === 'scopes' ? { scopes: 'profile' } : { grant_types: ['refresh_token'] };
        const updated = await putJSON(`${BASE_URL}/admin/api/clients/${clientId}`, { ...changes, consent_required: true }, admin);
        expect(updated.status).toBe(200);
      }
      const completed = await fetch(`${OAUTH_URL}/consent`, { method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: BASE_URL,
          Cookie: `${login.idpSessionCookie}; ${csrf!.split(';')[0]}` }, body: form, redirect: 'manual',
      });
      expect(completed.status, mutation).toBe(400);
      expect(completed.headers.get('location')).toBeNull();
      expect((await completed.json()).error).toBe('invalid_request');
    }
  });
});
