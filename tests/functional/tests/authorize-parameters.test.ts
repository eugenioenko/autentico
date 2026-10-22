import { beforeAll, describe, expect, it } from 'vitest';
import {
  BASE_URL, OAUTH_URL, ADMIN_USERNAME, ADMIN_PASSWORD,
  getAdminToken, obtainAuthCodeSession, postForm, postJSON, putJSON,
} from '../helpers';

const CALLBACK = `${BASE_URL}/parameter-callback?registered=kept`;
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const CLIENTS = ['authorize-public', 'authorize-confidential'];
let cookie: string;
let admin: string;
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

async function authorize(clientId: string, method: string, withSession: boolean, challenge: string, transform: string, extra: Record<string, string> = {}) {
  const parameters = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CALLBACK, scope: 'openid',
    state: 'opaque & state', code_challenge: challenge, code_challenge_method: transform, ...extra,
  });
  if (transform === '') parameters.delete('code_challenge_method');
  const headers: Record<string, string> = {};
  if (withSession) headers.Cookie = cookie;
  if (method === 'POST') {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers.Origin = BASE_URL;
  }
  return fetch(`${OAUTH_URL}/authorize${method === 'GET' ? `?${parameters}` : ''}`, {
    method, headers, body: method === 'POST' ? parameters : undefined, redirect: 'manual',
  });
}

describe('Authorize PKCE method validation', () => {
  beforeAll(async () => {
    admin = await getAdminToken();
    for (const [index, clientId] of CLIENTS.entries()) {
      const response = await postJSON(`${OAUTH_URL}/register`, {
        client_id: clientId, client_name: clientId, redirect_uris: [CALLBACK],
        grant_types: ['authorization_code'], response_types: ['code'], scopes: 'openid',
        client_type: index === 0 ? 'public' : 'confidential',
        token_endpoint_auth_method: index === 0 ? 'none' : 'client_secret_basic',
        ...(index === 0 ? {} : { client_secret: 'authorize-parameter-secret' }),
        consent_required: false,
      }, admin);
      expect(response.status).toBe(201);
    }
    cookie = (await obtainAuthCodeSession(ADMIN_USERNAME, ADMIN_PASSWORD)).idpSessionCookie;
    expect(cookie).toBeTruthy();
  });

  for (const method of ['GET', 'POST']) {
    for (const withSession of [false, true]) {
      it.each(['fragment', 'form_post', 'other', 'QUERY'])(`rejects response_mode=%s over ${method}, SSO=${withSession}`, async (mode) => {
        const response = await authorize(CLIENTS[0], method, withSession, CHALLENGE, 'S256', { response_mode: mode });
        expect(response.status).toBe(302);
        const target = new URL(response.headers.get('Location')!);
        expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
        expect(target.searchParams.get('registered')).toBe('kept');
        expect(target.searchParams.get('state')).toBe('opaque & state');
        expect(target.searchParams.get('error')).toBe('invalid_request');
        expect(target.searchParams.has('code')).toBe(false);
        expect(target.hash).toBe('');
      });

      it.each(['query', ''])(`accepts response_mode=%s over ${method}, SSO=${withSession}`, async (mode) => {
        const response = await authorize(CLIENTS[0], method, withSession, CHALLENGE, 'S256', { response_mode: mode });
        if (withSession) {
          expect(response.status).toBe(302);
          const target = new URL(response.headers.get('Location')!);
          expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
          expect(target.searchParams.get('code')).toBeTruthy();
          expect(target.searchParams.get('state')).toBe('opaque & state');
          expect(target.searchParams.has('error')).toBe(false);
          expect(target.hash).toBe('');
        } else if (method === 'POST') {
          expect(response.status).toBe(302);
          const target = new URL(response.headers.get('Location')!, BASE_URL);
          expect(target.origin).toBe(BASE_URL);
          expect(target.pathname).toBe('/oauth2/authorize');
          expect(target.searchParams.has('error')).toBe(false);
          if (mode === 'query') expect(target.searchParams.get('response_mode')).toBe('query');
        } else {
          expect(response.status).toBe(200);
          expect(await response.text()).toContain('name="authorize_sig"');
        }
      });

      it.each(['https://rp.example/request.jwt', 'not-a-uri'])(`rejects request_uri=%s over ${method}, SSO=${withSession}`, async (uri) => {
        const response = await authorize(CLIENTS[0], method, withSession, CHALLENGE, 'S256', { request_uri: uri });
        expect(response.status).toBe(302);
        const target = new URL(response.headers.get('Location')!);
        expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
        expect(target.searchParams.get('registered')).toBe('kept');
        expect(target.searchParams.get('state')).toBe('opaque & state');
        expect(target.searchParams.get('error')).toBe('request_uri_not_supported');
        expect(target.searchParams.has('code')).toBe(false);
      });

      it.each([
        ['empty', { request_uri: '' }], ['absent', {}],
      ] as const)(`accepts %s request_uri over ${method}, SSO=${withSession}`, async (_name, extra) => {
        const response = await authorize(CLIENTS[0], method, withSession, CHALLENGE, 'S256', extra);
        if (withSession) {
          expect(response.status).toBe(302);
          const target = new URL(response.headers.get('Location')!);
          expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
          expect(target.searchParams.get('code')).toBeTruthy();
          expect(target.searchParams.has('error')).toBe(false);
        } else if (method === 'POST') {
          expect(response.status).toBe(302);
          const target = new URL(response.headers.get('Location')!, BASE_URL);
          expect(target.origin).toBe(BASE_URL);
          expect(target.pathname).toBe('/oauth2/authorize');
          expect(target.searchParams.has('error')).toBe(false);
        } else {
          expect(response.status).toBe(200);
          expect(await response.text()).toContain('name="authorize_sig"');
        }
      });

      for (const clientId of CLIENTS) {
        it.each([
          ['unsupported', CHALLENGE, 'S512'],
          ['wrong case', CHALLENGE, 's256'],
          ['method without challenge', '', 'S256'],
          ['plain without challenge', '', 'plain'],
        ])(`rejects %s for ${clientId} ${method} SSO=${withSession}`, async (_name, challenge, transform) => {
          const response = await authorize(clientId, method, withSession, challenge, transform);
          expect(response.status).toBe(302);
          const target = new URL(response.headers.get('Location')!);
          expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
          expect(target.searchParams.get('registered')).toBe('kept');
          expect(target.searchParams.get('state')).toBe('opaque & state');
          expect(target.searchParams.get('error')).toBe('invalid_request');
          expect(target.searchParams.has('code')).toBe(false);
        });
      }
    }

    it.each([false, true])(`rejects an omitted method when S256 is enforced over ${method}, SSO=%s`, async (withSession) => {
      const response = await authorize(CLIENTS[0], method, withSession, VERIFIER, '');
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get('Location')!);
      expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
      expect(target.searchParams.get('error')).toBe('invalid_request');
      expect(target.searchParams.has('code')).toBe(false);
    });

    it.each([false, true])(`round-trips omitted plain with an explicit policy opt-in over ${method}, SSO=%s`, async (withSession) => {
      expect((await putJSON(`${BASE_URL}/admin/api/settings`, { pkce_enforce_s256: 'false' }, admin)).status).toBe(204);
      try {
        const discovery = await (await fetch(`${BASE_URL}/.well-known/openid-configuration`)).json();
        expect(discovery.code_challenge_methods_supported).toEqual(['S256', 'plain']);
        let response = await authorize(CLIENTS[0], method, withSession, VERIFIER, '');
        if (!withSession) {
          if (method === 'POST') {
            expect(response.status).toBe(302);
            const target = new URL(response.headers.get('Location')!, BASE_URL);
            expect(target.origin).toBe(BASE_URL);
            expect(target.searchParams.get('code_challenge_method')).toBe('plain');
            response = await fetch(target, { redirect: 'manual' });
          }
          expect(response.status).toBe(200);
          const html = await response.text();
          const csrf = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/)?.[1];
          const signature = html.match(/name="authorize_sig"\s+value="([^"]+)"/)?.[1];
          const transform = html.match(/name="code_challenge_method"\s+value="([^"]+)"/)?.[1];
          expect(csrf).toBeTruthy();
          expect(signature).toBeTruthy();
          expect(transform).toBe('plain');
          const csrfCookie = response.headers.getSetCookie().find((value) => value.startsWith('_gorilla_csrf='));
          expect(csrfCookie).toBeTruthy();
          response = await fetch(`${OAUTH_URL}/login`, {
            method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded',
              Origin: BASE_URL, Cookie: csrfCookie!.split(';')[0] },
            body: new URLSearchParams({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD,
              'gorilla.csrf.Token': csrf!, authorize_sig: signature!, client_id: CLIENTS[0], redirect_uri: CALLBACK,
              scope: 'openid', state: 'opaque & state', code_challenge: VERIFIER, code_challenge_method: transform! }),
          });
        }
        expect(response.status).toBe(302);
        const target = new URL(response.headers.get('Location')!);
        expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
        expect(target.searchParams.get('state')).toBe('opaque & state');
        const code = target.searchParams.get('code');
        expect(code).toBeTruthy();
        const grant = { grant_type: 'authorization_code', client_id: CLIENTS[0], redirect_uri: CALLBACK, code: code! };
        const rejected = await postForm(`${OAUTH_URL}/token`, { ...grant, code_verifier: CHALLENGE });
        expect(rejected.status).toBe(400);
        expect((await rejected.json()).error).toBe('invalid_grant');
        const accepted = await postForm(`${OAUTH_URL}/token`, { ...grant, code_verifier: VERIFIER });
        expect(accepted.status).toBe(200);
        expect((await accepted.json()).access_token).toBeTruthy();
      } finally {
        expect((await putJSON(`${BASE_URL}/admin/api/settings`, { pkce_enforce_s256: 'true' }, admin)).status).toBe(204);
      }
      const discovery = await (await fetch(`${BASE_URL}/.well-known/openid-configuration`)).json();
      expect(discovery.code_challenge_methods_supported).toEqual(['S256']);
    });

    it(`continues valid S256 through SSO over ${method}`, async () => {
      const response = await authorize(CLIENTS[0], method, true, CHALLENGE, 'S256');
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get('Location')!);
      expect(target.origin + target.pathname).toBe(`${BASE_URL}/parameter-callback`);
      expect(target.searchParams.get('code')).toBeTruthy();
      expect(target.searchParams.get('state')).toBe('opaque & state');
      expect(target.searchParams.has('error')).toBe(false);
    });

    it(`permits a confidential client without PKCE over ${method}`, async () => {
      const response = await authorize(CLIENTS[1], method, true, '', '');
      expect(response.status).toBe(302);
      const target = new URL(response.headers.get('Location')!);
      expect(target.searchParams.get('code')).toBeTruthy();
      expect(target.searchParams.has('error')).toBe(false);
    });
  }
});
