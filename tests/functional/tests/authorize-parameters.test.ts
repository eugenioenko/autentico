import { beforeAll, describe, expect, it } from 'vitest';
import {
  BASE_URL, OAUTH_URL, ADMIN_USERNAME, ADMIN_PASSWORD,
  getAdminToken, obtainAuthCodeSession, postJSON,
} from '../helpers';

const CALLBACK = `${BASE_URL}/parameter-callback?registered=kept`;
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const CLIENTS = ['authorize-public', 'authorize-confidential'];
let cookie: string;

async function authorize(clientId: string, method: string, withSession: boolean, challenge: string, transform: string) {
  const parameters = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: CALLBACK, scope: 'openid',
    state: 'opaque & state', code_challenge: challenge, code_challenge_method: transform,
  });
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
    const admin = await getAdminToken();
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
