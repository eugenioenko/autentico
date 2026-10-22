import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postForm, postJSON, putJSON } from '../helpers';

const CLIENT = 'consent-freshness';
const CALLBACK = `${BASE_URL}/consent-test/callback`;
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
let admin: string;
let username: string;
let counter = 0;

function decode(value: string): string {
  return value.replaceAll('&amp;', '&').replaceAll('&quot;', '"')
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));
}

function formFields(html: string): URLSearchParams {
  const fields = new URLSearchParams();
  for (const match of html.matchAll(/name="([^"]+)"[^>]*value="([^"]*)"/g)) fields.set(match[1], decode(match[2]));
  return fields;
}

function authorize(overrides: Record<string, string> = {}): string {
  const query = new URLSearchParams({ response_type: 'code', client_id: CLIENT, redirect_uri: CALLBACK,
    scope: 'openid', state: 'opaque & state', nonce: 'consent-auth-time',
    code_challenge: CHALLENGE, code_challenge_method: 'S256', prompt: 'consent', ...overrides });
  return `${OAUTH_URL}/authorize?${query}`;
}

// A browser cookie jar restricted to this server; redirect callbacks are never followed.
class Browser {
  cookies = new Map<string, string>();
  async request(url: string, form?: URLSearchParams): Promise<Response> {
    const target = new URL(url, BASE_URL);
    expect(target.origin).toBe(BASE_URL);
    const headers: Record<string, string> = { Cookie: [...this.cookies].map(([key, value]) => `${key}=${value}`).join('; ') };
    if (form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; headers.Origin = BASE_URL; }
    const response = await fetch(target, { method: form ? 'POST' : 'GET', headers, body: form, redirect: 'manual' });
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0], index = pair.indexOf('=');
      const key = pair.slice(0, index), value = pair.slice(index + 1);
      if (value === '' || /max-age=0/i.test(cookie)) this.cookies.delete(key);
      else this.cookies.set(key, value);
    }
    return response;
  }
}

async function settings(values: Record<string, string>) {
  expect((await putJSON(`${BASE_URL}/admin/api/settings`, values, admin)).status).toBe(204);
}

async function clientPolicy(values: Record<string, unknown>) {
  expect((await putJSON(`${BASE_URL}/admin/api/clients/${CLIENT}`, values, admin)).status).toBe(200);
}

async function login(browser = new Browser(), overrides: Record<string, string> = {}) {
  const page = await browser.request(authorize(overrides));
  expect(page.status).toBe(200);
  const fields = formFields(await page.text());
  fields.set('username', username); fields.set('password', 'Password123!');
  const earliest = Math.floor(Date.now()/1000);
  const response = await browser.request(`${OAUTH_URL}/login`, fields);
  const latest = Math.floor(Date.now()/1000);
  expect(response.status).toBe(302);
  const location = response.headers.get('Location')!;
  expect(new URL(location, BASE_URL).pathname).toBe('/oauth2/consent');
  return { browser, location, earliest, latest };
}

async function consentPage(browser: Browser, location: string) {
  const response = await browser.request(location);
  expect(response.status).toBe(200);
  const fields = formFields(await response.text());
  expect(fields.get('consent_flow')).toBeTruthy();
  fields.set('action', 'allow');
  return fields;
}

async function exchange(response: Response) {
  expect(response.status).toBe(302);
  const callback = new URL(response.headers.get('Location')!);
  const token = await postForm(`${OAUTH_URL}/token`, { grant_type: 'authorization_code', client_id: CLIENT,
    redirect_uri: CALLBACK, code: callback.searchParams.get('code')!, code_verifier: VERIFIER });
  expect(token.status).toBe(200);
  return token.json();
}

function claims(raw: string) { return JSON.parse(Buffer.from(raw.split('.')[1], 'base64url').toString()); }
const wait = (milliseconds: number) => new Promise(resolve => setTimeout(resolve, milliseconds));

describe('consent request and authentication freshness', () => {
  beforeAll(async () => {
    admin = await getAdminToken();
    const response = await postJSON(`${BASE_URL}/admin/api/clients`, { client_id: CLIENT, client_name: 'Consent freshness',
      client_type: 'public', token_endpoint_auth_method: 'none', redirect_uris: [CALLBACK],
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], scopes: 'openid profile email', consent_required: true }, admin);
    expect(response.status).toBe(201);
  });

  beforeEach(async () => {
    username = `consent-user-${++counter}`;
    expect((await postJSON(`${BASE_URL}/admin/api/users`, { username, password: 'Password123!', email: `${username}@example.com` }, admin)).status).toBe(201);
    await settings({ sso_enabled: 'true', sso_session_idle_timeout: '1h', sso_session_max_age: '0', require_mfa: 'false', require_email_verification: 'false' });
    await clientPolicy({ is_active: true, consent_required: true, scopes: 'openid profile email', sso_session_idle_timeout: '1h' });
  });

  it('keeps real authentication time through delayed consent, exchange and repeated refresh', async () => {
    const { browser, location, earliest, latest } = await login();
    const fields = await consentPage(browser, location);
    await wait(2100);
    let token = await exchange(await browser.request(`${OAUTH_URL}/consent`, fields));
    const original = claims(token.id_token).auth_time;
    expect(original).toBeGreaterThanOrEqual(earliest);
    expect(original).toBeLessThanOrEqual(latest);
    for (let rotation = 0; rotation < 3; rotation++) {
      expect(claims(token.access_token).auth_time).toBe(original);
      expect(claims(token.id_token).auth_time).toBe(original);
      expect(claims(token.id_token).iat).toBeGreaterThan(original);
      await wait(1100);
      const refreshed = await postForm(`${OAUTH_URL}/token`, { grant_type: 'refresh_token', client_id: CLIENT, refresh_token: token.refresh_token });
      expect(refreshed.status).toBe(200);
      token = await refreshed.json();
    }
  });

  it('does not sign arbitrary GET requests even with an authenticated cookie', async () => {
    const { browser, location } = await login();
    for (const [key, value, status] of [
      ['scope', 'openid forbidden', 400], ['code_challenge', '', 400],
      ['redirect_uri', 'https://attacker.example/callback', 400], ['consent_flow', '', 401],
      ['state', 'changed state', 401], ['max_age', '0', 401],
    ] as const) {
      const request = new URL(location, BASE_URL); request.searchParams.set(key, value);
      const rejected = await browser.request(request.toString());
      expect(rejected.status).toBe(status);
      expect(await rejected.text()).not.toContain('name="consent_sig"');
    }
    await consentPage(browser, location);
  });

  it('checks changed client scope policy again at approval', async () => {
    const { browser, location } = await login();
    const fields = await consentPage(browser, location);
    await clientPolicy({ scopes: 'profile' });
    const response = await browser.request(`${OAUTH_URL}/consent`, fields);
    expect(response.status).toBe(400);
    expect(response.headers.get('Location')).toBeNull();
  });

  it('rejects approval after the per-client idle deadline and returns login_required silently', async () => {
    const { browser, location } = await login();
    const fields = await consentPage(browser, location);
    await clientPolicy({ sso_session_idle_timeout: '1s' });
    await wait(1200);
    expect((await browser.request(`${OAUTH_URL}/consent`, fields)).status).toBe(401);
    const silent = await browser.request(authorize({ prompt: 'none' }));
    expect(silent.status).toBe(302);
    expect(new URL(silent.headers.get('Location')!).searchParams.get('error')).toBe('login_required');
  });

  it('allows fresh login with SSO disabled but rejects an SSO continuation after disabling it', async () => {
    await settings({ sso_enabled: 'false' });
    const { browser, location } = await login();
    await exchange(await browser.request(`${OAUTH_URL}/consent`, await consentPage(browser, location)));
    await settings({ sso_enabled: 'true' });
    const sso = await browser.request(authorize());
    expect(sso.status).toBe(302);
    const ssoLocation = sso.headers.get('Location')!;
    expect(new URL(ssoLocation, BASE_URL).pathname).toBe('/oauth2/consent');
    await settings({ sso_enabled: 'false' });
    expect((await browser.request(ssoLocation)).status).toBe(401);
  });

  it('requires active login for max_age=0 and prevents removing the signed control', async () => {
    const { browser } = await login();
    const page = await browser.request(authorize({ max_age: '0' }));
    expect(page.status).toBe(200);
    const fields = formFields(await page.text());
    expect(fields.get('max_age')).toBe('0');
    fields.set('username', username); fields.set('password', 'Password123!');
    const tampered = new URLSearchParams(fields); tampered.delete('max_age');
    expect((await browser.request(`${OAUTH_URL}/login`, tampered)).status).toBe(400);
    const active = await browser.request(`${OAUTH_URL}/login`, fields);
    expect(active.status).toBe(302);
    const consent = await consentPage(browser, active.headers.get('Location')!);
    await wait(150);
    await exchange(await browser.request(`${OAUTH_URL}/consent`, consent));
  });

  it('rejects malformed authentication controls before silent authorization', async () => {
    const { browser } = await login();
    for (const controls of [{ max_age: '-1' }, { max_age: 'huge' }, { prompt: 'none consent' }]) {
      const response = await browser.request(authorize(controls));
      expect(response.status).toBe(302);
      expect(new URL(response.headers.get('Location')!).searchParams.get('error')).toBe('invalid_request');
    }
  });

  it('reports consent_required without opening a screen for prompt=none', async () => {
    const { browser } = await login();
    const silent = await browser.request(authorize({ prompt: 'none' }));
    expect(silent.status).toBe(302);
    const callback = new URL(silent.headers.get('Location')!);
    expect(callback.origin + callback.pathname).toBe(CALLBACK);
    expect(callback.searchParams.get('error')).toBe('consent_required');
    expect(callback.searchParams.get('code')).toBeNull();
  });
});
