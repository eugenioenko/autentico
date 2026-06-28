import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  BASE_URL,
  OAUTH_URL,
  ADMIN_CLIENT_ID,
  ADMIN_REDIRECT_URI,
  getAdminToken,
  putJSON,
} from '../helpers';

const SETTINGS_API = `${BASE_URL}/admin/api/settings`;

async function enableMagicLink(token: string) {
  const resp = await putJSON(SETTINGS_API, {
    magic_link_enabled: 'true',
    smtp_host: 'localhost',
    smtp_port: '2525',
    smtp_from: 'test@test.com',
  }, token);
  expect(resp.status).toBe(204);
}

async function disableMagicLink(token: string) {
  const resp = await putJSON(SETTINGS_API, {
    magic_link_enabled: 'false',
    smtp_host: '',
    smtp_from: '',
  }, token);
  expect(resp.status).toBe(204);
}

function magicLinkURL(extra?: Record<string, string>) {
  const params = new URLSearchParams({
    client_id: ADMIN_CLIENT_ID,
    redirect_uri: ADMIN_REDIRECT_URI,
    state: 'ml-test-state',
    scope: 'openid profile email',
    ...extra,
  });
  return `${OAUTH_URL}/magic-link?${params}`;
}

function authorizeURL() {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: ADMIN_CLIENT_ID,
    redirect_uri: ADMIN_REDIRECT_URI,
    scope: 'openid profile email',
    state: 'ml-test-state',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
  });
  return `${OAUTH_URL}/authorize?${params}`;
}

describe('Magic Link — disabled by default', () => {
  it('GET /magic-link returns 404 when disabled', async () => {
    const resp = await fetch(magicLinkURL(), { redirect: 'manual' });
    expect(resp.status).toBe(404);
    const body = await resp.text();
    expect(body).toContain('not enabled');
  });

  it('GET /magic-link/verify returns 404 when disabled', async () => {
    const resp = await fetch(`${OAUTH_URL}/magic-link/verify?token=test`, { redirect: 'manual' });
    expect(resp.status).toBe(404);
    const body = await resp.text();
    expect(body).toContain('not enabled');
  });

  it('login page does NOT show magic link button when disabled', async () => {
    const resp = await fetch(authorizeURL(), { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).not.toContain('使用邮箱链接登录');
  });
});

describe('Magic Link — enabled', () => {
  let adminToken: string;

  beforeAll(async () => {
    adminToken = await getAdminToken();
    await enableMagicLink(adminToken);
  });

  afterAll(async () => {
    await disableMagicLink(adminToken);
  });

  it('GET /magic-link renders the email form', async () => {
    const resp = await fetch(magicLinkURL(), { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('Send sign-in link');
    expect(body).toContain('name="email"');
  });

  it('login page shows magic link button when enabled', async () => {
    const resp = await fetch(authorizeURL(), { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('使用邮箱链接登录');
  });

  it('POST /magic-link with empty email shows validation error', async () => {
    // First GET the form to extract CSRF token + cookie
    const getResp = await fetch(magicLinkURL(), { redirect: 'manual' });
    const html = await getResp.text();
    const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
    expect(csrfMatch).toBeTruthy();
    const csrfToken = csrfMatch![1];

    const sigMatch = html.match(/name="authorize_sig"\s+value="([^"]*)"/);
    const authorizeSig = sigMatch ? sigMatch[1] : '';

    const cookies = getResp.headers.getSetCookie();
    const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));
    expect(csrfCookie).toBeTruthy();

    const resp = await fetch(`${OAUTH_URL}/magic-link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: csrfCookie!.split(';')[0],
        Origin: BASE_URL,
      },
      body: new URLSearchParams({
        email: '',
        'gorilla.csrf.Token': csrfToken,
        authorize_sig: authorizeSig,
        client_id: ADMIN_CLIENT_ID,
        redirect_uri: ADMIN_REDIRECT_URI,
        state: 'ml-test-state',
        scope: 'openid profile email',
      }),
      redirect: 'manual',
    });

    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('Please enter');
  });

  it('POST /magic-link with nonexistent email shows sent (no enumeration)', async () => {
    const getResp = await fetch(magicLinkURL(), { redirect: 'manual' });
    const html = await getResp.text();
    const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
    const csrfToken = csrfMatch![1];
    const sigMatch = html.match(/name="authorize_sig"\s+value="([^"]*)"/);
    const authorizeSig = sigMatch ? sigMatch[1] : '';
    const cookies = getResp.headers.getSetCookie();
    const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));

    const resp = await fetch(`${OAUTH_URL}/magic-link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: csrfCookie!.split(';')[0],
        Origin: BASE_URL,
      },
      body: new URLSearchParams({
        email: 'nobody@nonexistent.com',
        'gorilla.csrf.Token': csrfToken,
        authorize_sig: authorizeSig,
        client_id: ADMIN_CLIENT_ID,
        redirect_uri: ADMIN_REDIRECT_URI,
        state: 'ml-test-state',
        scope: 'openid profile email',
      }),
      redirect: 'manual',
    });

    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('sent');
    expect(body).not.toContain('not found');
  });

  it('GET /magic-link/verify with missing token shows expired page', async () => {
    const resp = await fetch(`${OAUTH_URL}/magic-link/verify?client_id=${ADMIN_CLIENT_ID}`, { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('Invalid or missing');
  });

  it('GET /magic-link/verify with invalid token shows expired page', async () => {
    const params = new URLSearchParams({
      token: 'completely-invalid-token',
      client_id: ADMIN_CLIENT_ID,
      redirect_uri: ADMIN_REDIRECT_URI,
      state: 'ml-test-state',
      scope: 'openid profile email',
    });
    const resp = await fetch(`${OAUTH_URL}/magic-link/verify?${params}`, { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('invalid or has already been used');
  });

  it('POST /magic-link with tampered signature is rejected', async () => {
    const getResp = await fetch(magicLinkURL(), { redirect: 'manual' });
    const html = await getResp.text();
    const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
    const csrfToken = csrfMatch![1];
    const cookies = getResp.headers.getSetCookie();
    const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));

    const resp = await fetch(`${OAUTH_URL}/magic-link`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: csrfCookie!.split(';')[0],
        Origin: BASE_URL,
      },
      body: new URLSearchParams({
        email: 'test@test.com',
        'gorilla.csrf.Token': csrfToken,
        authorize_sig: 'tampered-signature-value',
        client_id: ADMIN_CLIENT_ID,
        redirect_uri: ADMIN_REDIRECT_URI,
        state: 'ml-test-state',
        scope: 'openid profile email',
      }),
      redirect: 'manual',
    });

    expect(resp.status).toBe(400);
    const body = await resp.text();
    expect(body).toContain('tampered');
  });
});

describe('Magic Link — admin settings', () => {
  it('can toggle magic_link_enabled via settings API', async () => {
    const token = await getAdminToken();

    // Enable (with SMTP so the endpoint is fully functional)
    let resp = await putJSON(SETTINGS_API, {
      magic_link_enabled: 'true',
      smtp_host: 'localhost',
      smtp_port: '2525',
      smtp_from: 'test@test.com',
    }, token);
    expect(resp.status).toBe(204);

    // Verify enabled
    resp = await fetch(magicLinkURL(), { redirect: 'manual' });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain('Send sign-in link');

    // Disable and clear SMTP
    resp = await putJSON(SETTINGS_API, {
      magic_link_enabled: 'false',
      smtp_host: '',
      smtp_from: '',
    }, token);
    expect(resp.status).toBe(204);

    // Verify disabled
    resp = await fetch(magicLinkURL(), { redirect: 'manual' });
    expect(resp.status).toBe(404);
  });

  it('can update magic_link_expiration', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(SETTINGS_API, { magic_link_expiration: '30m' }, token);
    expect(resp.status).toBe(204);

    // Reset
    await putJSON(SETTINGS_API, { magic_link_expiration: '15m' }, token);
  });

  it('rejects invalid magic_link_expiration', async () => {
    const token = await getAdminToken();
    const resp = await putJSON(SETTINGS_API, { magic_link_expiration: 'not-a-duration' }, token);
    expect(resp.status).toBe(400);
  });
});
