import { describe, it, expect } from 'vitest';
import {
  BASE_URL,
  OAUTH_URL,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  ADMIN_CLIENT_ID,
  ADMIN_REDIRECT_URI,
  postForm,
} from '../helpers';

const TEST_CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const TEST_CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('Authorization Code Flow', () => {
  it('completes full flow: authorize → login → token exchange → userinfo', async () => {
    const state = 'test-state-abc';

    // Step 1: GET /authorize → 302 redirect to /login?auth_request_id=xxx
    const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
    authorizeURL.searchParams.set('response_type', 'code');
    authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
    authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
    authorizeURL.searchParams.set('scope', 'openid profile email');
    authorizeURL.searchParams.set('state', state);
    authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
    authorizeURL.searchParams.set('code_challenge_method', 'S256');

    const authorizeResp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
    expect(authorizeResp.status).toBe(302);

    const loginRedirect = authorizeResp.headers.get('Location');
    expect(loginRedirect).toBeTruthy();
    expect(loginRedirect).toContain('auth_request_id=');

    // Extract auth_request_id
    const loginRedirectURL = new URL(loginRedirect!, BASE_URL);
    const authRequestId = loginRedirectURL.searchParams.get('auth_request_id');
    expect(authRequestId).toBeTruthy();

    // Step 2: GET /login?auth_request_id=xxx — get login page with CSRF token
    const loginPageResp = await fetch(`${BASE_URL}${loginRedirect}`, { redirect: 'manual' });
    expect(loginPageResp.status).toBe(200);

    const html = await loginPageResp.text();
    expect(html).toContain('<form');

    const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
    expect(csrfMatch).toBeTruthy();
    const csrfToken = csrfMatch![1];

    const cookies = loginPageResp.headers.getSetCookie();
    const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));
    expect(csrfCookie).toBeTruthy();

    // Step 3: POST /login — submit credentials with auth_request_id
    const loginResp = await fetch(`${OAUTH_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: csrfCookie!.split(';')[0],
        Origin: BASE_URL,
      },
      body: new URLSearchParams({
        username: ADMIN_USERNAME,
        password: ADMIN_PASSWORD,
        'gorilla.csrf.Token': csrfToken,
        auth_request_id: authRequestId!,
      }),
      redirect: 'manual',
    });

    expect(loginResp.status).toBe(302);
    const location = loginResp.headers.get('Location');
    expect(location).toBeTruthy();

    const redirectURL = new URL(location!);
    const code = redirectURL.searchParams.get('code');
    const returnedState = redirectURL.searchParams.get('state');

    expect(code).toBeTruthy();
    expect(returnedState).toBe(state);

    // Step 4: POST /token — exchange code for tokens
    const tokenResp = await postForm(`${OAUTH_URL}/token`, {
      grant_type: 'authorization_code',
      code: code!,
      redirect_uri: ADMIN_REDIRECT_URI,
      client_id: ADMIN_CLIENT_ID,
      code_verifier: TEST_CODE_VERIFIER,
    });
    expect(tokenResp.ok).toBe(true);

    const tokens = await tokenResp.json();
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.token_type).toBe('Bearer');

    // Step 5: GET /userinfo — verify token works
    const userinfoResp = await fetch(`${OAUTH_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfoResp.ok).toBe(true);

    const claims = await userinfoResp.json();
    expect(claims.sub).toBeTruthy();
    expect(claims.preferred_username).toBe(ADMIN_USERNAME);
  });

  it('rejects public client authorize request without code_challenge', async () => {
    const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
    authorizeURL.searchParams.set('response_type', 'code');
    authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
    authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
    authorizeURL.searchParams.set('scope', 'openid');
    authorizeURL.searchParams.set('state', 'no-pkce-state');
    // No code_challenge — should be rejected for public clients

    const resp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
    expect(resp.status).toBe(302);

    const location = resp.headers.get('Location');
    expect(location).toBeTruthy();
    expect(location).toContain('error=invalid_request');
    expect(location).toContain('code_challenge');
  });
});
