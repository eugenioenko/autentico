const PORT = 19999;
export const BASE_URL = `http://localhost:${PORT}`;
export const OAUTH_URL = `${BASE_URL}/oauth2`;
export const ADMIN_USERNAME = 'admin';
export const ADMIN_PASSWORD = 'Password123!';
export const ADMIN_EMAIL = 'admin@test.com';
export const ADMIN_CLIENT_ID = 'autentico-admin';
export const ADMIN_REDIRECT_URI = `http://localhost:${PORT}/admin/callback`;

// RFC 7636 Appendix B test vectors for PKCE
const TEST_CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const TEST_CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

let cachedAdminToken: string | null = null;
// Client with ROPC enabled, created on first use
let ropcClientID: string | null = null;

export async function postForm(url: string, data: Record<string, string>, bearer?: string): Promise<Response> {
  const body = new URLSearchParams(data);
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  return fetch(url, {
    method: 'POST',
    headers,
    body,
    redirect: 'manual',
  });
}

export async function postFormBasic(url: string, data: Record<string, string>, clientId: string, clientSecret: string): Promise<Response> {
  const body = new URLSearchParams(data);
  const credentials = btoa(`${clientId}:${clientSecret}`);
  return fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Basic ${credentials}`,
    },
    body,
    redirect: 'manual',
  });
}

export async function postJSON(url: string, body: unknown, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  return fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

export async function putJSON(url: string, body: unknown, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  return fetch(url, {
    method: 'PUT',
    headers,
    body: JSON.stringify(body),
  });
}

export async function deleteRequest(url: string, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  return fetch(url, { method: 'DELETE', headers });
}

export async function getResponse(url: string, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = {};
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  return fetch(url, { headers, redirect: 'manual' });
}

export async function getJSON<T = unknown>(url: string, bearer?: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;
  const resp = await fetch(url, { headers });
  return resp.json() as Promise<T>;
}

/**
 * Performs the full authorization code flow to obtain tokens.
 * This works with the autentico-admin public client which only supports auth_code + refresh.
 */
export async function obtainTokenViaAuthCode(
  username: string,
  password: string,
  scope = 'openid profile email'
): Promise<{ access_token: string; refresh_token: string; id_token: string; token_type: string }> {
  // Step 1: GET /authorize → 302 redirect to /login?auth_request_id=xxx
  const authorizeURL = new URL(`${OAUTH_URL}/authorize`);
  authorizeURL.searchParams.set('response_type', 'code');
  authorizeURL.searchParams.set('client_id', ADMIN_CLIENT_ID);
  authorizeURL.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
  authorizeURL.searchParams.set('scope', scope);
  authorizeURL.searchParams.set('state', 'helper-state');
  authorizeURL.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
  authorizeURL.searchParams.set('code_challenge_method', 'S256');

  const authorizeResp = await fetch(authorizeURL.toString(), { redirect: 'manual' });
  if (authorizeResp.status !== 302) {
    throw new Error(`Authorize returned ${authorizeResp.status}, expected 302`);
  }

  const loginRedirect = authorizeResp.headers.get('Location');
  if (!loginRedirect) throw new Error('Authorize did not return Location header');

  // Extract auth_request_id from redirect URL
  const loginRedirectURL = new URL(loginRedirect, BASE_URL);
  const authRequestId = loginRedirectURL.searchParams.get('auth_request_id');
  if (!authRequestId) throw new Error('No auth_request_id in authorize redirect');

  // Step 2: GET /login?auth_request_id=xxx — get login page with CSRF token
  const loginPageResp = await fetch(`${BASE_URL}${loginRedirect}`, { redirect: 'manual' });
  if (loginPageResp.status !== 200) {
    throw new Error(`Login page returned ${loginPageResp.status}`);
  }

  const html = await loginPageResp.text();
  const csrfMatch = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
  if (!csrfMatch) throw new Error('Could not extract CSRF token from login page');
  const csrfToken = csrfMatch[1];

  const cookies = loginPageResp.headers.getSetCookie();
  const csrfCookie = cookies.find((c) => c.startsWith('_gorilla_csrf='));
  if (!csrfCookie) throw new Error('Could not extract CSRF cookie');

  // Step 3: POST /login — submit credentials with auth_request_id
  const loginResp = await fetch(`${OAUTH_URL}/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: csrfCookie.split(';')[0],
      Origin: BASE_URL,
    },
    body: new URLSearchParams({
      username,
      password,
      'gorilla.csrf.Token': csrfToken,
      auth_request_id: authRequestId,
    }),
    redirect: 'manual',
  });

  if (loginResp.status !== 302) {
    const body = await loginResp.text();
    throw new Error(`Login returned ${loginResp.status}: ${body}`);
  }

  const location = loginResp.headers.get('Location');
  if (!location) throw new Error('Login did not return Location header');
  const code = new URL(location).searchParams.get('code');
  if (!code) throw new Error('No code in redirect URL');

  // Step 4: POST /token — exchange code
  const tokenResp = await postForm(`${OAUTH_URL}/token`, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: ADMIN_REDIRECT_URI,
    client_id: ADMIN_CLIENT_ID,
    code_verifier: TEST_CODE_VERIFIER,
  });

  if (!tokenResp.ok) {
    const text = await tokenResp.text();
    throw new Error(`Token exchange failed (${tokenResp.status}): ${text}`);
  }

  return tokenResp.json();
}

/**
 * Get a cached admin access token (via auth code flow).
 */
export async function getAdminToken(): Promise<string> {
  if (cachedAdminToken) return cachedAdminToken;
  const tokens = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
  cachedAdminToken = tokens.access_token;
  return cachedAdminToken;
}

/**
 * Obtain a token via ROPC using a test client that has the password grant enabled.
 * Creates the test client on first use via the admin API.
 */
export async function obtainTokenViaROPC(
  username: string,
  password: string,
  scope = 'openid profile email'
): Promise<{ access_token: string; refresh_token: string; id_token: string; token_type: string }> {
  if (!ropcClientID) {
    const adminToken = await getAdminToken();
    const resp = await postJSON(
      `${OAUTH_URL}/register`,
      {
        client_name: 'Functional Test ROPC Client',
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['authorization_code', 'password', 'refresh_token'],
        response_types: ['code'],
        scopes: 'openid profile email offline_access',
        client_type: 'public',
        token_endpoint_auth_method: 'none',
      },
      adminToken
    );
    if (resp.status !== 201) {
      const text = await resp.text();
      throw new Error(`Failed to create ROPC client (${resp.status}): ${text}`);
    }
    const client = await resp.json();
    ropcClientID = client.client_id;
  }

  const resp = await postForm(`${OAUTH_URL}/token`, {
    grant_type: 'password',
    username,
    password,
    scope,
    client_id: ropcClientID!,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`ROPC token request failed (${resp.status}): ${text}`);
  }
  return resp.json();
}
