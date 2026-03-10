/**
 * Shared OIDC auth flow logic for k6 stress tests.
 *
 * Performs the full Authorization Code + PKCE flow:
 *   GET /oauth2/authorize  → extract CSRF token
 *   POST /oauth2/login     → obtain auth code
 *   POST /oauth2/token     → exchange code for tokens
 *   POST /oauth2/introspect → verify token is active
 *   POST /oauth2/token     → refresh access token
 *
 * Required env vars (set via -e or k6 cloud):
 *   BASE_URL     Server base URL          (default: http://localhost:8080)
 *   USERNAME     Test user username       (default: admin)
 *   PASSWORD     Test user password       (default: password)
 *   CLIENT_ID    Public PKCE client ID    (default: stress-test)
 *   REDIRECT_URI Registered redirect URI  (default: http://localhost:8080/stress/callback)
 *   OAUTH_PATH   OAuth2 path prefix       (default: /oauth2)
 */

import http from 'k6/http';
import { check, group } from 'k6';
import crypto from 'k6/crypto';
import { Trend, Counter, Rate } from 'k6/metrics';

export const BASE_URL    = __ENV.BASE_URL    || 'http://localhost:8080';
export const USERNAME    = __ENV.USERNAME    || 'admin';
export const PASSWORD    = __ENV.PASSWORD    || 'password';
export const CLIENT_ID   = __ENV.CLIENT_ID   || 'stress-test';
export const REDIRECT_URI = __ENV.REDIRECT_URI || 'http://localhost:8080/stress/callback';
export const OAUTH_PATH  = __ENV.OAUTH_PATH  || '/oauth2';

// Custom metrics
export const authorizeLatency  = new Trend('authorize_latency',  true);
export const loginLatency      = new Trend('login_latency',      true);
export const tokenLatency      = new Trend('token_latency',      true);
export const introspectLatency = new Trend('introspect_latency', true);
export const refreshLatency    = new Trend('refresh_latency',    true);
export const flowErrors        = new Counter('flow_errors');
export const flowSuccessRate   = new Rate('flow_success_rate');

function generatePKCE() {
  const verifierBytes = crypto.randomBytes(32);
  const verifier = crypto.hexEncode(verifierBytes)
    .slice(0, 43); // Use first 43 hex chars as verifier (URL-safe, no padding needed)
  const challenge = crypto.sha256(verifier, 'base64rawurl');
  return { verifier, challenge };
}

function extractCSRF(body) {
  const match = body.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/);
  return match ? match[1] : null;
}

function extractFormValue(body, name) {
  const match = body.match(new RegExp(`name="${name}"\\s+value="([^"]*)"`));
  return match ? match[1] : '';
}

/**
 * Runs the full PKCE auth code flow for one virtual user iteration.
 * Returns the token response body on success, null on any failure.
 */
export function authFlow() {
  const { verifier, challenge } = generatePKCE();
  const state = crypto.hexEncode(crypto.randomBytes(8));
  let success = true;

  // ── Step 1: Load authorize page ──────────────────────────────────────────
  let authPage;
  group('authorize', () => {
    const url = `${BASE_URL}${OAUTH_PATH}/authorize` +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      `&scope=openid+profile+email` +
      `&state=${state}` +
      `&code_challenge=${challenge}` +
      `&code_challenge_method=S256`;

    authPage = http.get(url);
    authorizeLatency.add(authPage.timings.duration);

    if (!check(authPage, { 'authorize: 200': (r) => r.status === 200 })) {
      flowErrors.add(1);
      success = false;
    }
  });

  if (!success) { flowSuccessRate.add(false); return null; }

  const csrfToken = extractCSRF(authPage.body);
  if (!csrfToken) {
    flowErrors.add(1);
    flowSuccessRate.add(false);
    return null;
  }

  // ── Step 2: Submit login form ─────────────────────────────────────────────
  let code = null;
  group('login', () => {
    const loginResp = http.post(
      `${BASE_URL}${OAUTH_PATH}/login`,
      {
        'gorilla.csrf.Token': csrfToken,
        username:             USERNAME,
        password:             PASSWORD,
        state:                extractFormValue(authPage.body, 'state') || state,
        redirect_uri:         REDIRECT_URI,
        client_id:            CLIENT_ID,
        scope:                'openid profile email',
        nonce:                '',
        code_challenge:       challenge,
        code_challenge_method: 'S256',
      },
      { redirects: 0, headers: { Referer: `${BASE_URL}${OAUTH_PATH}/authorize`, Origin: BASE_URL } }
    );
    loginLatency.add(loginResp.timings.duration);

    const location = loginResp.headers['Location'] || '';
    const codeMatch = location.match(/[?&]code=([^&]+)/);

    if (!check(loginResp, {
      'login: 302 with code': (r) => r.status === 302 && codeMatch !== null,
    })) {
      flowErrors.add(1);
      success = false;
      return;
    }
    code = codeMatch[1];
  });

  if (!success || !code) { flowSuccessRate.add(false); return null; }

  // ── Step 3: Exchange code for tokens ─────────────────────────────────────
  let tokens = null;
  group('token_exchange', () => {
    const tokenResp = http.post(
      `${BASE_URL}${OAUTH_PATH}/token`,
      {
        grant_type:    'authorization_code',
        code:          code,
        redirect_uri:  REDIRECT_URI,
        client_id:     CLIENT_ID,
        code_verifier: verifier,
      }
    );
    tokenLatency.add(tokenResp.timings.duration);

    if (!check(tokenResp, {
      'token: 200':             (r) => r.status === 200,
      'token: has access_token': (r) => {
        try { return !!JSON.parse(r.body).access_token; } catch { return false; }
      },
    })) {
      flowErrors.add(1);
      success = false;
      return;
    }
    tokens = JSON.parse(tokenResp.body);
  });

  if (!success || !tokens) { flowSuccessRate.add(false); return null; }

  // ── Step 4: Introspect ────────────────────────────────────────────────────
  group('introspect', () => {
    const introspectResp = http.post(
      `${BASE_URL}${OAUTH_PATH}/introspect`,
      JSON.stringify({ token: tokens.access_token }),
      { headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokens.access_token}` } }
    );
    introspectLatency.add(introspectResp.timings.duration);

    check(introspectResp, {
      'introspect: 200':     (r) => r.status === 200,
      'introspect: active':  (r) => {
        try { return JSON.parse(r.body).active === true; } catch { return false; }
      },
    });
  });

  // ── Step 5: Refresh ───────────────────────────────────────────────────────
  if (tokens.refresh_token) {
    group('refresh', () => {
      const refreshResp = http.post(
        `${BASE_URL}${OAUTH_PATH}/token`,
        {
          grant_type:    'refresh_token',
          refresh_token: tokens.refresh_token,
          client_id:     CLIENT_ID,
        }
      );
      refreshLatency.add(refreshResp.timings.duration);

      check(refreshResp, {
        'refresh: 200': (r) => r.status === 200,
      });
    });
  }

  flowSuccessRate.add(true);
  return tokens;
}
