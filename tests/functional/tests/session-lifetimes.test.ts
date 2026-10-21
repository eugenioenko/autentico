import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, getJSON, postJSON, postFormBasic } from '../helpers';

function claims(jwt: string): { sid: string; exp: number } {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
}

describe('OAuth session lifetime', () => {
  for (const short of ['access', 'refresh'] as const) {
    it(`keeps the session active when only ${short} expires`, async () => {
      const admin = await getAdminToken();
      const client = `session-lifetime-${short}`;
      const secret = 'session-lifetime-secret';
      const registered = await postJSON(`${OAUTH_URL}/register`, {
        client_id: client, client_name: client, client_secret: secret,
        redirect_uris: ['http://localhost:3000/callback'],
        grant_types: ['password', 'refresh_token'], response_types: ['code'],
        scopes: 'openid offline_access', client_type: 'confidential',
        token_endpoint_auth_method: 'client_secret_basic',
        access_token_expiration: short === 'access' ? '3s' : '1h',
        refresh_token_expiration: short === 'refresh' ? '3s' : '1h',
      }, admin);
      expect(registered.status, await registered.text()).toBe(201);
      const response = await postFormBasic(`${OAUTH_URL}/token`, {
        grant_type: 'password', username: 'admin', password: 'Password123!', scope: 'openid offline_access',
      }, client, secret);
      expect(response.status).toBe(200);
      const tokens = await response.json();
      const access = claims(tokens.access_token), refresh = claims(tokens.refresh_token);
      const sessions = await getJSON<{ data: { id: string; expires_at: string; status: string }[] }>(`${BASE_URL}/admin/api/sessions`, admin);
      const session = sessions.data.find(s => s.id === refresh.sid);
      expect(session).toBeDefined();
      expect(Math.floor(Date.parse(session!.expires_at) / 1000)).toBe(Math.max(access.exp, refresh.exp));
      await new Promise(resolve => setTimeout(resolve, Math.max(0, (short === 'access' ? access.exp : refresh.exp) * 1000 - Date.now() + 100)));
      const after = await getJSON<typeof sessions>(`${BASE_URL}/admin/api/sessions`, admin);
      expect(after.data.find(s => s.id === refresh.sid)?.status).toBe('active');
      const rotated = await postFormBasic(`${OAUTH_URL}/token`, {
        grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
      }, client, secret);
      expect(rotated.status).toBe(short === 'access' ? 200 : 400);
      if (short === 'access') expect((await rotated.json()).refresh_token).not.toBe(tokens.refresh_token);
    });
  }
});
