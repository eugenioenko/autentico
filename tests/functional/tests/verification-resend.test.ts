import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON } from '../helpers';

describe('Verification resend account privacy', () => {
  it('returns the same CSRF-protected page for unknown, unverified and verified accounts', async () => {
    const admin = await getAdminToken();
    const params = new URLSearchParams({ response_type: 'code', client_id: 'autentico-admin',
      redirect_uri: `${BASE_URL}/admin/callback`, scope: 'openid', state: 'resend-test',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' });
    const authorize = await fetch(`${OAUTH_URL}/authorize?${params}`, { redirect: 'manual' });
    expect(authorize.status).toBe(200);
    const html = await authorize.text();
    const csrf = html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/)?.[1];
    const signature = html.match(/name="authorize_sig"\s+value="([^"]+)"/)?.[1];
    const cookie = authorize.headers.getSetCookie().find(value => value.startsWith('_gorilla_csrf='))?.split(';')[0];
    expect(csrf).toBeTruthy(); expect(signature).toBeTruthy(); expect(cookie).toBeTruthy();
    params.set('gorilla.csrf.Token', csrf!);
    params.set('authorize_sig', signature!);
    params.set('username', 'resend-probe');
    async function resend(form = params): Promise<Response> {
      return fetch(`${OAUTH_URL}/resend-verification`, { method: 'POST', redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie!, Origin: BASE_URL }, body: form });
    }
    function publicBody(html: string): string {
      // CSP nonces differ per request independently of account state.
      return html.replace(/nonce="[^"]*"/g, 'nonce=""');
    }
    const unknown = await resend();
    expect(unknown.status).toBe(200);
    const generic = publicBody(await unknown.text());
    expect(generic).toContain('Check your inbox');
    expect(generic).not.toContain('already verified');
    const created = await postJSON(`${BASE_URL}/admin/api/users`, {
      username: 'resend-probe', password: 'Password123!', email: 'resend@example.com',
    }, admin);
    expect(created.status).toBe(201);
    const { data } = await created.json();
    const unverified = await resend();
    expect(unverified.status).toBe(200);
    expect(publicBody(await unverified.text())).toBe(generic);
    const verified = await fetch(`${BASE_URL}/admin/api/users/${data.id}`, {
      method: 'PUT', headers: { Authorization: `Bearer ${admin}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_email_verified: true }),
    });
    expect(verified.status).toBe(200);
    const repeated = await resend();
    expect(repeated.status).toBe(200);
    expect(publicBody(await repeated.text())).toBe(generic);
    const tampered = new URLSearchParams(params);
    tampered.set('authorize_sig', 'invalid');
    expect((await resend(tampered)).status).toBe(400);
  });
});
