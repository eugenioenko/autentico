import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI, getAdminToken, getResponse, putJSON } from '../helpers';

describe('Security Headers', () => {
  it('admin API returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/admin/api/users`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('account API returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${BASE_URL}/account/api/settings`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('userinfo returns Cache-Control: no-store', async () => {
    const token = await getAdminToken();
    const resp = await getResponse(`${OAUTH_URL}/userinfo`, token);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('discovery endpoint returns Cache-Control: no-store', async () => {
    const resp = await getResponse(`${BASE_URL}/.well-known/openid-configuration`);
    expect(resp.ok).toBe(true);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  it('all responses include X-Frame-Options and X-Content-Type-Options', async () => {
    const resp = await getResponse(`${BASE_URL}/.well-known/openid-configuration`);
    expect(resp.headers.get('X-Frame-Options')).toBe('DENY');
    expect(resp.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('error responses also include cache headers', async () => {
    // Unauthenticated request to admin API — should still have cache headers
    const resp = await getResponse(`${BASE_URL}/admin/api/users`);
    expect(resp.status).toBe(401);
    expect(resp.headers.get('Cache-Control')).toBe('no-store');
    expect(resp.headers.get('Pragma')).toBe('no-cache');
  });

  describe('theme logo URL', () => {
    async function setLogo(value: string): Promise<Response> {
      const token = await getAdminToken();
      return putJSON(`${BASE_URL}/admin/api/settings`, { theme_logo_url: value }, token);
    }

    async function loginPage(): Promise<Response> {
      const url = new URL(`${OAUTH_URL}/authorize`);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', ADMIN_CLIENT_ID);
      url.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
      url.searchParams.set('scope', 'openid');
      url.searchParams.set('state', 'logo-test');
      url.searchParams.set('code_challenge', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
      url.searchParams.set('code_challenge_method', 'S256');
      return fetch(url.toString(), { redirect: 'manual' });
    }

    it('allows a cross-origin https logo in img-src and renders it', async () => {
      expect((await setLogo('https://cdn.example.com/logo.svg')).status).toBe(204);
      try {
        const resp = await loginPage();
        expect(resp.status).toBe(200);
        expect(resp.headers.get('Content-Security-Policy')).toContain("img-src 'self' data: https://cdn.example.com;");
        expect(await resp.text()).toContain('<img src="https://cdn.example.com/logo.svg"');

        const account = await getResponse(`${BASE_URL}/account/api/settings`);
        expect(account.headers.get('Content-Security-Policy')).toContain('https://cdn.example.com');
      } finally {
        await setLogo('');
      }
    });

    it('renders a data:image logo unescaped', async () => {
      const dataURI = 'data:image/png;base64,iVBORw0KGgo=';
      expect((await setLogo(dataURI)).status).toBe(204);
      try {
        const resp = await loginPage();
        expect(resp.headers.get('Content-Security-Policy')).toContain("img-src 'self' data:;");
        const html = await resp.text();
        expect(html).toContain(`<img src="${dataURI}"`);
        expect(html).not.toContain('ZgotmplZ');
      } finally {
        await setLogo('');
      }
    });

    it('rejects non-https and script logo URLs', async () => {
      expect((await setLogo('http://cdn.example.com/logo.svg')).status).toBe(400);
      expect((await setLogo('javascript:alert(1)')).status).toBe(400);
      expect((await setLogo('//cdn.example.com/logo.svg')).status).toBe(400);
      const resp = await loginPage();
      expect(resp.headers.get('Content-Security-Policy')).toContain("img-src 'self' data:;");
    });
  });
});
