import { describe, it, expect, afterAll } from 'vitest';
import { BASE_URL, OAUTH_URL, ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI, getAdminToken, putJSON } from '../helpers';

const TEST_CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

async function updateSettings(settings: Record<string, string>): Promise<void> {
  const token = await getAdminToken();
  const resp = await putJSON(`${BASE_URL}/admin/api/settings`, settings, token);
  expect(resp.ok).toBe(true);
}

async function fetchLoginPage(): Promise<string> {
  const url = new URL(`${OAUTH_URL}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', ADMIN_CLIENT_ID);
  url.searchParams.set('redirect_uri', ADMIN_REDIRECT_URI);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', 'mode-test');
  url.searchParams.set('code_challenge', TEST_CODE_CHALLENGE);
  url.searchParams.set('code_challenge_method', 'S256');

  const resp = await fetch(url.toString(), { redirect: 'manual' });
  expect(resp.status).toBe(200);
  return resp.text();
}

afterAll(async () => {
  await updateSettings({
    auth_mode: 'password',
    passkey_login_mode: 'username_first',
  });
});

describe('Login page — auth_mode=password (default)', () => {
  it('shows username and password fields', async () => {
    await updateSettings({ auth_mode: 'password', passkey_login_mode: 'username_first', magic_link_enabled: 'false' });
    const html = await fetchLoginPage();

    expect(html).toContain('id="username"');
    expect(html).toContain('id="password"');
  });

  it('shows Log In button with correct text', async () => {
    const html = await fetchLoginPage();
    expect(html).toContain('type="submit"');
    expect(html).toContain('>Log In<');
  });

  it('does not show passkey button', async () => {
    const html = await fetchLoginPage();
    expect(html).not.toContain('id="passkey-login-btn"');
  });
});

describe('Login page — auth_mode=password_and_passkey', () => {
  describe('passkey_login_mode=username_first', () => {
    it('shows username, password, login button, and passkey button', async () => {
      await updateSettings({ auth_mode: 'password_and_passkey', passkey_login_mode: 'username_first' });
      const html = await fetchLoginPage();

      expect(html).toContain('id="username"');
      expect(html).toContain('id="password"');
      expect(html).toContain('>Log In<');
      expect(html).toContain('id="passkey-login-btn"');
    });

    it('passkey button says "Sign in with passkey"', async () => {
      const html = await fetchLoginPage();
      expect(html).toContain('Sign in with passkey');
    });

    it('shows "or" divider between login and passkey buttons', async () => {
      const html = await fetchLoginPage();
      expect(html).toContain('"auth-divider">or<');
    });

    it('passkey button is secondary', async () => {
      const html = await fetchLoginPage();
      const btnMatch = html.match(/<button[^>]*class="([^"]*)"[^>]*id="passkey-login-btn"/);
      expect(btnMatch).toBeTruthy();
      expect(btnMatch![1]).toContain('auth-btn-secondary');
    });
  });

  describe('passkey_login_mode=discoverable', () => {
    it('shows username and password fields with passkey button', async () => {
      await updateSettings({ auth_mode: 'password_and_passkey', passkey_login_mode: 'discoverable' });
      const html = await fetchLoginPage();

      expect(html).toContain('id="username"');
      expect(html).toContain('id="password"');
      expect(html).toContain('id="passkey-login-btn"');
    });
  });

  describe('passkey_login_mode=conditional', () => {
    it('username field has webauthn autocomplete', async () => {
      await updateSettings({ auth_mode: 'password_and_passkey', passkey_login_mode: 'conditional' });
      const html = await fetchLoginPage();

      expect(html).toContain('id="username"');
      expect(html).toMatch(/autocomplete="[^"]*webauthn[^"]*"/);
    });
  });

  describe('passkey_login_mode=passkey_only', () => {
    it('still shows username field for password fallback', async () => {
      await updateSettings({ auth_mode: 'password_and_passkey', passkey_login_mode: 'passkey_only' });
      const html = await fetchLoginPage();

      expect(html).toContain('id="username"');
      expect(html).toContain('id="password"');
    });
  });
});

describe('Login page — auth_mode=passkey_only', () => {
  describe('passkey_login_mode=passkey_only', () => {
    it('hides username and password fields', async () => {
      await updateSettings({ auth_mode: 'passkey_only', passkey_login_mode: 'passkey_only' });
      const html = await fetchLoginPage();

      expect(html).not.toContain('id="username"');
      expect(html).not.toContain('id="password"');
    });

    it('shows passkey button as primary with correct text', async () => {
      const html = await fetchLoginPage();
      const btnMatch = html.match(/<button[^>]*class="([^"]*)"[^>]*id="passkey-login-btn"/);
      expect(btnMatch).toBeTruthy();
      expect(btnMatch![1]).toContain('auth-btn');
      expect(btnMatch![1]).not.toContain('auth-btn-secondary');
      expect(html).toContain('Sign in with passkey');
    });

    it('does not show Log In button', async () => {
      const html = await fetchLoginPage();
      expect(html).not.toContain('>Log In<');
    });

    it('does not show "or" divider', async () => {
      const html = await fetchLoginPage();
      expect(html).not.toContain('"auth-divider">or<');
    });
  });

  describe('passkey_login_mode=username_first', () => {
    it('shows username field but hides password', async () => {
      await updateSettings({ auth_mode: 'passkey_only', passkey_login_mode: 'username_first' });
      const html = await fetchLoginPage();

      expect(html).toContain('id="username"');
      expect(html).not.toContain('id="password"');
    });

    it('passkey button is primary when no login button', async () => {
      const html = await fetchLoginPage();
      const btnMatch = html.match(/<button[^>]*class="([^"]*)"[^>]*id="passkey-login-btn"/);
      expect(btnMatch).toBeTruthy();
      expect(btnMatch![1]).toContain('auth-btn');
      expect(btnMatch![1]).not.toContain('auth-btn-secondary');
    });
  });
});
