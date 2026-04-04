import { describe, it, expect } from 'vitest';
import { OAUTH_URL, obtainTokenViaROPC, postForm } from '../helpers';

const INTROSPECT = `${OAUTH_URL}/introspect`;

describe('Token Introspection — happy path', () => {
  it('returns active=true with claims for valid token', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    const resp = await postForm(INTROSPECT, { token: tokens.access_token });
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(true);
    expect(body.sub).toBeTruthy();
    expect(body.iss).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
  });

  it('returns active=false for revoked token', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    // Revoke
    await postForm(`${OAUTH_URL}/revoke`, { token: tokens.access_token });

    // Introspect
    const resp = await postForm(INTROSPECT, { token: tokens.access_token });
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(false);
  });
});

describe('Token Introspection — error cases', () => {
  it('returns active=false for garbage token', async () => {
    const resp = await postForm(INTROSPECT, { token: 'garbage-not-a-jwt' });
    expect(resp.ok).toBe(true);

    const body = await resp.json();
    expect(body.active).toBe(false);
  });

  it('returns 400 for missing token param', async () => {
    const resp = await postForm(INTROSPECT, {});
    expect(resp.status).toBe(400);
  });

  it('returns 400 for empty token', async () => {
    const resp = await postForm(INTROSPECT, { token: '' });
    expect(resp.status).toBe(400);
  });
});
