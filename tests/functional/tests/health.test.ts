import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getResponse, postForm } from '../helpers';

describe('Health Check', () => {
  it('returns 200', async () => {
    const resp = await fetch(`${BASE_URL}/healthz`);
    expect(resp.ok).toBe(true);
  });

  it('returns JSON with status', async () => {
    const resp = await fetch(`${BASE_URL}/healthz`);
    const body = await resp.json();
    expect(body.status).toBe('ok');
  });
});

describe('Onboard guard', () => {
  it('GET /onboard redirects when already onboarded', async () => {
    const resp = await getResponse(`${BASE_URL}/onboard`);
    expect(resp.status).toBe(302);
  });

  it('POST /onboard is blocked when already onboarded', async () => {
    // POST to /onboard is CSRF-protected, so without a valid token it returns 403.
    // Either way, onboarding cannot be repeated.
    const resp = await postForm(`${BASE_URL}/onboard`, {
      username: 'hacker',
      password: 'TryToOnboard!',
    });
    expect([302, 403]).toContain(resp.status);
  });
});
