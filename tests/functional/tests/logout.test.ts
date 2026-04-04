import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, obtainTokenViaROPC, postForm, getResponse, postJSON, obtainTokenViaAuthCode, ADMIN_USERNAME, ADMIN_PASSWORD } from '../helpers';

describe('Logout — happy path', () => {
  it('POST with id_token_hint deactivates session', async () => {
    const tokens = await obtainTokenViaROPC('admin', 'Password123!');

    // Logout via POST
    const logoutResp = await postForm(`${OAUTH_URL}/logout`, {
      id_token_hint: tokens.access_token,
    });
    expect(logoutResp.ok).toBe(true);

    // Token should be dead
    const userinfo = await getResponse(`${OAUTH_URL}/userinfo`, tokens.access_token);
    expect(userinfo.status).toBe(401);
  });

  it('GET with no params renders logout page', async () => {
    const resp = await getResponse(`${OAUTH_URL}/logout`);
    expect(resp.status).toBe(200);
  });

  it('GET with registered post_logout_redirect_uri redirects', async () => {
    // Get a fresh admin token (cached one may have been invalidated by session tests)
    const freshTokens = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    const token = freshTokens.access_token;
    const clientResp = await postJSON(`${OAUTH_URL}/register`, {
      client_name: 'Logout Test Client',
      redirect_uris: ['http://localhost:3000/callback'],
      post_logout_redirect_uris: ['http://localhost:3000/logged-out'],
    }, token);
    expect(clientResp.status).toBe(201);
    const client = await clientResp.json();

    const resp = await getResponse(
      `${OAUTH_URL}/logout?client_id=${client.client_id}&post_logout_redirect_uri=${encodeURIComponent('http://localhost:3000/logged-out')}`
    );
    expect(resp.status).toBe(302);
    expect(resp.headers.get('Location')).toBe('http://localhost:3000/logged-out');
  });
});

describe('Logout — error cases', () => {
  it('POST with invalid id_token_hint still renders logout page', async () => {
    const resp = await postForm(`${OAUTH_URL}/logout`, {
      id_token_hint: 'garbage-jwt',
    });
    expect(resp.status).toBe(200);
  });

  it('GET with unregistered redirect URI shows logout page', async () => {
    const freshTokens = await obtainTokenViaAuthCode(ADMIN_USERNAME, ADMIN_PASSWORD);
    const token = freshTokens.access_token;
    const clientResp = await postJSON(`${OAUTH_URL}/register`, {
      client_name: 'Logout Unregistered URI Client',
      redirect_uris: ['http://localhost:3000/callback'],
      post_logout_redirect_uris: ['http://localhost:3000/allowed'],
    }, token);
    expect(clientResp.status).toBe(201);
    const client = await clientResp.json();

    const resp = await getResponse(
      `${OAUTH_URL}/logout?client_id=${client.client_id}&post_logout_redirect_uri=${encodeURIComponent('http://evil.com/steal')}`
    );
    expect(resp.status).toBe(200); // No redirect, shows logout page
  });
});
