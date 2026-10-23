import { it, expect } from 'vitest';
import { OAUTH_URL, getAdminToken, obtainTokenViaROPC, postForm } from '../helpers';

it('requires admin audience for privileged revocation and preserves tokens on rejection', async () => {
 const app = await obtainTokenViaROPC('admin', 'Password123!');
 const target = await obtainTokenViaROPC('admin', 'Password123!');
 for (const credential of [target.access_token, target.refresh_token]) {
  const response = await postForm(`${OAUTH_URL}/revoke`, { token: credential }, app.access_token);
  expect(response.status).toBe(403);
  expect(response.headers.get('www-authenticate')).toContain('Bearer error="insufficient_scope"');
  expect(await response.json()).toMatchObject({ error: 'insufficient_scope' });
 }
 const admin = await getAdminToken();
 const active = await postForm(`${OAUTH_URL}/introspect`, { token: target.access_token }, admin);
 expect(await active.json()).toMatchObject({ active: true });
 const accepted = await postForm(`${OAUTH_URL}/revoke`, { token: target.access_token }, admin);
 expect(accepted.status).toBe(200);
 for (const credential of [target.access_token, target.refresh_token]) {
  const inactive = await postForm(`${OAUTH_URL}/introspect`, { token: credential }, admin);
  expect(await inactive.json()).toEqual({ active: false });
 }
});
