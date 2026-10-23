import { it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, obtainTokenViaROPC, postForm, postJSON } from '../helpers';

it('requires admin audience for privileged revocation and preserves tokens on rejection', async () => {
 const app = await obtainTokenViaROPC('admin', 'Password123!');
 const admin = await getAdminToken();
 const created = await postJSON(`${BASE_URL}/admin/api/users`, {username:'revocation-target',password:'Password123!',email:'revocation-target@example.com'},admin);
 expect(created.status).toBe(201);
 const client = await postJSON(`${OAUTH_URL}/register`, {client_id:'revocation-target-client',client_name:'Revocation target',client_type:'public',token_endpoint_auth_method:'none',redirect_uris:['http://localhost/callback'],grant_types:['password','refresh_token'],scopes:'openid'},admin);
 expect(client.status).toBe(201);
 const issued = await postForm(`${OAUTH_URL}/token`, {grant_type:'password',username:'revocation-target',password:'Password123!',client_id:'revocation-target-client',scope:'openid'});
 expect(issued.status).toBe(200);
 const target = await issued.json();
 for (const credential of [target.access_token, target.refresh_token]) {
  const response = await postForm(`${OAUTH_URL}/revoke`, { token: credential }, app.access_token);
  expect(response.status).toBe(403);
  expect(response.headers.get('www-authenticate')).toContain('Bearer error="insufficient_scope"');
  expect(await response.json()).toMatchObject({ error: 'insufficient_scope' });
 }
 for (const credential of [target.access_token, target.refresh_token]) {
  const active = await postForm(`${OAUTH_URL}/introspect`, { token: credential }, admin);
  expect(await active.json()).toMatchObject({ active: true });
 }
 const accepted = await postForm(`${OAUTH_URL}/revoke`, { token: target.access_token }, admin);
 expect(accepted.status).toBe(200);
 for (const credential of [target.access_token, target.refresh_token]) {
  const inactive = await postForm(`${OAUTH_URL}/introspect`, { token: credential }, admin);
  expect(await inactive.json()).toEqual({ active: false });
 }
});
