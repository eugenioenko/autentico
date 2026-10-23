import { it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, putJSON, postForm } from '../helpers';

it('enforces required email verification before password grants and preserves the admin exemption', async () => {
 const admin = await getAdminToken();
 const client = await postJSON(`${OAUTH_URL}/register`, {client_id:'email-policy',client_name:'Email policy',client_type:'public',token_endpoint_auth_method:'none',redirect_uris:['http://localhost/callback'],grant_types:['password'],scopes:'openid'},admin);
 expect(client.status).toBe(201);
 const created = await postJSON(`${BASE_URL}/admin/api/users`, {username:'unverified-policy',password:'Password123!',email:'policy@example.com'},admin);
 expect(created.status).toBe(201);
 const user = (await created.json()).data;
 const grant = () => postForm(`${OAUTH_URL}/token`, {grant_type:'password',client_id:'email-policy',username:'unverified-policy',password:'Password123!',scope:'openid'});
 expect((await grant()).status).toBe(200);
 const settings = await putJSON(`${BASE_URL}/admin/api/settings`, {require_email_verification:'true'},admin);
 expect(settings.ok).toBe(true);
 const denied = await grant();
 expect(denied.status).toBe(400);
 expect(await denied.json()).toMatchObject({error:'invalid_grant',error_description:'Email verification is required'});
 const exempt = await postForm(`${OAUTH_URL}/token`, {grant_type:'password',client_id:'email-policy',username:'admin',password:'Password123!',scope:'openid'});
 expect(exempt.status).toBe(200);
 const verified = await putJSON(`${BASE_URL}/admin/api/users/${user.id}`, {is_email_verified:true},admin);
 expect(verified.status,await verified.text()).toBe(200);
 expect((await grant()).status).toBe(200);
});
