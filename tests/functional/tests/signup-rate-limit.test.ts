import { it, expect } from 'vitest';
import { join } from 'path';
import { BASE_URL, OAUTH_URL, postForm, putJSON } from '../helpers';
import { startServer, stopServer } from '../server-manager';

for (const suffix of ['', '/']) {
 it(`shares the existing IP budget for authorize and signup POST at /signup${suffix}`, async () => {
  await stopServer();
  await startServer({binary:join(import.meta.dirname,'../../../autentico'),args:['start'],env:{
   AUTENTICO_RATE_LIMIT_RPS:'0.000001',AUTENTICO_RATE_LIMIT_BURST:'4',
   AUTENTICO_RATE_LIMIT_RPM:'60000',AUTENTICO_RATE_LIMIT_RPM_BURST:'60000',
  }});
  const adminGrant=await postForm(`${OAUTH_URL}/token`,{grant_type:'password',client_id:'autentico-admin',username:'admin',password:'Password123!',scope:'openid profile email'});
  expect(adminGrant.status).toBe(200);
  const enabled=await putJSON(`${BASE_URL}/admin/api/clients/autentico-account`,{allow_self_signup:true},(await adminGrant.json()).access_token);
  expect(enabled.ok).toBe(true);
  const parameters={client_id:'autentico-account',redirect_uri:`${BASE_URL}/account/callback`,response_type:'code',scope:'openid',state:'signup-limit',prompt:'create',code_challenge:'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method:'S256'};
  const page=await fetch(`${OAUTH_URL}/authorize?${new URLSearchParams(parameters)}`,{redirect:'manual'});
  expect(page.status).toBe(200);
  const html=await page.text();
  const csrf=html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/)?.[1];
  const signature=html.match(/name="authorize_sig"\s+value="([^"]+)"/)?.[1];
  const cookie=page.headers.getSetCookie().find(value=>value.startsWith('_gorilla_csrf='))?.split(';')[0];
  expect(csrf).toBeTruthy();expect(signature).toBeTruthy();expect(cookie).toBeTruthy();
  for (let index=0;index<3;index++) {
   const response=await fetch(`${OAUTH_URL}/signup${suffix}`,{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie!,Origin:BASE_URL},body:new URLSearchParams({...parameters,'gorilla.csrf.Token':csrf!,authorize_sig:signature!,username:`limited-user-${index}`,email:`limited${index}@example.com`,password:'Password123!',confirm_password:'Password123!'})});
   if(index<2) {
    expect(response.status,await response.clone().text()).toBe(302);
    expect(new URL(response.headers.get('location')!).searchParams.get('code')).toBeTruthy();
   } else {
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('1');
    expect(await response.json()).toMatchObject({error:'too_many_requests'});
   }
  }
  // A different auth route consumes the same IP budget; spoofed forwarding
  // headers do not create a new identity with no configured trusted proxy.
  const login=await fetch(`${OAUTH_URL}/login?${new URLSearchParams(parameters)}`,{redirect:'manual',headers:{'X-Forwarded-For':'203.0.113.90'}});
  expect(login.status).toBe(429);
  const invalidGet=await fetch(`${OAUTH_URL}/signup${suffix}`,{redirect:'manual'});
  expect(invalidGet.status).toBe(429);
 });
}

for (const suffix of ['', '/']) {
 it(`still rejects missing and invalid CSRF at /signup${suffix} with budget available`, async () => {
  await stopServer();
  await startServer({binary:join(import.meta.dirname,'../../../autentico'),args:['start'],env:{
   AUTENTICO_RATE_LIMIT_RPS:'0.000001',AUTENTICO_RATE_LIMIT_BURST:'4',
   AUTENTICO_RATE_LIMIT_RPM:'60000',AUTENTICO_RATE_LIMIT_RPM_BURST:'60000',
  }});
  const parameters={client_id:'autentico-account',redirect_uri:`${BASE_URL}/account/callback`,response_type:'code',scope:'openid',state:'csrf-check',code_challenge:'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method:'S256'};
  const page=await fetch(`${OAUTH_URL}/authorize?${new URLSearchParams(parameters)}`,{redirect:'manual'});
  expect(page.status).toBe(200);
  const cookie=page.headers.getSetCookie().find(value=>value.startsWith('_gorilla_csrf='))?.split(';')[0];
  expect(cookie).toBeTruthy();
  for (const value of ['', 'invalid-csrf-token']) {
   const body=new URLSearchParams(parameters);
   if (value) body.set('gorilla.csrf.Token',value);
   const response=await fetch(`${OAUTH_URL}/signup${suffix}`,{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie!,Origin:BASE_URL},body});
   expect(response.status).toBe(403);
   expect(await response.text()).toContain('CSRF');
  }
 });
}
