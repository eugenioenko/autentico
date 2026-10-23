import { beforeAll, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL, getAdminToken, postJSON, putJSON, postForm } from '../helpers';

let admin: string;
const client_id = 'generic-lockout-client';
const callback = `${BASE_URL}/lockout-callback`;
const password = 'Password123!';
beforeAll(async () => {
 admin = await getAdminToken();
 expect((await putJSON(`${BASE_URL}/admin/api/settings`, {account_lockout_max_attempts:'2',account_lockout_duration:'1m',require_email_verification:'false',require_mfa:'false'},admin)).status).toBe(204);
 expect((await postJSON(`${OAUTH_URL}/register`, {client_id,client_name:client_id,client_type:'public',token_endpoint_auth_method:'none',redirect_uris:[callback],grant_types:['authorization_code','password'],response_types:['code'],scopes:'openid'},admin)).status).toBe(201);
});

async function browserLogin(username: string, submittedPassword: string): Promise<{status: number; error: string | null; location: string}> {
 const params={client_id,redirect_uri:callback,response_type:'code',scope:'openid',state:'lockout-check',code_challenge:'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method:'S256'};
 const page=await fetch(`${OAUTH_URL}/authorize?${new URLSearchParams(params)}`,{redirect:'manual'});
 expect(page.status).toBe(200);
 const html=await page.text();
 const csrf=html.match(/name="gorilla\.csrf\.Token"\s+value="([^"]+)"/)?.[1];
 const sig=html.match(/name="authorize_sig"\s+value="([^"]*)"/)?.[1];
 const cookie=page.headers.getSetCookie().find(c=>c.startsWith('_gorilla_csrf='))?.split(';')[0];
 expect(csrf).toBeTruthy();expect(sig).toBeTruthy();expect(cookie).toBeTruthy();
 const response=await fetch(`${OAUTH_URL}/login`,{method:'POST',redirect:'manual',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie!,Origin:BASE_URL},body:new URLSearchParams({...params,username,password:submittedPassword,'gorilla.csrf.Token':csrf!,authorize_sig:sig!})});
 const location=response.headers.get('location')!;
 return {status:response.status,error:new URL(location,BASE_URL).searchParams.get('error'),location};
}

for (const flow of ['token','browser']) {
 it(`keeps unknown and locked account responses identical before and after the threshold via ${flow}`,async () => {
  const username=`lockout-${flow}`;
  const created=await postJSON(`${BASE_URL}/admin/api/users`,{username,password,email:`${username}@example.com`},admin);
  expect(created.status).toBe(201);const user=(await created.json()).data;
  const tokenRequest=(name: string, submittedPassword: string)=>postForm(`${OAUTH_URL}/token`,{grant_type:'password',client_id,username:name,password:submittedPassword,scope:'openid'});
  for (let attempt=0;attempt<5;attempt++) {
   if (flow==='token') {
    const known=await tokenRequest(username,'wrong-password');
    const unknown=await tokenRequest('does-not-exist','wrong-password');
    expect(known.status).toBe(400);expect(unknown.status).toBe(400);
    const body=await known.json();expect(body).toEqual(await unknown.json());
    expect(body).toMatchObject({error:'invalid_grant',error_description:'Invalid username or password'});
   } else {
    const known=await browserLogin(username,'wrong-password');
    const unknown=await browserLogin('does-not-exist','wrong-password');
    expect(known.status).toBe(302);expect(known).toEqual(unknown);
    expect(known.error).toBe('Invalid username or password');
   }
  }
  // Correct credentials cannot bypass an active lock and do not reveal it.
  if (flow==='token') {
   const locked=await tokenRequest(username,password);expect(locked.status).toBe(400);
   expect(await locked.json()).toMatchObject({error:'invalid_grant',error_description:'Invalid username or password'});
  } else expect((await browserLogin(username,password)).error).toBe('Invalid username or password');
  const inspection=await fetch(`${BASE_URL}/admin/api/users/${user.id}`,{headers:{Authorization:`Bearer ${admin}`}});
  expect(inspection.status).toBe(200);
  expect((await inspection.json()).data).toMatchObject({failed_login_attempts:2,locked_until:expect.any(String)});
  expect((await postJSON(`${BASE_URL}/admin/api/users/${user.id}/unlock`,{},admin)).status).toBe(200);
  if (flow==='token') expect((await tokenRequest(username,password)).status).toBe(200);
  else {const unlocked=await browserLogin(username,password);expect(new URL(unlocked.location,BASE_URL).searchParams.get('code')).toBeTruthy();}
 });
}
