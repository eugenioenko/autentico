import { test, expect } from '@playwright/test';
import { startServer, stopServer, getAdminToken, updateSettings, BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD } from '../server-manager';
import { clearEmails, extractLink, waitForNewEmail } from '../smtp-helper';

let admin: string;
const api = BASE_URL + '/admin/api/signup-invites';
test.beforeAll(async () => {
  await startServer();
  admin = await getAdminToken();
  await updateSettings(admin, { allow_self_signup: 'false', profile_field_email: 'optional', require_mfa: 'false' });
});
test.afterAll(() => stopServer());

test('admin creates a capped shared link, recipient signs up without email, admin revokes it', async ({ page, browser, request }) => {
  const earlier = await request.post(api, { headers: {Authorization:'Bearer '+admin},
    data: { kind: 'personal', delivery_method: 'link', email: 'earlier@test.com' } });
  expect(earlier.status()).toBe(201);
  await page.goto(BASE_URL + '/admin/users?tab=invites');
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type=submit]');
  await page.getByRole('button', {name:'Create invite'}).click();
  await page.getByLabel('Invitation type').selectOption('shared');
  await page.getByLabel('Maximum signups').fill('2');
  await page.getByRole('button', {name:'Generate link'}).click();
  const link = await page.getByText(/http.*\/invite\?token=/).innerText();
  await page.getByRole('group', {name:'earlier@test.com'}).getByRole('button', {name:'Revoke'}).click();
  await expect(page.getByText(link, {exact:true})).toBeVisible();
  const guest = await browser.newContext();
  const signup = await guest.newPage();
  await signup.goto(link);
  await signup.fill('#username','invited-member');
  await signup.fill('#password','Password123!');
  await signup.fill('#confirm_password','Password123!');
  await signup.click('#signup-btn');
  await expect(signup.getByTestId('account-dashboard')).toBeVisible();
  await page.reload();
  await expect(page.getByText(/1 of 2 used/)).toBeVisible();
  await page.getByRole('button',{name:'Revoke'}).click();
  await expect(page.getByText('Revoked',{exact:true})).toHaveCount(2);
  expect((await signup.goto(link))?.status()).toBe(410);
  await guest.close();
});

test('emailed invite verifies only its bound address and completes passkey signup', async ({ page, request }) => {
  await updateSettings(admin, { auth_mode:'passkey_only', profile_field_locale:'required', require_email_verification:'true', smtp_host:'localhost', smtp_port:'2525',smtp_from:'admin@test.com' });
  await clearEmails();
  const headers={Authorization:'Bearer '+admin};
  const created=await request.post(api,{headers,data:{kind:'personal',delivery_method:'email',email:'member@test.com'}});
  expect(created.status()).toBe(201);
  const {data}=await created.json();
  expect(data.url).toBeUndefined();
  const original=extractLink(await waitForNewEmail(),'invite')!;
  await clearEmails();
  expect((await request.post(api+'/'+data.id+'/retry',{headers})).status()).toBe(204);
  expect((await request.get(original)).status()).toBe(410);
  const link=extractLink(await waitForNewEmail(),'invite')!;
  const session=await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable');
  await session.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true}});
  await page.goto(link);
  await expect(page.locator('#email')).toHaveValue('member@test.com');
  await expect(page.locator('#email')).toHaveAttribute('readonly','');
  await page.fill('#username','invite-passkey');
  await expect(page.getByLabel('Locale')).toHaveAttribute('required', '');
  await page.getByLabel('Locale').fill('en-US');
  await page.click('#signup-btn');
  await expect(page.getByTestId('account-dashboard')).toBeVisible();
  expect((await request.get(link)).status()).toBe(410);
});

test('revoking an invitation during WebAuthn registration leaves no user or spent use', async ({ page, request }) => {
  await updateSettings(admin, { auth_mode: 'passkey_only', profile_field_locale: 'hidden', require_email_verification: 'false' });
  const headers = { Authorization: 'Bearer ' + admin };
  const issued = await request.post(api, { headers, data: { kind: 'personal', delivery_method: 'link' } });
  expect(issued.status()).toBe(201);
  const { data: invite } = await issued.json();
  const session = await page.context().newCDPSession(page);
  await session.send('WebAuthn.enable');
  await session.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await page.route('**/passkey/register/finish?**', async route => {
    expect((await request.delete(api + '/' + invite.id, { headers })).status()).toBe(204);
    await route.continue();
  });
  await page.goto(invite.url);
  await page.fill('#username', 'abandoned-invite');
  await page.click('#signup-btn');
  await expect(page.locator('#signup-error')).toContainText('invitation unavailable');
  const listed = (await (await request.get(api, { headers })).json()).data.items;
  expect(listed.find((item: {id: string}) => item.id === invite.id).use_count).toBe(0);
  const users = (await (await request.get(BASE_URL + '/admin/api/users?search=abandoned-invite', { headers })).json()).data.items;
  expect(users).toHaveLength(0);
});

test('invitation discovery waits for the configured OAuth path', async ({ page }) => {
  const discoveries: string[] = [];
  await page.route('**/.well-known/openid-configuration', async route => {
    discoveries.push(new URL(route.request().url()).pathname);
    await route.fulfill({status: 503, body: 'test discovery endpoint'});
  });
  await page.route('**/account/api/settings', route => route.fulfill({status: 503, body: 'temporarily unavailable'}));
  await page.goto(BASE_URL + '/account/invite?id=public-invite-id');
  await expect(page.getByRole('alert')).toContainText('Could not load account settings');
  expect(discoveries).toEqual([]);
  await page.unroute('**/account/api/settings');
  await page.route('**/account/api/settings', route => route.fulfill({json: {data: {oauth_path: '/custom-issuer'}}}));
  await page.getByRole('button', {name:'Retry'}).click();
  await expect.poll(() => discoveries.length).toBeGreaterThan(0);
  expect(new Set(discoveries)).toEqual(new Set(['/custom-issuer/.well-known/openid-configuration']));
});
