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

test('admin creates a capped shared link, recipient signs up without email, admin revokes it', async ({ page, browser }) => {
  await page.goto(BASE_URL + '/admin/users?tab=invites');
  await page.fill('#username', ADMIN_USERNAME);
  await page.fill('#password', ADMIN_PASSWORD);
  await page.click('button[type=submit]');
  await page.getByRole('button', {name:'Create invite'}).click();
  await page.getByLabel('Invitation type').selectOption('shared');
  await page.getByLabel('Maximum signups').fill('2');
  await page.getByRole('button', {name:'Generate link'}).click();
  const link = await page.getByText(/http.*\/invite\?token=/).innerText();
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
  await expect(page.getByText('Revoked',{exact:true})).toBeVisible();
  expect((await signup.goto(link))?.status()).toBe(410);
  await guest.close();
});

test('emailed invite verifies only its bound address and completes passkey signup', async ({ page, request }) => {
  await updateSettings(admin, { auth_mode:'passkey_only', require_email_verification:'true', smtp_host:'localhost', smtp_port:'2525',smtp_from:'admin@test.com' });
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
  await page.click('#signup-btn');
  await expect(page.getByTestId('account-dashboard')).toBeVisible();
  expect((await request.get(link)).status()).toBe(410);
});
