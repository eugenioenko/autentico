import { afterAll, beforeAll, expect, it } from 'vitest';
import { restartServer } from '../server-manager';
import { smtpCapture, type CapturedMessage } from '../smtp-capture';
import { BASE_URL, OAUTH_URL, ADMIN_CLIENT_ID, ADMIN_REDIRECT_URI, ACCOUNT_CLIENT_ID, ACCOUNT_REDIRECT_URI, getAdminToken, postJSON, putJSON, postForm, getResponse } from '../helpers';

const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const budgetEmail = 'magic-budget@test.com', expiredEmail = 'magic-expired@test.com';
let smtp: Awaited<ReturnType<typeof smtpCapture>>;
let admin: string;

/** Decode the HTML-escaped signed fields and email links without changing opaque values. */
function decode(value: string) {
  return value.replace(/&amp;/g, '&').replace(/&#(\d+);/g, (_, number) => String.fromCharCode(Number(number))).replace(/&#x([a-f0-9]+);/gi, (_, number) => String.fromCharCode(parseInt(number, 16))).replace(/&quot;/g, '"');
}
/** Extract the real form, including CSRF and authorization signatures, from the server. */
function fields(html: string) {
  const result = new URLSearchParams();
  for (const input of html.matchAll(/<input\b[^>]*>/g)) {
    const name = input[0].match(/name="([^"]+)"/), value = input[0].match(/value="([^"]*)"/);
    if (name && value) result.set(name[1], decode(value[1]));
  }
  return result;
}
/** Exercise the production request endpoint and preserve its confirmation form. */
async function requestLink(email: string, account = false) {
  const params = new URLSearchParams({ client_id: account ? ACCOUNT_CLIENT_ID : ADMIN_CLIENT_ID, redirect_uri: account ? ACCOUNT_REDIRECT_URI : ADMIN_REDIRECT_URI, scope: 'openid profile email', state: 'budget-state', code_challenge: challenge, code_challenge_method: 'S256' });
  const page = await fetch(`${OAUTH_URL}/magic-link?${params}`);
  expect(page.status).toBe(200);
  const form = fields(await page.text()); form.set('email', email);
  const cookie = page.headers.getSetCookie().find(value => value.startsWith('_gorilla_csrf='))!.split(';')[0];
  const response = await fetch(`${OAUTH_URL}/magic-link`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie, Origin: BASE_URL }, body: form, redirect: 'manual' });
  expect(response.status).toBe(200); expect(response.headers.get('location')).toBeNull();
  const html = await response.text();
  expect(html).toContain('If an account with that email exists');
  expect(html).toContain('Wait one minute');
  return { cookie, form: fields(html) };
}
/** Submit codes through the real CSRF-protected confirmation endpoint. */
async function verifyCode(request: Awaited<ReturnType<typeof requestLink>>, code: string) {
  const form = new URLSearchParams(request.form); form.set('code', code);
  return fetch(`${OAUTH_URL}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: request.cookie, Origin: BASE_URL }, body: form, redirect: 'manual' });
}
/** Read credentials from the SMTP body, rather than from application storage. */
function credential(message: CapturedMessage) {
  let html = message.data;
  if (/content-transfer-encoding:\s*quoted-printable/i.test(html)) html = html.replace(/=\r?\n/g, '').replace(/=([a-f0-9]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  const code = html.match(/font-family:monospace;[^>]*>(\d{6})<\/p>/)?.[1];
  const link = html.match(/href="([^"]*magic-link\/verify[^"]*)"/)?.[1];
  expect(code).toBeTruthy(); expect(link).toBeTruthy();
  return { code: code!, link: decode(link!) };
}
/** Create verified accounts through the admin API, leaving credentials private to SMTP. */
async function createUser(username: string, email: string) {
  const created = await postJSON(`${BASE_URL}/admin/api/users`, { username, email, password: 'Password123!' }, admin);
  expect(created.status).toBe(201);
  const id = (await created.json()).data.id;
  expect((await putJSON(`${BASE_URL}/admin/api/users/${id}`, { is_email_verified: true }, admin)).status).toBe(200);
}
beforeAll(async () => {
  smtp = await smtpCapture(); admin = await getAdminToken();
  expect((await putJSON(`${BASE_URL}/admin/api/settings`, { magic_link_enabled: 'true', smtp_host: '127.0.0.1', smtp_port: String(smtp.port), smtp_from: 'auth@test.com', require_mfa: 'false', magic_link_expiration: '120s' }, admin)).status).toBe(204);
  await createUser('magic-budget', budgetEmail); await createUser('magic-expired', expiredEmail);
});
afterAll(async () => { if (smtp) await smtp.close(); });

it('persists attempts across resends, clients and restart, throttles mail, and resets after expiry', async () => {
  const initial = await requestLink(budgetEmail);
  const firstMail = await smtp.waitFor(budgetEmail, 1), first = credential(firstMail);
  const wrong = first.code === '000000' ? '000001' : '000000';
  for (let attempt = 0; attempt < 4; attempt++) {
    const response = await verifyCode(initial, wrong);
    expect(response.status).toBe(200); expect(await response.text()).toContain('Invalid code');
  }
  await requestLink(budgetEmail, true);
  await requestLink('unknown@test.com');
  expect((await putJSON(`${BASE_URL}/admin/api/settings`, { magic_link_expiration: '10s' }, admin)).status).toBe(204);
  const expiring = await requestLink(expiredEmail);
  const expiredMail = await smtp.waitFor(expiredEmail, 1), expired = credential(expiredMail);
  for (let attempt = 0; attempt < 5; attempt++) {
    const response = await verifyCode(expiring, expired.code === '000000' ? '000001' : '000000');
    expect(response.status).toBe(200); expect(await response.text()).toContain('Invalid code');
  }
  expect((await putJSON(`${BASE_URL}/admin/api/settings`, { magic_link_expiration: '120s' }, admin)).status).toBe(204);
  await restartServer();
  expect((await getResponse(`${BASE_URL}/account/api/profile`, admin)).status).toBe(200);
  // Wait through the actual per-account cooldown; no database access or test-only clock.
  await new Promise(resolve => setTimeout(resolve, Math.max(0, Math.max(firstMail.receivedAt, expiredMail.receivedAt) + 60_200 - Date.now())));
  expect(smtp.messages.filter(mail => mail.recipients.includes(budgetEmail))).toHaveLength(1);
  expect(smtp.messages.filter(mail => mail.recipients.includes('unknown@test.com'))).toHaveLength(0);
  const replacement = await requestLink(budgetEmail, true);
  const replacementMail = await smtp.waitFor(budgetEmail, 2), next = credential(replacementMail);
  expect(replacementMail.data).toContain('expire in 1 minutes');
  const oldLink = await fetch(first.link, { redirect: 'manual' });
  expect(oldLink.status).toBe(200); expect(oldLink.headers.get('location')).toBeNull();
  const failed = await verifyCode(replacement, next.code === '000000' ? '000001' : '000000');
  expect(failed.status).toBe(200); expect(await failed.text()).toContain('Invalid code');
  const exhausted = await verifyCode(replacement, next.code);
  expect(exhausted.status).toBe(200); expect(exhausted.headers.get('location')).toBeNull();
  const exhaustedLink = await fetch(next.link, { redirect: 'manual' });
  expect(exhaustedLink.status).toBe(200); expect(exhaustedLink.headers.get('location')).toBeNull();
  await requestLink(budgetEmail);
  const renewed = await requestLink(expiredEmail, true);
  const renewedMail = await smtp.waitFor(expiredEmail, 2);
  const expiredLink = await fetch(expired.link, { redirect: 'manual' });
  expect(expiredLink.headers.get('location')).toBeNull();
  const renewedCode = credential(renewedMail).code;
  for (let attempt = 0; attempt < 4; attempt++) {
    const response = await verifyCode(renewed, renewedCode === '000000' ? '000001' : '000000');
    expect(response.status).toBe(200); expect(await response.text()).toContain('Invalid code');
  }
  const success = await verifyCode(renewed, renewedCode);
  expect(success.status).toBe(302);
  const code = new URL(success.headers.get('location')!).searchParams.get('code')!;
  const exchanged = await postForm(`${OAUTH_URL}/token`, { grant_type: 'authorization_code', code, redirect_uri: ACCOUNT_REDIRECT_URI, client_id: ACCOUNT_CLIENT_ID, code_verifier: verifier });
  expect(exchanged.status).toBe(200);
  expect((await getResponse(`${BASE_URL}/account/api/profile`, (await exchanged.json()).access_token)).status).toBe(200);
  expect(smtp.messages.filter(mail => mail.recipients.includes(budgetEmail))).toHaveLength(2);
}, 90_000);
