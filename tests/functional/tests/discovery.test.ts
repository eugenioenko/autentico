import { describe, it, expect } from 'vitest';
import { BASE_URL, OAUTH_URL } from '../helpers';

describe('OIDC Discovery', () => {
  it('returns required metadata fields', async () => {
    const resp = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
    expect(resp.ok).toBe(true);

    const config = await resp.json();

    // RFC 8414 §2: REQUIRED fields
    expect(config.issuer).toBeTruthy();
    expect(config.authorization_endpoint).toBeTruthy();
    expect(config.token_endpoint).toBeTruthy();
    expect(config.response_types_supported).toContain('code');

    // OIDC Discovery §3: REQUIRED fields
    expect(config.subject_types_supported).toContain('public');
    expect(config.id_token_signing_alg_values_supported).toContain('RS256');

    // RECOMMENDED / OPTIONAL fields we advertise
    expect(config.jwks_uri).toBeTruthy();
    expect(config.userinfo_endpoint).toBeTruthy();
    expect(config.registration_endpoint).toBeTruthy();
    expect(config.scopes_supported).toContain('openid');
    expect(config.grant_types_supported).toContain('authorization_code');
    expect(config.token_endpoint_auth_methods_supported).toContain('client_secret_basic');
    expect(config.end_session_endpoint).toBeTruthy();
    expect(config.introspection_endpoint).toBeTruthy();
    expect(config.revocation_endpoint).toBeTruthy();
    expect(config.code_challenge_methods_supported).toContain('S256');
  });

  it('issuer matches the server URL', async () => {
    const resp = await fetch(`${BASE_URL}/.well-known/openid-configuration`);
    const config = await resp.json();

    expect(config.issuer).toBe(`${OAUTH_URL}`);
  });
});

describe('JWKS', () => {
  it('returns a valid RSA key', async () => {
    const resp = await fetch(`${OAUTH_URL}/.well-known/jwks.json`);
    expect(resp.ok).toBe(true);

    const jwks = await resp.json();
    expect(jwks.keys).toHaveLength(1);

    const key = jwks.keys[0];
    expect(key.kty).toBe('RSA');
    expect(key.alg).toBe('RS256');
    expect(key.use).toBe('sig');
    expect(key.kid).toBeTruthy();
    expect(key.n).toBeTruthy();
    expect(key.e).toBeTruthy();
  });
});
