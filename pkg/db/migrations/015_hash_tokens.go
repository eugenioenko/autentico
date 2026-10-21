package migrations

// All bearer credentials and in-flight login grants are discarded. Requiring
// an explicit major-migration approval avoids silently signing everyone out.
// Account data, TOTP enrollment, trusted devices, and settings are preserved.
const migration015 = `
PRAGMA secure_delete = ON;
DELETE FROM tokens;
DELETE FROM sessions;
DELETE FROM auth_codes;
DELETE FROM idp_sessions;
DELETE FROM mfa_challenges;
DELETE FROM device_codes;
DELETE FROM passkey_challenges;
DELETE FROM magic_link_tokens;
ALTER TABLE tokens RENAME COLUMN access_token TO access_token_hash;
ALTER TABLE tokens RENAME COLUMN refresh_token TO refresh_token_hash;
ALTER TABLE sessions RENAME COLUMN access_token TO access_token_hash;
ALTER TABLE sessions RENAME COLUMN refresh_token TO refresh_token_hash;
ALTER TABLE tokens ADD COLUMN client_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN acr TEXT NOT NULL DEFAULT '';
`
