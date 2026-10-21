package migrations

const migration014 = `
	ALTER TABLE users ADD COLUMN totp_failed_attempts INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE users ADD COLUMN totp_locked_until DATETIME;
`
