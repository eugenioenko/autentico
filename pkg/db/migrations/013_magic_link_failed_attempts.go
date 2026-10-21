package migrations

const migration013 = `
	ALTER TABLE magic_link_tokens ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
`
