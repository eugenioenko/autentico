package migrations

const migration005 = `
-- Rebuild tokens table to make user_id nullable (for client_credentials grant).
-- SQLite does not support ALTER TABLE to change NOT NULL constraints.
CREATE TABLE IF NOT EXISTS tokens_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    access_token_type TEXT NOT NULL,
    refresh_token_expires_at DATETIME NOT NULL,
    refresh_token_last_used_at DATETIME,
    access_token_expires_at DATETIME NOT NULL,
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scope TEXT NOT NULL,
    grant_type TEXT NOT NULL,
    revoked_at DATETIME,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO tokens_new SELECT * FROM tokens;
DROP TABLE tokens;
ALTER TABLE tokens_new RENAME TO tokens;

CREATE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens(refresh_token);
CREATE INDEX IF NOT EXISTS idx_tokens_access_token ON tokens(access_token);
`
