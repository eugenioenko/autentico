package migrations

const migration007 = `
ALTER TABLE clients ADD COLUMN consent_required INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS user_consents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_user_consents_user_client ON user_consents(user_id, client_id);
`
