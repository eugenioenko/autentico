package migrations

const migration011 = `
CREATE TABLE IF NOT EXISTS user_claims (
    user_id     TEXT NOT NULL,
    claim_name  TEXT NOT NULL,
    claim_value TEXT NOT NULL DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, claim_name),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_claims_user_id ON user_claims(user_id);
`
