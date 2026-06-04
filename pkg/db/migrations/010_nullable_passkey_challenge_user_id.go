package migrations

const migration010 = `
-- Rebuild passkey_challenges table to make user_id nullable (for discoverable login).
-- SQLite does not support ALTER TABLE to change NOT NULL constraints.
CREATE TABLE IF NOT EXISTS passkey_challenges_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    challenge_data TEXT NOT NULL,
    type TEXT NOT NULL,
    login_state TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO passkey_challenges_new SELECT * FROM passkey_challenges;
DROP TABLE passkey_challenges;
ALTER TABLE passkey_challenges_new RENAME TO passkey_challenges;
`
