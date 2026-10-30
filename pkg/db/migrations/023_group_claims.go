package migrations

const migration023 = `
CREATE TABLE IF NOT EXISTS group_claims (
    group_id    TEXT NOT NULL,
    claim_name  TEXT NOT NULL,
    claim_value TEXT NOT NULL DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, claim_name),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);
`
