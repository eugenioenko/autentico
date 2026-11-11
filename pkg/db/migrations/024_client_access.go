package migrations

const migration024 = `
ALTER TABLE clients ADD COLUMN restrict_access BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS client_allowed_groups (
    client_id  TEXT NOT NULL,
    group_id   TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, group_id),
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_client_allowed_groups_group_id ON client_allowed_groups(group_id);

CREATE TABLE IF NOT EXISTS client_allowed_users (
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, user_id),
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_client_allowed_users_user_id ON client_allowed_users(user_id);
`
