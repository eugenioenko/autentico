package migrations

const migration008 = `
CREATE TABLE IF NOT EXISTS device_codes (
    code TEXT PRIMARY KEY,
    user_code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    user_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    last_polled_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at);
`
