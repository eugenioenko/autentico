package migrations

const migration025 = `
CREATE TABLE signup_invites (
 id TEXT PRIMARY KEY,
 token_hash TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN ('personal','shared')),
 delivery_method TEXT NOT NULL CHECK(delivery_method IN ('link','email')),
 email TEXT,
 max_uses INTEGER CHECK(max_uses > 0),
 use_count INTEGER NOT NULL DEFAULT 0,
 created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at DATETIME,
 revoked_at DATETIME,
 CHECK(kind <> 'personal' OR (max_uses IS 1 AND expires_at IS NOT NULL)),
 CHECK(kind <> 'shared' OR (email IS NULL AND delivery_method = 'link')),
 CHECK(delivery_method <> 'email' OR email IS NOT NULL)
);
`
