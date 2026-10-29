package migrations

// ForwardAuth sessions have their own credentials; the central IdP cookie is
// never shared with protected applications. Deleting a parent removes children.
const migration021 = `
CREATE TABLE protected_apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    origin TEXT NOT NULL UNIQUE,
    allowed_return_paths TEXT NOT NULL,
    client_id TEXT NOT NULL UNIQUE REFERENCES clients(client_id),
    session_ttl TEXT NOT NULL DEFAULT '8h',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE forward_auth_sessions (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES protected_apps(id) ON DELETE CASCADE,
    idp_session_id TEXT NOT NULL REFERENCES idp_sessions(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    last_activity_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME
);
CREATE INDEX idx_forward_auth_sessions_parent ON forward_auth_sessions(idp_session_id);
CREATE INDEX idx_forward_auth_sessions_expiry ON forward_auth_sessions(expires_at);
`
