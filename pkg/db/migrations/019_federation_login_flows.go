package migrations

// Pending federation flows retain only hashes of the browser binding and signed
// state. Integer expiry avoids SQLite timestamp/offset comparison ambiguity.
const migration019 = `
CREATE TABLE federation_login_flows (
    flow_id TEXT PRIMARY KEY NOT NULL,
    browser_hash TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX idx_federation_login_flows_expiry ON federation_login_flows(expires_at);
`
