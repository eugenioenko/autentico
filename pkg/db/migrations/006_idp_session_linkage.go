package migrations

const migration006 = `
ALTER TABLE auth_codes ADD COLUMN idp_session_id TEXT;
ALTER TABLE sessions   ADD COLUMN idp_session_id TEXT;

CREATE INDEX IF NOT EXISTS idx_auth_codes_idp_session_id ON auth_codes(idp_session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_idp_session_id   ON sessions(idp_session_id);
`
