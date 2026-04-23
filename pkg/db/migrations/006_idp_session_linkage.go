package migrations

// auth_codes.idp_session_id / sessions.idp_session_id:
//   FK into idp_sessions(id). Carried from /authorize into the auth_code, then
//   forward to the sessions row at code exchange. Nullable: NULL for grants
//   that don't go through a browser session (ROPC, client_credentials). Drives
//   idpsession.DeactivateWithCascade — revoke one IdP session and every OAuth
//   session born from that browser login goes with it.
const migration006 = `
ALTER TABLE auth_codes ADD COLUMN idp_session_id TEXT;
ALTER TABLE sessions   ADD COLUMN idp_session_id TEXT;

CREATE INDEX IF NOT EXISTS idx_auth_codes_idp_session_id ON auth_codes(idp_session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_idp_session_id   ON sessions(idp_session_id);
`
