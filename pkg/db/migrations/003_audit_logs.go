package migrations

const migration003 = `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		event TEXT NOT NULL,
		actor_id TEXT,
		actor_username TEXT NOT NULL DEFAULT '',
		target_type TEXT NOT NULL DEFAULT '',
		target_id TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		ip_address TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON audit_logs(event);
`
