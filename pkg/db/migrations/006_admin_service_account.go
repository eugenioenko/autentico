package migrations

const migration006 = `
ALTER TABLE clients ADD COLUMN is_admin_service_account BOOLEAN NOT NULL DEFAULT FALSE;
`
