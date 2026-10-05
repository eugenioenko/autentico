package migrations

const migration012 = `
ALTER TABLE clients ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN logo_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN client_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN show_in_account INTEGER NOT NULL DEFAULT 0;
`
