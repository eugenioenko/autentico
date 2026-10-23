package migrations

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/rs/xid"
)

// NULL permits adding the unique index before transforming existing rows. The
// same transaction populates every hash; new devices always supply a hash.
const migration020 = `
PRAGMA secure_delete = ON;
ALTER TABLE trusted_devices ADD COLUMN token_hash TEXT;
CREATE UNIQUE INDEX idx_trusted_devices_token_hash ON trusted_devices(token_hash);
`

func hashTrustedDevices(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id FROM trusted_devices ORDER BY id`)
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			_ = rows.Close()
			return err
		}
		tokens = append(tokens, token)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, token := range tokens {
		// OWASP Session Management: public record IDs must not disclose credentials.
		// Keep the existing cookie usable by hashing it without rotating its value.
		digest := sha256.Sum256([]byte(token))
		if _, err := tx.Exec(`UPDATE trusted_devices SET id=?, token_hash=? WHERE id=?`, xid.New().String(), hex.EncodeToString(digest[:]), token); err != nil {
			return fmt.Errorf("hash trusted device: %w", err)
		}
	}
	return nil
}
