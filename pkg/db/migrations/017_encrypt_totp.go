package migrations

import (
	"database/sql"
	"fmt"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
)

const migration017 = `PRAGMA secure_delete = ON;`

// encryptTotp preserves all enrollment, replay and lockout state. The runner
// commits the transformation and schema version together, restoring the offline
// backup if any step fails. Deactivated and pending enrollments are included.
func encryptTotp(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id, totp_secret FROM users WHERE totp_secret <> '' ORDER BY id`)
	if err != nil {
		return err
	}
	type enrollment struct{ id, secret string }
	var enrollments []enrollment
	for rows.Next() {
		var row enrollment
		if err := rows.Scan(&row.id, &row.secret); err != nil {
			_ = rows.Close()
			return err
		}
		enrollments = append(enrollments, row)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, enrollment := range enrollments {
		// RFC 6238 §5.1: encrypt the existing shared seed without replacing it.
		sealed, err := totpsecret.Seal(config.GetBootstrap().TotpEncryptionKey, enrollment.id, enrollment.secret)
		if err != nil {
			return fmt.Errorf("encrypt TOTP enrollment: %w", err)
		}
		if _, err := tx.Exec(`UPDATE users SET totp_secret = ? WHERE id = ?`, sealed, enrollment.id); err != nil {
			return err
		}
	}
	return nil
}

func validateEncryptedTotp(db *sql.DB) error {
	rows, err := db.Query(`SELECT id, totp_secret FROM users WHERE totp_secret <> ''`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, stored string
		if err := rows.Scan(&id, &stored); err != nil {
			return err
		}
		if _, err := totpsecret.Open(config.GetBootstrap().TotpEncryptionKey, id, stored); err != nil {
			return err
		}
	}
	return rows.Err()
}
