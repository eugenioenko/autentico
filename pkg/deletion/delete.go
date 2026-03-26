package deletion

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func CancelDeletionRequest(id string) error {
	result, err := db.GetDB().Exec(`DELETE FROM deletion_requests WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to cancel deletion request: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("deletion request not found")
	}
	return nil
}

// HardDeleteUser permanently removes a user and all associated data.
// Tables with ON DELETE CASCADE (passkey_challenges, passkey_credentials) are handled automatically.
// All others are deleted explicitly before removing the user row.
func HardDeleteUser(userID string) error {
	d := db.GetDB()
	tables := []string{
		"deletion_requests",
		"tokens",
		"sessions",
		"auth_codes",
		"idp_sessions",
		"mfa_challenges",
		"trusted_devices",
		"federated_identities",
	}
	for _, table := range tables {
		if _, err := d.Exec(fmt.Sprintf(`DELETE FROM %s WHERE user_id = ?`, table), userID); err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
		}
	}
	if _, err := d.Exec(`DELETE FROM users WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
