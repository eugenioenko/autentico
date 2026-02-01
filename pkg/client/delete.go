package client

import (
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// DeleteClient performs a soft delete by setting is_active to false
func DeleteClient(clientID string) error {
	// First, verify the client exists
	_, err := ClientByClientID(clientID)
	if err != nil {
		return err
	}

	query := `
		UPDATE clients SET
			is_active = FALSE,
			updated_at = ?
		WHERE client_id = ?
	`

	now := time.Now().UTC()
	result, err := db.GetDB().Exec(query, now, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("client not found")
	}

	return nil
}
