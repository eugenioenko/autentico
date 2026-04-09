package deletion

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
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
// Delegates to user.HardDeleteUser which handles the full cascade.
func HardDeleteUser(userID string) error {
	return user.HardDeleteUser(userID)
}
