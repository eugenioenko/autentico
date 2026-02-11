package user

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteUser(id string) error {
	query := `UPDATE users SET deactivated_at = CURRENT_TIMESTAMP WHERE id = ?`
	result, err := db.GetDB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
