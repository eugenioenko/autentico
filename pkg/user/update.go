package user

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateUser(id, newEmail, newRole string) error {
	query := `UPDATE users SET email = ?, role = ? WHERE id = ?`
	_, err := db.GetDB().Exec(query, newEmail, newRole, id)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	return nil
}

func UnlockUser(id string) error {
	query := `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`
	result, err := db.GetDB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %v", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to unlock user: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}
