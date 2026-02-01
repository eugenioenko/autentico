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
