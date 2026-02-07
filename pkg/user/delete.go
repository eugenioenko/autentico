package user

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteUser(id string) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := db.GetDB().Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	return nil
}
