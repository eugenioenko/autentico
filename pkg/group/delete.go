package group

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func DeleteGroup(id string) error {
	result, err := db.GetDB().Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check delete result: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("group not found")
	}
	return nil
}
