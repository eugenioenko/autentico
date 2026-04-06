package group

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/db"
)

func AddMember(groupID, userID string) error {
	query := `INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)`
	_, err := db.GetDB().Exec(query, userID, groupID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("user is already a member of this group")
		}
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			return fmt.Errorf("user or group not found")
		}
		return fmt.Errorf("failed to add member: %w", err)
	}
	return nil
}

func RemoveMember(groupID, userID string) error {
	result, err := db.GetDB().Exec(`DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check remove result: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user is not a member of this group")
	}
	return nil
}
