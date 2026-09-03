package userclaim

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// DeleteClaim removes a single custom claim from a user.
func DeleteClaim(userID, name string) error {
	result, err := db.GetDB().Exec(
		`DELETE FROM user_claims WHERE user_id = ? AND claim_name = ?`, userID, name,
	)
	if err != nil {
		return fmt.Errorf("failed to delete claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check delete result: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("claim not found")
	}
	return nil
}
