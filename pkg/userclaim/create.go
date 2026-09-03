package userclaim

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/db"
)

// UpsertClaim inserts a custom claim for a user, or updates its value if the
// (user_id, claim_name) pair already exists.
func UpsertClaim(userID, name, value string) error {
	query := `INSERT INTO user_claims (user_id, claim_name, claim_value) VALUES (?, ?, ?)
		ON CONFLICT(user_id, claim_name) DO UPDATE SET
			claim_value = excluded.claim_value,
			updated_at = CURRENT_TIMESTAMP`
	_, err := db.GetDB().Exec(query, userID, name, value)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("failed to save claim: %w", err)
	}
	return nil
}
