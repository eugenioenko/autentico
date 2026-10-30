package groupclaim

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// DeleteClaim removes one local assignment from its group.
// It reports a missing claim separately from a storage failure.
func DeleteClaim(groupID, name string) error {
	result, err := db.GetDB().Exec(`DELETE FROM group_claims WHERE group_id = ? AND claim_name = ?`, groupID, name)
	if err != nil {
		// Group custom claims §4: propagate a failed deletion.
		return fmt.Errorf("failed to delete group claim: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		// Group custom claims §4: success requires confirming the affected assignment.
		return fmt.Errorf("failed to check group claim deletion: %w", err)
	}
	if count == 0 {
		// Group custom claims §4: an unknown local claim must produce 404.
		return fmt.Errorf("claim not found")
	}
	// Group custom claims §4: exactly one group/name assignment was removed.
	return nil
}
