package groupclaim

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpsertClaim(groupID, name, value string) error {
	_, err := db.GetDB().Exec(`INSERT INTO group_claims (group_id, claim_name, claim_value) VALUES (?, ?, ?)
		ON CONFLICT(group_id, claim_name) DO UPDATE SET
		claim_value = excluded.claim_value, updated_at = CURRENT_TIMESTAMP`, groupID, name, value)
	if err != nil {
		if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
			// Group custom claims §4: a claim cannot outlive or precede its group.
			return fmt.Errorf("group not found")
		}
		// Group custom claims §4: propagate failed writes to the admin endpoint.
		return fmt.Errorf("failed to save group claim: %w", err)
	}
	// Group custom claims §4: the unique group/name assignment has been persisted.
	return nil
}
