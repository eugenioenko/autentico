package groupclaim

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ClaimsByGroupID lists a group's local claims in name order, without token prefixes.
// It returns an empty slice when no assignments exist and propagates storage errors.
func ClaimsByGroupID(groupID string) ([]GroupClaimResponse, error) {
	rows, err := db.GetDB().Query(`SELECT claim_name, claim_value, updated_at
		FROM group_claims WHERE group_id = ? ORDER BY claim_name`, groupID)
	if err != nil {
		// Group custom claims §4: do not turn database failures into empty listings.
		return nil, fmt.Errorf("failed to list group claims: %w", err)
	}
	defer func() { _ = rows.Close() }()
	claims := []GroupClaimResponse{}
	for rows.Next() {
		var claim GroupClaimResponse
		if err := rows.Scan(&claim.Name, &claim.Value, &claim.UpdatedAt); err != nil {
			// Group custom claims §4: fail an unreadable listing instead of returning partial data.
			return nil, fmt.Errorf("failed to scan group claim: %w", err)
		}
		claims = append(claims, claim)
	}
	// Group custom claims §4: return local names and propagate iteration failures.
	return claims, rows.Err()
}
