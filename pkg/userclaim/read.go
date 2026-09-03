package userclaim

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/db"
)

// ClaimsByUserID returns all custom claims for a user, ordered by name.
// Used by the admin API.
func ClaimsByUserID(userID string) ([]UserClaimResponse, error) {
	query := `SELECT claim_name, claim_value, updated_at FROM user_claims
		WHERE user_id = ? ORDER BY claim_name`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get claims for user: %w", err)
	}
	defer func() { _ = rows.Close() }()

	claims := []UserClaimResponse{}
	for rows.Next() {
		var c UserClaimResponse
		if err := rows.Scan(&c.Name, &c.Value, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan claim: %w", err)
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

// ClaimMapByUserID returns a user's custom claims as a name -> value map.
// Used for embedding claims in tokens and the UserInfo response, mirroring
// group.GroupNamesByUserID.
func ClaimMapByUserID(userID string) (map[string]string, error) {
	query := `SELECT claim_name, claim_value FROM user_claims WHERE user_id = ?`
	rows, err := db.GetDB().Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim map for user: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("failed to scan claim: %w", err)
		}
		result[name] = value
	}
	return result, rows.Err()
}

// ClaimMapByUserIDs returns custom claims for several users at once, keyed by
// user ID. Used by list endpoints that enrich many users in one query.
func ClaimMapByUserIDs(userIDs []string) (map[string]map[string]string, error) {
	if len(userIDs) == 0 {
		return map[string]map[string]string{}, nil
	}
	placeholders := make([]string, len(userIDs))
	args := make([]any, len(userIDs))
	for i, id := range userIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	query := `SELECT user_id, claim_name, claim_value FROM user_claims
		WHERE user_id IN (` + strings.Join(placeholders, ",") + `)`
	rows, err := db.GetDB().Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim maps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]map[string]string)
	for rows.Next() {
		var userID, name, value string
		if err := rows.Scan(&userID, &name, &value); err != nil {
			return nil, fmt.Errorf("failed to scan claim: %w", err)
		}
		if result[userID] == nil {
			result[userID] = make(map[string]string)
		}
		result[userID][name] = value
	}
	return result, rows.Err()
}
