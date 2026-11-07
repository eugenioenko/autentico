package userclaim

import (
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
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

// ClaimMapByUserID returns only directly assigned custom claims as a name -> value map.
// Token and UserInfo callers use EffectiveClaimMapByUserID to include group defaults.
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

// EffectiveClaimMapByUserID resolves group.claim defaults followed by individual
// overrides in one database snapshot. Direct admin claim listings stay unchanged.
func EffectiveClaimMapByUserID(userID string) (map[string]string, error) {
	rows, err := db.GetDB().Query(`
		SELECT claim_name, claim_value FROM (
			SELECT g.name || '.' || gc.claim_name AS claim_name, gc.claim_value, 0 AS priority
			FROM group_claims gc
			JOIN groups g ON g.id = gc.group_id
			JOIN user_groups ug ON ug.group_id = gc.group_id
			WHERE ug.user_id = ?
			UNION ALL
			SELECT claim_name, claim_value, 1 AS priority FROM user_claims WHERE user_id = ?
		) ORDER BY priority, claim_name`, userID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve effective claims: %w", err)
	}
	defer func() { _ = rows.Close() }()

	claims := make(map[string]string)
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("failed to scan effective claim: %w", err)
		}
		// OIDC Core §5.1.2: protect standard claims even from invalid stored rows,
		// including standard claims absent from the current scope's response.
		if !IsReservedClaimName(name) {
			claims[name] = value
		}
	}
	return claims, rows.Err()
}

// EffectiveClaimsByUserID returns the custom claims emitted in tokens and UserInfo.
// With merge_group_claims disabled it matches EffectiveClaimMapByUserID; enabled,
// inherited claims use local names and always carry sorted, unique string arrays.
func EffectiveClaimsByUserID(userID string) (map[string]any, error) {
	if !config.Get().MergeGroupClaims {
		claims, err := EffectiveClaimMapByUserID(userID)
		if err != nil {
			return nil, err
		}
		result := make(map[string]any, len(claims))
		for name, value := range claims {
			result[name] = value
		}
		return result, nil
	}
	return mergedClaimMapByUserID(userID)
}

func mergedClaimMapByUserID(userID string) (map[string]any, error) {
	rows, err := db.GetDB().Query(`
		SELECT claim_name, claim_value, priority FROM (
			SELECT gc.claim_name, gc.claim_value, 0 AS priority
			FROM group_claims gc
			JOIN user_groups ug ON ug.group_id = gc.group_id
			WHERE ug.user_id = ?
			UNION ALL
			SELECT claim_name, claim_value, 1 AS priority FROM user_claims WHERE user_id = ?
		) ORDER BY priority, claim_name, claim_value`, userID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve effective claims: %w", err)
	}
	defer func() { _ = rows.Close() }()

	inherited := make(map[string][]string)
	direct := make(map[string]string)
	for rows.Next() {
		var name, value string
		var priority int
		if err := rows.Scan(&name, &value, &priority); err != nil {
			return nil, fmt.Errorf("failed to scan effective claim: %w", err)
		}
		// OIDC Core §5.1.2: unprefixed group-local names such as role must never
		// replace standard or Autentico claims.
		if IsReservedClaimName(name) {
			continue
		}
		if priority == 1 {
			// Group custom claims §7: an individual claim replaces the inherited
			// values but keeps the array type members of that key receive.
			if _, ok := inherited[name]; ok {
				inherited[name] = []string{value}
			} else {
				direct[name] = value
			}
			continue
		}
		values := inherited[name]
		// Group custom claims §7: rows arrive sorted by value, so duplicates are adjacent.
		if len(values) == 0 || values[len(values)-1] != value {
			inherited[name] = append(values, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make(map[string]any, len(inherited)+len(direct))
	for name, value := range direct {
		result[name] = value
	}
	for name, values := range inherited {
		result[name] = values
	}
	return result, nil
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
